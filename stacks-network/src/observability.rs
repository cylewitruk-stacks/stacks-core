//! Process-level tracing setup shared by node and signer binaries.
//!
//! Structured formatting is always available. OTLP/HTTP is compiled behind
//! `otel` and activated only by `STACKS_OTEL_ENABLED`. Its custom processor has
//! a bounded queue and only `try_send`s from span completion, so collector
//! slowness can never backpressure a swarm or signer thread.

use std::sync::atomic::{AtomicU64, Ordering};

use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

static OTEL_QUEUE_DROPS: AtomicU64 = AtomicU64::new(0);
static OTEL_EXPORT_DROPS: AtomicU64 = AtomicU64::new(0);

pub fn dropped_span_totals() -> (u64, u64) {
    (
        OTEL_QUEUE_DROPS.load(Ordering::Relaxed),
        OTEL_EXPORT_DROPS.load(Ordering::Relaxed),
    )
}

pub struct ObservabilityGuard {
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl ObservabilityGuard {
    fn disabled() -> Self {
        Self {
            #[cfg(feature = "otel")]
            provider: None,
        }
    }
}

#[cfg(feature = "otel")]
impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            if provider.shutdown().is_err() {
                OTEL_EXPORT_DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Install the process-global tracing subscriber. A failed optional exporter
/// never prevents the normal formatting subscriber from being installed.
pub fn install_tracing(
    service_name: &'static str,
    fallback_filter: &'static str,
) -> Result<ObservabilityGuard, String> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(fallback_filter));
    let requested = std::env::var("STACKS_OTEL_ENABLED")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"));

    #[cfg(feature = "otel")]
    if requested {
        return install_otel_tracing(service_name, filter);
    }

    let result = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .try_init()
        .map_err(|error| error.to_string());
    result?;

    #[cfg(not(feature = "otel"))]
    if requested {
        return Err(
            "STACKS_OTEL_ENABLED requested, but this binary was built without the `otel` feature"
                .to_owned(),
        );
    }

    let _ = service_name;
    Ok(ObservabilityGuard::disabled())
}

#[cfg(feature = "otel")]
fn install_otel_tracing(
    service_name: &'static str,
    filter: EnvFilter,
) -> Result<ObservabilityGuard, String> {
    use std::time::Duration;

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::{Protocol, WithExportConfig};
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
    use opentelemetry_sdk::Resource;

    let queue_size = bounded_env_usize("STACKS_OTEL_QUEUE_SIZE", 2048, 16, 65_536)?;
    let batch_size = bounded_env_usize("STACKS_OTEL_BATCH_SIZE", 256, 1, queue_size)?;
    let delay_ms = bounded_env_u64("STACKS_OTEL_BATCH_DELAY_MS", 1_000, 10, 60_000)?;
    let export_timeout_ms = bounded_env_u64("STACKS_OTEL_EXPORT_TIMEOUT_MS", 5_000, 100, 60_000)?;
    let ratio = std::env::var("STACKS_OTEL_SAMPLE_RATIO")
        .ok()
        .map(|value| {
            value
                .parse::<f64>()
                .map_err(|_| "STACKS_OTEL_SAMPLE_RATIO is not a number".to_owned())
                .and_then(|value| {
                    (value.is_finite() && (0.0..=1.0).contains(&value))
                        .then_some(value)
                        .ok_or_else(|| "STACKS_OTEL_SAMPLE_RATIO must be in [0,1]".to_owned())
                })
        })
        .transpose()?
        .unwrap_or(1.0);

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_timeout(Duration::from_millis(export_timeout_ms))
        .build()
        .map_err(|error| format!("failed to build OTLP exporter: {error}"))?;
    let processor = NonblockingBatchSpanProcessor::new(
        exporter,
        queue_size,
        batch_size,
        Duration::from_millis(delay_ms),
    )
    .map_err(|error| format!("failed to start OTLP exporter worker: {error}"))?;
    let provider = SdkTracerProvider::builder()
        .with_span_processor(processor)
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            ratio,
        ))))
        .with_resource(Resource::builder().with_service_name(service_name).build())
        .build();
    let tracer = provider.tracer("stacks-network");
    opentelemetry::global::set_tracer_provider(provider.clone());

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()
        .map_err(|error| {
            let _ = provider.shutdown();
            format!("failed to install tracing subscriber: {error}")
        })?;
    Ok(ObservabilityGuard {
        provider: Some(provider),
    })
}

#[cfg(feature = "otel")]
fn bounded_env_usize(
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, String> {
    let value = std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| format!("{name} is not an unsigned integer"))
        })
        .transpose()?
        .unwrap_or(default);
    (minimum..=maximum)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| format!("{name} must be in [{minimum},{maximum}]"))
}

#[cfg(feature = "otel")]
fn bounded_env_u64(name: &str, default: u64, minimum: u64, maximum: u64) -> Result<u64, String> {
    let value = std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("{name} is not an unsigned integer"))
        })
        .transpose()?
        .unwrap_or(default);
    (minimum..=maximum)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| format!("{name} must be in [{minimum},{maximum}]"))
}

#[cfg(feature = "otel")]
mod bounded_processor {
    use std::fmt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
    use std::sync::Mutex;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use opentelemetry::Context;
    use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
    use opentelemetry_sdk::trace::{Span, SpanData, SpanExporter, SpanProcessor};
    use opentelemetry_sdk::Resource;

    use super::{OTEL_EXPORT_DROPS, OTEL_QUEUE_DROPS};

    enum Control {
        SetResource(Resource, SyncSender<()>),
        Flush(SyncSender<OTelSdkResult>),
        Shutdown(Duration, SyncSender<OTelSdkResult>),
    }

    pub(super) struct NonblockingBatchSpanProcessor {
        spans: SyncSender<SpanData>,
        control: mpsc::Sender<Control>,
        shutdown: AtomicBool,
        worker: Mutex<Option<JoinHandle<()>>>,
    }

    impl fmt::Debug for NonblockingBatchSpanProcessor {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("NonblockingBatchSpanProcessor")
                .field("shutdown", &self.shutdown.load(Ordering::Relaxed))
                .finish_non_exhaustive()
        }
    }

    impl NonblockingBatchSpanProcessor {
        pub(super) fn new<E: SpanExporter + 'static>(
            exporter: E,
            queue_size: usize,
            batch_size: usize,
            scheduled_delay: Duration,
        ) -> std::io::Result<Self> {
            let (span_tx, span_rx) = mpsc::sync_channel(queue_size);
            let (control_tx, control_rx) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("stacks-otel-exporter".to_owned())
                .spawn(move || {
                    export_worker(exporter, span_rx, control_rx, batch_size, scheduled_delay)
                })?;
            Ok(Self {
                spans: span_tx,
                control: control_tx,
                shutdown: AtomicBool::new(false),
                worker: Mutex::new(Some(worker)),
            })
        }
    }

    impl SpanProcessor for NonblockingBatchSpanProcessor {
        fn on_start(&self, _span: &mut Span, _cx: &Context) {}

        fn on_end(&self, span: SpanData) {
            if self.shutdown.load(Ordering::Relaxed) {
                OTEL_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if self.spans.try_send(span).is_err() {
                OTEL_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn force_flush(&self) -> OTelSdkResult {
            let (sender, receiver) = mpsc::sync_channel(1);
            self.control
                .send(Control::Flush(sender))
                .map_err(|_| OTelSdkError::AlreadyShutdown)?;
            receiver
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| match error {
                    RecvTimeoutError::Timeout => OTelSdkError::Timeout(Duration::from_secs(5)),
                    RecvTimeoutError::Disconnected => OTelSdkError::AlreadyShutdown,
                })?
        }

        fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
            if self.shutdown.swap(true, Ordering::SeqCst) {
                return Ok(());
            }
            let (sender, receiver) = mpsc::sync_channel(1);
            self.control
                .send(Control::Shutdown(timeout, sender))
                .map_err(|_| OTelSdkError::AlreadyShutdown)?;
            let result = receiver
                .recv_timeout(timeout)
                .map_err(|error| match error {
                    RecvTimeoutError::Timeout => OTelSdkError::Timeout(timeout),
                    RecvTimeoutError::Disconnected => OTelSdkError::AlreadyShutdown,
                })?;
            if result.is_ok() {
                if let Some(worker) = self
                    .worker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    let _ = worker.join();
                }
            }
            result
        }

        fn set_resource(&mut self, resource: &Resource) {
            let (sender, receiver) = mpsc::sync_channel(1);
            if self
                .control
                .send(Control::SetResource(resource.clone(), sender))
                .is_ok()
            {
                let _ = receiver.recv_timeout(Duration::from_secs(1));
            }
        }
    }

    fn export_worker<E: SpanExporter + 'static>(
        mut exporter: E,
        spans: Receiver<SpanData>,
        control: Receiver<Control>,
        batch_size: usize,
        scheduled_delay: Duration,
    ) {
        let mut pending = Vec::with_capacity(batch_size);
        let mut last_export = Instant::now();
        loop {
            while let Ok(message) = control.try_recv() {
                match message {
                    Control::SetResource(resource, response) => {
                        exporter.set_resource(&resource);
                        let _ = response.send(());
                    }
                    Control::Flush(response) => {
                        drain_spans(&spans, &mut pending, batch_size);
                        let _ = response.send(export_pending(&exporter, &mut pending));
                        last_export = Instant::now();
                    }
                    Control::Shutdown(timeout, response) => {
                        drain_spans(&spans, &mut pending, usize::MAX);
                        let mut result = export_pending(&exporter, &mut pending);
                        if result.is_ok() {
                            result = exporter.shutdown_with_timeout(timeout);
                        }
                        let _ = response.send(result);
                        return;
                    }
                }
            }

            let until_export = scheduled_delay.saturating_sub(last_export.elapsed());
            match spans.recv_timeout(until_export.min(Duration::from_millis(100))) {
                Ok(span) => pending.push(span),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    let _ = export_pending(&exporter, &mut pending);
                    let _ = exporter.shutdown();
                    return;
                }
            }
            drain_spans(&spans, &mut pending, batch_size);
            if pending.len() >= batch_size || last_export.elapsed() >= scheduled_delay {
                let _ = export_pending(&exporter, &mut pending);
                last_export = Instant::now();
            }
        }
    }

    fn drain_spans(spans: &Receiver<SpanData>, pending: &mut Vec<SpanData>, limit: usize) {
        while pending.len() < limit {
            match spans.try_recv() {
                Ok(span) => pending.push(span),
                Err(_) => break,
            }
        }
    }

    fn export_pending<E: SpanExporter>(exporter: &E, pending: &mut Vec<SpanData>) -> OTelSdkResult {
        if pending.is_empty() {
            return Ok(());
        }
        let dropped_on_failure = pending.len() as u64;
        let batch = std::mem::take(pending);
        let result = futures::executor::block_on(exporter.export(batch));
        if result.is_err() {
            OTEL_EXPORT_DROPS.fetch_add(dropped_on_failure, Ordering::Relaxed);
        }
        result
    }
}

#[cfg(feature = "otel")]
use bounded_processor::NonblockingBatchSpanProcessor;

#[cfg(test)]
mod tests {
    #[cfg(feature = "otel")]
    use std::sync::atomic::{AtomicBool, Ordering};
    #[cfg(feature = "otel")]
    use std::sync::{mpsc, Arc, Mutex};
    #[cfg(feature = "otel")]
    use std::time::Duration;

    #[cfg(feature = "otel")]
    use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};
    #[cfg(feature = "otel")]
    use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
    #[cfg(feature = "otel")]
    use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};

    #[cfg(feature = "otel")]
    #[test]
    fn telemetry_limits_fail_closed() {
        assert!(super::bounded_env_usize("STACKS_TEST_MISSING", 32, 16, 64).is_ok());
        assert!(super::bounded_env_usize("STACKS_TEST_MISSING", 8, 16, 64).is_err());
        assert!(super::bounded_env_u64("STACKS_TEST_MISSING", 10, 10, 20).is_ok());
    }

    /// Blocks only its first export so the test can prove span completion is
    /// a nonblocking `try_send` even while the collector is unavailable.
    #[cfg(feature = "otel")]
    #[derive(Debug)]
    struct BlockingFailExporter {
        first: AtomicBool,
        started: mpsc::SyncSender<()>,
        release: Arc<Mutex<mpsc::Receiver<()>>>,
    }

    #[cfg(feature = "otel")]
    impl SpanExporter for BlockingFailExporter {
        async fn export(&self, _batch: Vec<SpanData>) -> OTelSdkResult {
            if self.first.swap(false, Ordering::SeqCst) {
                let _ = self.started.send(());
                let result = self
                    .release
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .recv_timeout(Duration::from_secs(2));
                if result.is_err() {
                    return Err(OTelSdkError::InternalFailure(
                        "test exporter release timed out".to_owned(),
                    ));
                }
            }
            Err(OTelSdkError::InternalFailure(
                "injected collector failure".to_owned(),
            ))
        }
    }

    #[cfg(feature = "otel")]
    #[test]
    fn unavailable_exporter_cannot_backpressure_span_completion() {
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let exporter = BlockingFailExporter {
            first: AtomicBool::new(true),
            started: started_tx,
            release: Arc::new(Mutex::new(release_rx)),
        };
        let processor =
            super::NonblockingBatchSpanProcessor::new(exporter, 2, 1, Duration::from_secs(60))
                .unwrap();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor)
            .build();
        let tracer = provider.tracer("nonblocking-export-test");
        let (queue_before, export_before) = super::dropped_span_totals();

        tracer.start("blocks-export-worker").end();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        // If `on_end` waited for the exporter, this loop would deadlock before
        // the release below. Instead the bounded queue fills and drops.
        for _ in 0..64 {
            tracer.start("bounded-while-collector-is-down").end();
        }
        assert!(super::dropped_span_totals().0 > queue_before);

        release_tx.send(()).unwrap();
        assert!(provider.force_flush().is_err());
        assert!(super::dropped_span_totals().1 > export_before);
        let _ = provider.shutdown();
    }
}
