// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::io::Write;
use std::sync::LazyLock;
use std::{env, io, thread};

use chrono::prelude::*;
use lazy_static::lazy_static;
use slog::{Drain, Level, Logger, OwnedKVList, Record, KV};
use slog_term::{CountingWriter, Decorator, RecordDecorator, Serializer};

lazy_static! {
    pub static ref LOGGER: Logger = make_logger();
    pub static ref STACKS_LOG_FORMAT_TIME: Option<String> = env::var("STACKS_LOG_FORMAT_TIME").ok();
}
struct TermFormat<D: Decorator> {
    decorator: D,
    pretty_print: bool,
    debug: bool,
    isatty: bool,
}

fn print_msg_header(mut rd: &mut dyn RecordDecorator, record: &Record) -> io::Result<bool> {
    rd.start_level()?;
    write!(rd, "{}", record.level().as_short_str())?;
    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_timestamp()?;
    match &*STACKS_LOG_FORMAT_TIME {
        None => {
            let now = Utc::now();
            write!(
                rd,
                "[{:5}.{:06}]",
                now.timestamp(),
                now.timestamp_subsec_micros()
            )?;
        }
        Some(ref format) => {
            let datetime: DateTime<Local> = Local::now();
            write!(rd, "[{}]", datetime.format(format))?;
        }
    }
    write!(rd, " ")?;
    write!(rd, "[{}:{}]", record.file(), record.line())?;
    write!(rd, " ")?;
    match thread::current().name() {
        None => write!(rd, "[{:?}]", thread::current().id())?,
        Some(name) => write!(rd, "[{name}]")?,
    }

    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_msg()?;
    let mut count_rd = CountingWriter::new(&mut rd);
    write!(count_rd, "{}", record.msg())?;
    Ok(count_rd.count() != 0)
}

fn pretty_print_msg_header(
    rd: &mut dyn RecordDecorator,
    record: &Record,
    debug: bool,
    isatty: bool,
) -> io::Result<bool> {
    rd.start_timestamp()?;
    let now: DateTime<Utc> = Utc::now();
    write!(
        rd,
        "{}{}",
        color_if_tty("\x1b[0;90m", isatty),
        now.format("%b %e %T%.6f")
    )?;
    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_level()?;

    match record.level() {
        Level::Critical | Level::Error => write!(
            rd,
            "{}{}{}",
            color_if_tty("\x1b[0;91m", isatty),
            record.level().as_short_str(),
            color_if_tty("\x1b[0m", isatty)
        ),
        Level::Warning => write!(
            rd,
            "{}{}{}",
            color_if_tty("\x1b[0;33m", isatty),
            record.level().as_short_str(),
            color_if_tty("\x1b[0m", isatty)
        ),
        Level::Info => write!(
            rd,
            "{}{}{}",
            color_if_tty("\x1b[0;94m", isatty),
            record.level().as_short_str(),
            color_if_tty("\x1b[0m", isatty)
        ),
        _ => write!(rd, "{}", record.level().as_short_str()),
    }?;

    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_msg()?;
    write!(rd, "{}", record.msg())?;

    if debug {
        write!(rd, " ")?;
        write!(
            rd,
            "{}({:?}, {}:{}){}",
            color_if_tty("\x1b[0;90m", isatty),
            thread::current().id(),
            record.file(),
            record.line(),
            color_if_tty("\x1b[0m", isatty)
        )?;
    }

    Ok(true)
}

impl<D: Decorator> Drain for TermFormat<D> {
    type Ok = ();
    type Err = io::Error;

    fn log(&self, record: &Record, values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
        self.format_full(record, values)
    }
}

impl<D: Decorator> TermFormat<D> {
    pub fn new(decorator: D, pretty_print: bool, debug: bool, isatty: bool) -> TermFormat<D> {
        TermFormat {
            decorator,
            pretty_print,
            debug,
            isatty,
        }
    }

    fn format_full(&self, record: &Record, values: &OwnedKVList) -> io::Result<()> {
        self.decorator.with_record(record, values, |decorator| {
            let comma_needed = if self.pretty_print {
                pretty_print_msg_header(decorator, record, self.debug, self.isatty)
            } else {
                print_msg_header(decorator, record)
            }?;
            {
                let mut serializer = Serializer::new(decorator, comma_needed, true);

                record.kv().serialize(record, &mut serializer)?;

                values.serialize(record, &mut serializer)?;

                serializer.finish()?;
            }

            decorator.start_whitespace()?;
            writeln!(decorator)?;

            decorator.flush()?;

            Ok(())
        })
    }
}

#[cfg(feature = "slog_json")]
fn make_json_logger() -> Logger {
    use std::sync::Mutex;

    use slog::FnValue;

    let def_keys = o!("file" => FnValue(move |info| {
                          info.file()
                      }),
                      "line" => FnValue(move |info| {
                          info.line()
                      }),
                      "thread" => FnValue(move |_| {
                          match thread::current().name() {
                              None => format!("{:?}", thread::current().id()),
                              Some(name) => name.to_string(),
                          }
                      }),
    );

    let drain = Mutex::new(slog_json::Json::default(std::io::stderr()));
    let filtered_drain = slog::LevelFilter::new(drain, get_loglevel()).ignore_res();
    slog::Logger::root(filtered_drain, def_keys)
}

#[cfg(not(feature = "slog_json"))]
fn make_json_logger() -> Logger {
    panic!("Tried to construct JSON logger, but stacks-blockchain built without slog_json feature enabled.")
}

fn make_logger() -> Logger {
    if env::var("STACKS_LOG_JSON") == Ok("1".into()) {
        make_json_logger()
    } else {
        let debug = env::var("STACKS_LOG_DEBUG") == Ok("1".into());
        let pretty_print = env::var("STACKS_LOG_PP") == Ok("1".into());
        let decorator = get_decorator();
        let atty = isatty();
        let drain = TermFormat::new(decorator, pretty_print, debug, atty);
        Logger::root(drain.ignore_res(), o!())
    }
}

#[cfg(any(test, feature = "testing"))]
fn get_decorator() -> slog_term::PlainSyncDecorator<slog_term::TestStdoutWriter> {
    slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter)
}

#[cfg(any(test, feature = "testing"))]
fn isatty() -> bool {
    use std::io::IsTerminal;
    io::stdout().is_terminal()
}

#[cfg(not(any(test, feature = "testing")))]
fn get_decorator() -> slog_term::PlainSyncDecorator<std::io::Stderr> {
    slog_term::PlainSyncDecorator::new(std::io::stderr())
}

#[cfg(not(any(test, feature = "testing")))]
fn isatty() -> bool {
    use std::io::IsTerminal;
    io::stderr().is_terminal()
}

fn inner_get_loglevel() -> slog::Level {
    if env::var("STACKS_LOG_TRACE") == Ok("1".into()) {
        slog::Level::Trace
    } else if env::var("STACKS_LOG_DEBUG") == Ok("1".into())
        || env::var("BLOCKSTACK_DEBUG") == Ok("1".into())
    {
        slog::Level::Debug
    } else if env::var("STACKS_LOG_CRITONLY") == Ok("1".into()) {
        slog::Level::Critical
    } else {
        slog::Level::Info
    }
}

/// Whether contract-call records include full arguments and return values.
///
/// `STACKS_LOG_CLARITY_VALUES=1` enables these fields and `=0` disables them.
/// Other values, including an unset variable, follow debug/trace verbosity.
/// The setting is read once per process.
pub fn clarity_values_enabled() -> bool {
    static CLARITY_VALUES_ENABLED: LazyLock<bool> = LazyLock::new(|| {
        verbose_fields_enabled_for(
            env::var("STACKS_LOG_CLARITY_VALUES").ok().as_deref(),
            get_loglevel(),
        )
    });
    *CLARITY_VALUES_ENABLED
}

/// Whether diagnostic records include contract-source-bearing payloads and transactions.
///
/// `STACKS_LOG_CONTRACT_SOURCE=1` includes them and `=0` suppresses them.
/// Other values, including an unset variable, follow debug/trace verbosity.
/// The setting is read once per process, independently of Clarity value logging.
pub fn contract_source_enabled() -> bool {
    static CONTRACT_SOURCE_ENABLED: LazyLock<bool> = LazyLock::new(|| {
        verbose_fields_enabled_for(
            env::var("STACKS_LOG_CONTRACT_SOURCE").ok().as_deref(),
            get_loglevel(),
        )
    });
    *CONTRACT_SOURCE_ENABLED
}

/// Resolves the field override against the node's logging verbosity.
fn verbose_fields_enabled_for(setting: Option<&str>, level: Level) -> bool {
    match setting {
        Some("1") => true,
        Some("0") => false,
        _ => Level::Debug.is_at_least(level),
    }
}

/// Returns the node's logging verbosity, reading the environment once.
pub fn get_loglevel() -> slog::Level {
    static LOGLEVEL: LazyLock<Level> = LazyLock::new(inner_get_loglevel);
    *LOGLEVEL
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Trace.is_at_least(cur_level) {
            slog::trace!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Error.is_at_least(cur_level) {
            slog::error!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Warning.is_at_least(cur_level) {
            slog::warn!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Info.is_at_least(cur_level) {
            slog::info!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Debug.is_at_least(cur_level) {
            slog::debug!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => ({
        let cur_level = $crate::util::log::get_loglevel();
        if slog::Level::Critical.is_at_least(cur_level) {
            slog::slog_crit!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

fn color_if_tty(color: &str, isatty: bool) -> &str {
    if isatty {
        color
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fmt;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Captures complete records written by a real logging drain.
    #[derive(Clone, Default)]
    struct CaptureWriter {
        /// Captured output shared with the test.
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Counts calls to either value formatter.
    struct RenderProbe<'a> {
        /// Number of formatting invocations.
        calls: &'a Cell<usize>,
    }

    impl fmt::Display for RenderProbe<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.calls.set(self.calls.get() + 1);
            formatter.write_str("full value")
        }
    }

    impl fmt::Debug for RenderProbe<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(self, formatter)
        }
    }

    /// Emits one summary with conditional Display and Debug fields.
    fn emit_conditional_fields(logger: &Logger, enabled: bool) {
        let calls = Cell::new(0);
        let value = RenderProbe { calls: &calls };
        let args = format_args!("{value}");
        let result = format_args!("{value:?}");
        let argument_fields = slog::b!("function_args" => args);
        let argument_fields = if enabled { argument_fields } else { slog::b!() };
        let result_fields = slog::b!("return_value" => result);
        slog::info!(logger, "Contract-call successfully processed";
            "txid" => "test-tx",
            argument_fields,
            if enabled { result_fields } else { slog::b!() });
        if enabled {
            assert!(calls.get() >= 2);
        } else {
            assert_eq!(calls.get(), 0);
        }
    }

    /// Overrides apply at every level; absent or invalid values follow verbosity.
    #[test]
    fn test_verbose_fields_setting() {
        for level in [
            Level::Critical,
            Level::Error,
            Level::Warning,
            Level::Info,
            Level::Debug,
            Level::Trace,
        ] {
            assert!(verbose_fields_enabled_for(Some("1"), level));
            assert!(!verbose_fields_enabled_for(Some("0"), level));
            let verbose = level == Level::Debug || level == Level::Trace;
            for setting in [None, Some(""), Some("invalid")] {
                assert_eq!(verbose_fields_enabled_for(setting, level), verbose);
            }
        }
    }

    /// Both text formats omit disabled fields without invoking their formatters.
    #[test]
    fn test_conditional_fields_text() {
        for pretty in [false, true] {
            for enabled in [false, true] {
                let writer = CaptureWriter::default();
                let decorator = slog_term::PlainSyncDecorator::new(writer.clone());
                let logger = Logger::root(
                    TermFormat::new(decorator, pretty, false, false).fuse(),
                    o!(),
                );
                emit_conditional_fields(&logger, enabled);
                let output = String::from_utf8(writer.bytes.lock().unwrap().clone()).unwrap();
                assert_eq!(output.lines().count(), 1);
                assert!(output.contains("Contract-call successfully processed"));
                assert!(output.contains("txid: test-tx"));
                assert_eq!(output.contains("function_args: full value"), enabled);
                assert_eq!(output.contains("return_value: full value"), enabled);
                assert_eq!(output.contains("function_args"), enabled);
                assert_eq!(output.contains("return_value"), enabled);
            }
        }
    }

    /// JSON fields retain their names and string values, with no null placeholders.
    #[cfg(feature = "slog_json")]
    #[test]
    fn test_conditional_fields_json() {
        for enabled in [false, true] {
            let writer = CaptureWriter::default();
            let logger = Logger::root(
                Mutex::new(slog_json::Json::default(writer.clone())).fuse(),
                o!(),
            );
            emit_conditional_fields(&logger, enabled);
            let output = String::from_utf8(writer.bytes.lock().unwrap().clone()).unwrap();
            assert_eq!(output.lines().count(), 1);
            let record: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert_eq!(record["msg"], "Contract-call successfully processed");
            assert_eq!(record["txid"], "test-tx");
            for key in ["function_args", "return_value"] {
                if enabled {
                    assert_eq!(record[key], "full value");
                } else {
                    assert!(record.get(key).is_none());
                }
            }
        }
    }

    #[test]
    #[ignore = "manual test"]
    fn test_log_pretty_print() {
        env::set_var("STACKS_LOG_PP", "1");
        let logger: Logger = make_logger();
        slog::slog_info!(logger, "Info test"); //equivalent to info!(..)
        slog::slog_warn!(logger, "Warn test"); //equivalent to warn!(..)
        slog::slog_error!(logger, "Erro test"); //equivalent to erro!(..)
    }
}
