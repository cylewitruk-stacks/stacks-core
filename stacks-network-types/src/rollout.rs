//! Shared rollout policy for node and signer libp2p application traffic.

use serde::Deserialize;

/// Controls whether a process observes, consumes, or publishes application data
/// on libp2p. Transport control traffic remains active in every mode except
/// [`RolloutMode::Off`].
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RolloutMode {
    /// Do not start the libp2p service.
    #[default]
    Off,
    /// Establish and measure the overlay, but do not deliver application data.
    Observe,
    /// Accept validated libp2p ingress while retaining legacy-only egress.
    Receive,
    /// Accept and publish over both transports.
    Dual,
    /// Prefer libp2p, retaining the legacy transport as a rollback fallback.
    Libp2pPreferred,
    /// Use libp2p for application data and do not fall back to legacy transport.
    Libp2pOnly,
}

impl RolloutMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Observe => "observe",
            Self::Receive => "receive",
            Self::Dual => "dual",
            Self::Libp2pPreferred => "libp2p-preferred",
            Self::Libp2pOnly => "libp2p-only",
        }
    }

    pub const fn enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    pub const fn accepts_application_ingress(self) -> bool {
        matches!(
            self,
            Self::Receive | Self::Dual | Self::Libp2pPreferred | Self::Libp2pOnly
        )
    }

    pub const fn publishes_application_data(self) -> bool {
        matches!(self, Self::Dual | Self::Libp2pPreferred | Self::Libp2pOnly)
    }

    pub const fn legacy_fallback_enabled(self) -> bool {
        !matches!(self, Self::Libp2pOnly)
    }

    /// Whether the incumbent Stacks P2P TCP listener must remain available.
    ///
    /// This is deliberately separate from application-data fallback so socket
    /// ownership cannot become an implicit call-site convention. A
    /// `libp2p-only` process keeps the incumbent scheduler for RPC and
    /// chainstate integration, but does not expose its legacy peer transport.
    pub const fn legacy_listener_enabled(self) -> bool {
        !matches!(self, Self::Libp2pOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::RolloutMode;

    #[test]
    fn only_libp2p_only_disables_the_legacy_listener() {
        for mode in [
            RolloutMode::Off,
            RolloutMode::Observe,
            RolloutMode::Receive,
            RolloutMode::Dual,
            RolloutMode::Libp2pPreferred,
        ] {
            assert!(mode.legacy_listener_enabled(), "mode {mode:?}");
        }
        assert!(!RolloutMode::Libp2pOnly.legacy_listener_enabled());
        assert_eq!(RolloutMode::Libp2pOnly.as_str(), "libp2p-only");
    }
}
