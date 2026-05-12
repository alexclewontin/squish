/// Channel lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Open request sent, waiting for confirmation.
    Opening,
    /// Channel is active and can send/receive data.
    Open,
    /// We sent EOF — no more data from our side.
    EofSent,
    /// We received EOF — no more data from their side.
    EofReceived,
    /// Close has been sent or received; channel is shutting down.
    Closing,
    /// Fully closed.
    Closed,
}

impl ChannelState {
    pub fn can_send_data(&self) -> bool {
        matches!(self, Self::Open | Self::EofReceived)
    }

    pub fn can_recv_data(&self) -> bool {
        matches!(self, Self::Open | Self::EofSent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_can_send_and_recv() {
        assert!(ChannelState::Open.can_send_data());
        assert!(ChannelState::Open.can_recv_data());
    }

    #[test]
    fn eof_sent_can_recv_but_not_send() {
        assert!(!ChannelState::EofSent.can_send_data());
        assert!(ChannelState::EofSent.can_recv_data());
    }

    #[test]
    fn eof_received_can_send_but_not_recv() {
        assert!(ChannelState::EofReceived.can_send_data());
        assert!(!ChannelState::EofReceived.can_recv_data());
    }

    #[test]
    fn closed_states_cannot_send_or_recv() {
        for state in [
            ChannelState::Opening,
            ChannelState::Closing,
            ChannelState::Closed,
        ] {
            assert!(!state.can_send_data(), "{state:?} should not send");
            assert!(!state.can_recv_data(), "{state:?} should not recv");
        }
    }
}
