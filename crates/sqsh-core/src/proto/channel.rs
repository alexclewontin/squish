use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Per-channel stream messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelMessage {
    // -- lifecycle --
    Open {
        channel_type: ChannelType,
        params: ChannelParams,
    },
    OpenConfirmation {
        max_packet_size: u32,
    },
    OpenFailure {
        reason: ChannelFailureReason,
        description: String,
    },
    Close,
    Eof,

    // -- data --
    Data {
        data: Vec<u8>,
    },
    ExtendedData {
        data_type: u32,
        data: Vec<u8>,
    },

    // -- requests --
    Request {
        request_type: RequestType,
        want_reply: bool,
    },
    RequestSuccess,
    RequestFailure,

    // -- exit --
    ExitStatus {
        status: u32,
    },
    ExitSignal {
        signal: String,
        core_dumped: bool,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    Session,
    DirectTcpip,
    ForwardedTcpip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelParams {
    Session,
    DirectTcpip(TcpipParams),
    ForwardedTcpip(TcpipParams),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpipParams {
    pub host: String,
    pub port: u16,
    pub originator_addr: String,
    pub originator_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestType {
    PtyReq(PtyReqParams),
    Shell,
    Exec { command: String },
    WindowChange(WindowChangeParams),
    Signal { signal: String },
    Env { name: String, value: String },
    Subsystem { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtyReqParams {
    pub term: String,
    pub width_cols: u32,
    pub height_rows: u32,
    pub width_px: u32,
    pub height_px: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowChangeParams {
    pub width_cols: u32,
    pub height_rows: u32,
    pub width_px: u32,
    pub height_px: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelFailureReason {
    AdministrativelyProhibited,
    UnknownChannelType,
    ResourceShortage,
}
