//! RPC-over-HTTP v2 (MS-RPCH) implementation.
//!
//! Handles the two-channel architecture (RPC_IN_DATA / RPC_OUT_DATA)
//! and RTS (Request to Send) PDUs for mstsc compatibility.

use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;
use uuid::Uuid;

pub const RPC_VERSION: u8 = 5;
pub const RPC_VERSION_MINOR: u8 = 0;
pub const PTYPE_RTS: u8 = 20;
pub const PACKED_DREP_LITTLE_ENDIAN: [u8; 4] = [0x10, 0x00, 0x00, 0x00];
pub const RPCH_PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_RECEIVE_WINDOW_SIZE: u32 = 262_144;
pub const DEFAULT_CONNECTION_TIMEOUT: u32 = 120_000;

const RTS_HEADER_LEN: usize = 20;

const CMD_RECEIVE_WINDOW_SIZE: u16 = 0x0000;
const CMD_FLOW_CONTROL_ACK: u16 = 0x0001;
const CMD_CONNECTION_TIMEOUT: u16 = 0x0002;
const CMD_COOKIE: u16 = 0x0003;
const CMD_CHANNEL_LIFETIME: u16 = 0x0004;
const CMD_CLIENT_KEEPALIVE: u16 = 0x0005;
const CMD_VERSION: u16 = 0x0006;
const CMD_ASSOCIATION_GROUP_ID: u16 = 0x000D;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RpchError {
    #[error("buffer too short: need {needed} bytes, have {have}")]
    BufferTooShort { needed: usize, have: usize },
    #[error("invalid RPC version: {major}.{minor}")]
    InvalidRpcVersion { major: u8, minor: u8 },
    #[error("invalid PDU type: {0}")]
    InvalidPtype(u8),
    #[error("invalid packed data representation: {0:02x?}")]
    InvalidPackedDrep([u8; 4]),
    #[error("invalid fragment length: declared {declared}, actual {actual}")]
    InvalidFragLength { declared: usize, actual: usize },
    #[error("unknown RTS command type: 0x{0:04x}")]
    UnknownCommand(u16),
    #[error("invalid UUID bytes")]
    InvalidUuid,
    #[error("invalid CONN/A1 sequence")]
    InvalidConnA1,
    #[error("invalid CONN/B1 sequence")]
    InvalidConnB1,
    #[error("unexpected virtual connection state: expected {expected:?}, actual {actual:?}")]
    UnexpectedState {
        expected: VirtualConnectionState,
        actual: VirtualConnectionState,
    },
    #[error("virtual connection cookie mismatch: expected {expected}, actual {actual}")]
    VirtualConnectionCookieMismatch { expected: Uuid, actual: Uuid },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtsCommand {
    ReceiveWindowSize(u32),
    FlowControlAck {
        bytes_received: u32,
        available_window: u32,
        channel_cookie: Uuid,
    },
    ConnectionTimeout(u32),
    Cookie(Uuid),
    ChannelLifetime(u32),
    ClientKeepalive(u32),
    Version(u32),
    AssociationGroupId(Uuid),
}

impl RtsCommand {
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::ReceiveWindowSize(_)
            | Self::ConnectionTimeout(_)
            | Self::ChannelLifetime(_)
            | Self::ClientKeepalive(_)
            | Self::Version(_) => 2 + 4,
            Self::FlowControlAck { .. } => 2 + 4 + 4 + 16,
            Self::Cookie(_) | Self::AssociationGroupId(_) => 2 + 16,
        }
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        match self {
            Self::ReceiveWindowSize(value) => {
                buf.put_u16_le(CMD_RECEIVE_WINDOW_SIZE);
                buf.put_u32_le(*value);
            }
            Self::FlowControlAck {
                bytes_received,
                available_window,
                channel_cookie,
            } => {
                buf.put_u16_le(CMD_FLOW_CONTROL_ACK);
                buf.put_u32_le(*bytes_received);
                buf.put_u32_le(*available_window);
                put_uuid_le(buf, channel_cookie);
            }
            Self::ConnectionTimeout(value) => {
                buf.put_u16_le(CMD_CONNECTION_TIMEOUT);
                buf.put_u32_le(*value);
            }
            Self::Cookie(value) => {
                buf.put_u16_le(CMD_COOKIE);
                put_uuid_le(buf, value);
            }
            Self::ChannelLifetime(value) => {
                buf.put_u16_le(CMD_CHANNEL_LIFETIME);
                buf.put_u32_le(*value);
            }
            Self::ClientKeepalive(value) => {
                buf.put_u16_le(CMD_CLIENT_KEEPALIVE);
                buf.put_u32_le(*value);
            }
            Self::Version(value) => {
                buf.put_u16_le(CMD_VERSION);
                buf.put_u32_le(*value);
            }
            Self::AssociationGroupId(value) => {
                buf.put_u16_le(CMD_ASSOCIATION_GROUP_ID);
                put_uuid_le(buf, value);
            }
        }
    }

    fn parse(buf: &mut &[u8]) -> Result<Self, RpchError> {
        ensure_remaining(buf.remaining(), 2)?;
        let command_type = buf.get_u16_le();

        match command_type {
            CMD_RECEIVE_WINDOW_SIZE => {
                ensure_remaining(buf.remaining(), 4)?;
                Ok(Self::ReceiveWindowSize(buf.get_u32_le()))
            }
            CMD_FLOW_CONTROL_ACK => {
                ensure_remaining(buf.remaining(), 24)?;
                let bytes_received = buf.get_u32_le();
                let available_window = buf.get_u32_le();
                let channel_cookie = get_uuid_le(buf)?;
                Ok(Self::FlowControlAck {
                    bytes_received,
                    available_window,
                    channel_cookie,
                })
            }
            CMD_CONNECTION_TIMEOUT => {
                ensure_remaining(buf.remaining(), 4)?;
                Ok(Self::ConnectionTimeout(buf.get_u32_le()))
            }
            CMD_COOKIE => Ok(Self::Cookie(get_uuid_le(buf)?)),
            CMD_CHANNEL_LIFETIME => {
                ensure_remaining(buf.remaining(), 4)?;
                Ok(Self::ChannelLifetime(buf.get_u32_le()))
            }
            CMD_CLIENT_KEEPALIVE => {
                ensure_remaining(buf.remaining(), 4)?;
                Ok(Self::ClientKeepalive(buf.get_u32_le()))
            }
            CMD_VERSION => {
                ensure_remaining(buf.remaining(), 4)?;
                Ok(Self::Version(buf.get_u32_le()))
            }
            CMD_ASSOCIATION_GROUP_ID => Ok(Self::AssociationGroupId(get_uuid_le(buf)?)),
            other => Err(RpchError::UnknownCommand(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtsPdu {
    pub rpc_version: u8,
    pub rpc_version_minor: u8,
    pub ptype: u8,
    pub pfc_flags: u8,
    pub packed_drep: [u8; 4],
    pub auth_length: u16,
    pub call_id: u32,
    pub flags: u16,
    pub commands: Vec<RtsCommand>,
}

impl RtsPdu {
    pub fn new(call_id: u32, flags: u16, commands: Vec<RtsCommand>) -> Self {
        Self {
            rpc_version: RPC_VERSION,
            rpc_version_minor: RPC_VERSION_MINOR,
            ptype: PTYPE_RTS,
            pfc_flags: 0,
            packed_drep: PACKED_DREP_LITTLE_ENDIAN,
            auth_length: 0,
            call_id,
            flags,
            commands,
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self, RpchError> {
        ensure_remaining(data.len(), RTS_HEADER_LEN)?;

        let mut buf = data;
        let rpc_version = buf.get_u8();
        let rpc_version_minor = buf.get_u8();
        let ptype = buf.get_u8();
        let pfc_flags = buf.get_u8();

        let mut packed_drep = [0u8; 4];
        buf.copy_to_slice(&mut packed_drep);

        let frag_length = buf.get_u16_le() as usize;
        let auth_length = buf.get_u16_le();
        let call_id = buf.get_u32_le();
        let flags = buf.get_u16_le();
        let num_commands = buf.get_u16_le() as usize;

        if rpc_version != RPC_VERSION || rpc_version_minor != RPC_VERSION_MINOR {
            return Err(RpchError::InvalidRpcVersion {
                major: rpc_version,
                minor: rpc_version_minor,
            });
        }
        if ptype != PTYPE_RTS {
            return Err(RpchError::InvalidPtype(ptype));
        }
        if packed_drep != PACKED_DREP_LITTLE_ENDIAN {
            return Err(RpchError::InvalidPackedDrep(packed_drep));
        }
        if frag_length != data.len() {
            return Err(RpchError::InvalidFragLength {
                declared: frag_length,
                actual: data.len(),
            });
        }

        let mut commands = Vec::with_capacity(num_commands);
        for _ in 0..num_commands {
            commands.push(RtsCommand::parse(&mut buf)?);
        }

        if buf.has_remaining() {
            return Err(RpchError::InvalidFragLength {
                declared: frag_length,
                actual: data.len() - buf.remaining(),
            });
        }

        Ok(Self {
            rpc_version,
            rpc_version_minor,
            ptype,
            pfc_flags,
            packed_drep,
            auth_length,
            call_id,
            flags,
            commands,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let total_len = RTS_HEADER_LEN
            + self
                .commands
                .iter()
                .map(RtsCommand::encoded_len)
                .sum::<usize>();

        let mut buf = BytesMut::with_capacity(total_len);
        buf.put_u8(self.rpc_version);
        buf.put_u8(self.rpc_version_minor);
        buf.put_u8(self.ptype);
        buf.put_u8(self.pfc_flags);
        buf.put_slice(&self.packed_drep);
        buf.put_u16_le(total_len as u16);
        buf.put_u16_le(self.auth_length);
        buf.put_u32_le(self.call_id);
        buf.put_u16_le(self.flags);
        buf.put_u16_le(self.commands.len() as u16);

        for command in &self.commands {
            command.write_to(&mut buf);
        }

        buf.to_vec()
    }

    pub fn conn_a1(
        call_id: u32,
        virtual_connection_cookie: Uuid,
        out_channel_cookie: Uuid,
    ) -> Self {
        Self::new(
            call_id,
            0,
            vec![
                RtsCommand::Version(RPCH_PROTOCOL_VERSION),
                RtsCommand::Cookie(virtual_connection_cookie),
                RtsCommand::Cookie(out_channel_cookie),
                RtsCommand::ReceiveWindowSize(DEFAULT_RECEIVE_WINDOW_SIZE),
            ],
        )
    }

    pub fn conn_b1(
        call_id: u32,
        virtual_connection_cookie: Uuid,
        in_channel_cookie: Uuid,
        association_group_id: Uuid,
    ) -> Self {
        Self::new(
            call_id,
            0,
            vec![
                RtsCommand::Version(RPCH_PROTOCOL_VERSION),
                RtsCommand::Cookie(virtual_connection_cookie),
                RtsCommand::Cookie(in_channel_cookie),
                RtsCommand::ChannelLifetime(1_073_741_824),
                RtsCommand::ClientKeepalive(300_000),
                RtsCommand::AssociationGroupId(association_group_id),
            ],
        )
    }

    pub fn conn_c2(call_id: u32) -> Self {
        ConnC2::default().to_pdu(call_id)
    }

    pub fn as_conn_a1(&self) -> Result<ConnA1, RpchError> {
        ConnA1::from_pdu(self)
    }

    pub fn as_conn_b1(&self) -> Result<ConnB1, RpchError> {
        ConnB1::from_pdu(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnA1 {
    pub call_id: u32,
    pub version: u32,
    pub virtual_connection_cookie: Uuid,
    pub out_channel_cookie: Uuid,
    pub receive_window_size: u32,
}

impl ConnA1 {
    pub fn parse(data: &[u8]) -> Result<Self, RpchError> {
        let pdu = RtsPdu::parse(data)?;
        Self::from_pdu(&pdu)
    }

    pub fn from_pdu(pdu: &RtsPdu) -> Result<Self, RpchError> {
        if pdu.flags != 0 || pdu.commands.len() != 4 {
            return Err(RpchError::InvalidConnA1);
        }

        match pdu.commands.as_slice() {
            [RtsCommand::Version(version), RtsCommand::Cookie(virtual_connection_cookie), RtsCommand::Cookie(out_channel_cookie), RtsCommand::ReceiveWindowSize(receive_window_size)] => {
                Ok(Self {
                    call_id: pdu.call_id,
                    version: *version,
                    virtual_connection_cookie: *virtual_connection_cookie,
                    out_channel_cookie: *out_channel_cookie,
                    receive_window_size: *receive_window_size,
                })
            }
            _ => Err(RpchError::InvalidConnA1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnB1 {
    pub call_id: u32,
    pub version: u32,
    pub virtual_connection_cookie: Uuid,
    pub in_channel_cookie: Uuid,
    pub channel_lifetime: u32,
    pub client_keepalive: u32,
    pub association_group_id: Uuid,
}

impl ConnB1 {
    pub fn parse(data: &[u8]) -> Result<Self, RpchError> {
        let pdu = RtsPdu::parse(data)?;
        Self::from_pdu(&pdu)
    }

    pub fn from_pdu(pdu: &RtsPdu) -> Result<Self, RpchError> {
        if pdu.flags != 0 || pdu.commands.len() != 6 {
            return Err(RpchError::InvalidConnB1);
        }

        match pdu.commands.as_slice() {
            [RtsCommand::Version(version), RtsCommand::Cookie(virtual_connection_cookie), RtsCommand::Cookie(in_channel_cookie), RtsCommand::ChannelLifetime(channel_lifetime), RtsCommand::ClientKeepalive(client_keepalive), RtsCommand::AssociationGroupId(association_group_id)] => {
                Ok(Self {
                    call_id: pdu.call_id,
                    version: *version,
                    virtual_connection_cookie: *virtual_connection_cookie,
                    in_channel_cookie: *in_channel_cookie,
                    channel_lifetime: *channel_lifetime,
                    client_keepalive: *client_keepalive,
                    association_group_id: *association_group_id,
                })
            }
            _ => Err(RpchError::InvalidConnB1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnC2 {
    pub version: u32,
    pub receive_window_size: u32,
    pub connection_timeout: u32,
}

impl Default for ConnC2 {
    fn default() -> Self {
        Self {
            version: RPCH_PROTOCOL_VERSION,
            receive_window_size: DEFAULT_RECEIVE_WINDOW_SIZE,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
        }
    }
}

impl ConnC2 {
    pub fn to_pdu(&self, call_id: u32) -> RtsPdu {
        RtsPdu::new(
            call_id,
            0,
            vec![
                RtsCommand::Version(self.version),
                RtsCommand::ReceiveWindowSize(self.receive_window_size),
                RtsCommand::ConnectionTimeout(self.connection_timeout),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VirtualConnectionState {
    #[default]
    WaitingOutChannel,
    WaitingInChannel,
    ConnectionEstablished,
    DataTransfer,
}

#[derive(Debug, Clone)]
pub struct VirtualConnection {
    state: VirtualConnectionState,
    version: Option<u32>,
    virtual_connection_cookie: Option<Uuid>,
    out_channel_cookie: Option<Uuid>,
    in_channel_cookie: Option<Uuid>,
    association_group_id: Option<Uuid>,
    receive_window_size: Option<u32>,
    channel_lifetime: Option<u32>,
    client_keepalive: Option<u32>,
    out_call_id: Option<u32>,
    in_call_id: Option<u32>,
}

impl Default for VirtualConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualConnection {
    pub fn new() -> Self {
        Self {
            state: VirtualConnectionState::WaitingOutChannel,
            version: None,
            virtual_connection_cookie: None,
            out_channel_cookie: None,
            in_channel_cookie: None,
            association_group_id: None,
            receive_window_size: None,
            channel_lifetime: None,
            client_keepalive: None,
            out_call_id: None,
            in_call_id: None,
        }
    }

    pub fn state(&self) -> VirtualConnectionState {
        self.state
    }

    pub fn virtual_connection_cookie(&self) -> Option<Uuid> {
        self.virtual_connection_cookie
    }

    pub fn out_channel_cookie(&self) -> Option<Uuid> {
        self.out_channel_cookie
    }

    pub fn in_channel_cookie(&self) -> Option<Uuid> {
        self.in_channel_cookie
    }

    pub fn association_group_id(&self) -> Option<Uuid> {
        self.association_group_id
    }

    pub fn process_rts(
        &mut self,
        channel: ChannelType,
        data: &[u8],
    ) -> Result<Option<RtsPdu>, RpchError> {
        let pdu = RtsPdu::parse(data)?;
        match channel {
            ChannelType::Out => {
                let conn = ConnA1::from_pdu(&pdu)?;
                self.accept_out_channel(conn)?;
                Ok(None)
            }
            ChannelType::In => {
                let conn = ConnB1::from_pdu(&pdu)?;
                let response = self.accept_in_channel(conn)?;
                Ok(Some(response))
            }
        }
    }

    pub fn accept_out_channel(&mut self, conn: ConnA1) -> Result<(), RpchError> {
        if self.state != VirtualConnectionState::WaitingOutChannel {
            return Err(RpchError::UnexpectedState {
                expected: VirtualConnectionState::WaitingOutChannel,
                actual: self.state,
            });
        }

        self.version = Some(conn.version);
        self.virtual_connection_cookie = Some(conn.virtual_connection_cookie);
        self.out_channel_cookie = Some(conn.out_channel_cookie);
        self.receive_window_size = Some(conn.receive_window_size);
        self.out_call_id = Some(conn.call_id);
        self.state = VirtualConnectionState::WaitingInChannel;
        Ok(())
    }

    pub fn accept_in_channel(&mut self, conn: ConnB1) -> Result<RtsPdu, RpchError> {
        if self.state != VirtualConnectionState::WaitingInChannel {
            return Err(RpchError::UnexpectedState {
                expected: VirtualConnectionState::WaitingInChannel,
                actual: self.state,
            });
        }

        let expected_cookie = self
            .virtual_connection_cookie
            .ok_or(RpchError::UnexpectedState {
                expected: VirtualConnectionState::WaitingInChannel,
                actual: VirtualConnectionState::WaitingOutChannel,
            })?;

        if conn.virtual_connection_cookie != expected_cookie {
            return Err(RpchError::VirtualConnectionCookieMismatch {
                expected: expected_cookie,
                actual: conn.virtual_connection_cookie,
            });
        }

        self.version = Some(conn.version);
        self.in_channel_cookie = Some(conn.in_channel_cookie);
        self.association_group_id = Some(conn.association_group_id);
        self.channel_lifetime = Some(conn.channel_lifetime);
        self.client_keepalive = Some(conn.client_keepalive);
        self.in_call_id = Some(conn.call_id);
        self.state = VirtualConnectionState::ConnectionEstablished;

        Ok(ConnC2::default().to_pdu(self.out_call_id.unwrap_or(conn.call_id)))
    }

    pub fn enter_data_transfer(&mut self) -> Result<(), RpchError> {
        if self.state != VirtualConnectionState::ConnectionEstablished {
            return Err(RpchError::UnexpectedState {
                expected: VirtualConnectionState::ConnectionEstablished,
                actual: self.state,
            });
        }

        self.state = VirtualConnectionState::DataTransfer;
        Ok(())
    }
}

fn ensure_remaining(available: usize, needed: usize) -> Result<(), RpchError> {
    if available < needed {
        return Err(RpchError::BufferTooShort {
            needed,
            have: available,
        });
    }
    Ok(())
}

fn get_uuid_le(buf: &mut &[u8]) -> Result<Uuid, RpchError> {
    ensure_remaining(buf.remaining(), 16)?;
    let raw = &buf[..16];
    let uuid = Uuid::from_slice_le(raw).map_err(|_| RpchError::InvalidUuid)?;
    buf.advance(16);
    Ok(uuid)
}

fn put_uuid_le(buf: &mut BytesMut, value: &Uuid) {
    buf.put_slice(&value.to_bytes_le());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    #[test]
    fn rts_pdu_round_trips() {
        let pdu = RtsPdu {
            rpc_version: RPC_VERSION,
            rpc_version_minor: RPC_VERSION_MINOR,
            ptype: PTYPE_RTS,
            pfc_flags: 0x03,
            packed_drep: PACKED_DREP_LITTLE_ENDIAN,
            auth_length: 0,
            call_id: 42,
            flags: 0,
            commands: vec![
                RtsCommand::Version(1),
                RtsCommand::ReceiveWindowSize(DEFAULT_RECEIVE_WINDOW_SIZE),
                RtsCommand::FlowControlAck {
                    bytes_received: 1024,
                    available_window: 2048,
                    channel_cookie: uuid(0x11111111222233334444555555555555),
                },
                RtsCommand::ConnectionTimeout(DEFAULT_CONNECTION_TIMEOUT),
                RtsCommand::Cookie(uuid(0xaaaaaaaa111122223333444455556666)),
                RtsCommand::ChannelLifetime(1_073_741_824),
                RtsCommand::ClientKeepalive(300_000),
                RtsCommand::AssociationGroupId(uuid(0xbbbbbbbb111122223333444455556666)),
            ],
        };

        let bytes = pdu.to_bytes();
        let parsed = RtsPdu::parse(&bytes).unwrap();
        assert_eq!(parsed, pdu);
    }

    #[test]
    fn parses_conn_a1() {
        let vc = uuid(0x11111111222233334444555555555555);
        let out = uuid(0x99999999aaaabbbbccccdddddddddddd);
        let bytes = RtsPdu::conn_a1(7, vc, out).to_bytes();

        let conn = ConnA1::parse(&bytes).unwrap();
        assert_eq!(conn.call_id, 7);
        assert_eq!(conn.version, RPCH_PROTOCOL_VERSION);
        assert_eq!(conn.virtual_connection_cookie, vc);
        assert_eq!(conn.out_channel_cookie, out);
        assert_eq!(conn.receive_window_size, DEFAULT_RECEIVE_WINDOW_SIZE);
    }

    #[test]
    fn parses_conn_b1() {
        let vc = uuid(0x11111111222233334444555555555555);
        let input = uuid(0x22222222333344445555666677777777);
        let assoc = uuid(0x1234567890abcdef1234567890abcdef);
        let bytes = RtsPdu::conn_b1(9, vc, input, assoc).to_bytes();

        let conn = ConnB1::parse(&bytes).unwrap();
        assert_eq!(conn.call_id, 9);
        assert_eq!(conn.version, RPCH_PROTOCOL_VERSION);
        assert_eq!(conn.virtual_connection_cookie, vc);
        assert_eq!(conn.in_channel_cookie, input);
        assert_eq!(conn.channel_lifetime, 1_073_741_824);
        assert_eq!(conn.client_keepalive, 300_000);
        assert_eq!(conn.association_group_id, assoc);
    }

    #[test]
    fn generates_conn_c2() {
        let pdu = RtsPdu::conn_c2(11);

        assert_eq!(pdu.call_id, 11);
        assert_eq!(
            pdu.commands,
            vec![
                RtsCommand::Version(RPCH_PROTOCOL_VERSION),
                RtsCommand::ReceiveWindowSize(DEFAULT_RECEIVE_WINDOW_SIZE),
                RtsCommand::ConnectionTimeout(DEFAULT_CONNECTION_TIMEOUT),
            ]
        );
    }

    #[test]
    fn virtual_connection_transitions_to_data_transfer() {
        let vc = uuid(0x11111111222233334444555555555555);
        let out = uuid(0x22222222333344445555666677777777);
        let input = uuid(0x33333333444455556666777788888888);
        let assoc = uuid(0x44444444555566667777888899999999);

        let mut connection = VirtualConnection::new();

        let out_bytes = RtsPdu::conn_a1(100, vc, out).to_bytes();
        assert!(connection
            .process_rts(ChannelType::Out, &out_bytes)
            .unwrap()
            .is_none());
        assert_eq!(connection.state(), VirtualConnectionState::WaitingInChannel);
        assert_eq!(connection.virtual_connection_cookie(), Some(vc));
        assert_eq!(connection.out_channel_cookie(), Some(out));

        let in_bytes = RtsPdu::conn_b1(101, vc, input, assoc).to_bytes();
        let response = connection
            .process_rts(ChannelType::In, &in_bytes)
            .unwrap()
            .unwrap();
        assert_eq!(
            connection.state(),
            VirtualConnectionState::ConnectionEstablished
        );
        assert_eq!(connection.in_channel_cookie(), Some(input));
        assert_eq!(connection.association_group_id(), Some(assoc));
        assert_eq!(response, RtsPdu::conn_c2(100));

        connection.enter_data_transfer().unwrap();
        assert_eq!(connection.state(), VirtualConnectionState::DataTransfer);
    }

    #[test]
    fn rejects_mismatched_virtual_connection_cookie() {
        let mut connection = VirtualConnection::new();
        let vc = uuid(0x11111111222233334444555555555555);
        let different_vc = uuid(0x99999999888877776666555544444444);

        connection
            .accept_out_channel(ConnA1::parse(&RtsPdu::conn_a1(1, vc, uuid(2)).to_bytes()).unwrap())
            .unwrap();

        let err = connection
            .accept_in_channel(
                ConnB1::parse(&RtsPdu::conn_b1(2, different_vc, uuid(3), uuid(4)).to_bytes())
                    .unwrap(),
            )
            .unwrap_err();

        assert_eq!(
            err,
            RpchError::VirtualConnectionCookieMismatch {
                expected: vc,
                actual: different_vc,
            }
        );
    }
}
