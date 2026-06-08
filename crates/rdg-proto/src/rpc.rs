//! DCE/RPC PDU framing (bind, bind_ack, request, response).

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;
use uuid::Uuid;

pub const RPC_VERSION: u8 = 5;
pub const RPC_VERSION_MINOR: u8 = 0;
pub const RPC_HEADER_SIZE: usize = 16;
pub const RPC_COMMON_DATA_REPRESENTATION: [u8; 4] = [0x10, 0x00, 0x00, 0x00];

pub const PFC_FIRST_FRAG: u8 = 0x01;
pub const PFC_LAST_FRAG: u8 = 0x02;
pub const PFC_FIRST_AND_LAST_FRAG: u8 = PFC_FIRST_FRAG | PFC_LAST_FRAG;

pub const DEFAULT_MAX_XMIT_FRAG: u16 = 5840;
pub const DEFAULT_MAX_RECV_FRAG: u16 = 5840;

pub const TSG_INTERFACE_UUID: Uuid = Uuid::from_u128(0x44e265dd7daf42cd85603cdb6e7a2729);
pub const TSG_INTERFACE_VERSION: u32 = syntax_version(1, 3);

pub const NDR_TRANSFER_SYNTAX_UUID: Uuid = Uuid::from_u128(0x8a885d041ceb11c99fe808002b104860);
pub const NDR_TRANSFER_SYNTAX_VERSION: u32 = syntax_version(2, 0);

const BIND_FIXED_FIELDS_SIZE: usize = 12;
const REQUEST_FIXED_FIELDS_SIZE: usize = 8;
const RESPONSE_FIXED_FIELDS_SIZE: usize = 8;
const SYNTAX_ID_SIZE: usize = 20;

const fn syntax_version(major: u16, minor: u16) -> u32 {
    ((minor as u32) << 16) | major as u32
}

fn pad_to_4(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("buffer too short: need {needed} bytes, have {have}")]
    BufferTooShort { needed: usize, have: usize },
    #[error("unknown RPC PDU type: {0}")]
    UnknownPduType(u8),
    #[error("unexpected RPC PDU type: expected {expected:?}, got {actual:?}")]
    UnexpectedPduType {
        expected: RpcPduType,
        actual: RpcPduType,
    },
    #[error("invalid RPC version: {major}.{minor}")]
    InvalidVersion { major: u8, minor: u8 },
    #[error("invalid fragment length: {frag_length}")]
    InvalidFragmentLength { frag_length: u16 },
    #[error("invalid bind context count: {0}")]
    InvalidContextCount(u8),
    #[error("invalid transfer syntax count: {0}")]
    InvalidTransferSyntaxCount(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RpcPduType {
    Request = 0,
    Response = 2,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterContext = 14,
    AlterContextResp = 15,
}

impl RpcPduType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Request),
            2 => Some(Self::Response),
            11 => Some(Self::Bind),
            12 => Some(Self::BindAck),
            13 => Some(Self::BindNak),
            14 => Some(Self::AlterContext),
            15 => Some(Self::AlterContextResp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcPduHeader {
    pub rpc_vers: u8,
    pub rpc_vers_minor: u8,
    pub ptype: RpcPduType,
    pub pfc_flags: u8,
    pub packed_drep: [u8; 4],
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl RpcPduHeader {
    pub fn new(
        ptype: RpcPduType,
        pfc_flags: u8,
        frag_length: u16,
        auth_length: u16,
        call_id: u32,
    ) -> Self {
        Self {
            rpc_vers: RPC_VERSION,
            rpc_vers_minor: RPC_VERSION_MINOR,
            ptype,
            pfc_flags,
            packed_drep: RPC_COMMON_DATA_REPRESENTATION,
            frag_length,
            auth_length,
            call_id,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, RpcError> {
        if buf.len() < RPC_HEADER_SIZE {
            return Err(RpcError::BufferTooShort {
                needed: RPC_HEADER_SIZE,
                have: buf.len(),
            });
        }

        let mut r = buf;
        let rpc_vers = r.get_u8();
        let rpc_vers_minor = r.get_u8();
        if rpc_vers != RPC_VERSION || rpc_vers_minor != RPC_VERSION_MINOR {
            return Err(RpcError::InvalidVersion {
                major: rpc_vers,
                minor: rpc_vers_minor,
            });
        }

        let ptype =
            RpcPduType::from_u8(r.get_u8()).ok_or_else(|| RpcError::UnknownPduType(buf[2]))?;
        let pfc_flags = r.get_u8();
        let mut packed_drep = [0u8; 4];
        r.copy_to_slice(&mut packed_drep);
        let frag_length = r.get_u16_le();
        if frag_length < RPC_HEADER_SIZE as u16 {
            return Err(RpcError::InvalidFragmentLength { frag_length });
        }
        if buf.len() < frag_length as usize {
            return Err(RpcError::BufferTooShort {
                needed: frag_length as usize,
                have: buf.len(),
            });
        }
        let auth_length = r.get_u16_le();
        let call_id = r.get_u32_le();

        Ok(Self {
            rpc_vers,
            rpc_vers_minor,
            ptype,
            pfc_flags,
            packed_drep,
            frag_length,
            auth_length,
            call_id,
        })
    }

    pub fn write(&self, buf: &mut BytesMut) {
        buf.put_u8(self.rpc_vers);
        buf.put_u8(self.rpc_vers_minor);
        buf.put_u8(self.ptype as u8);
        buf.put_u8(self.pfc_flags);
        buf.extend_from_slice(&self.packed_drep);
        buf.put_u16_le(self.frag_length);
        buf.put_u16_le(self.auth_length);
        buf.put_u32_le(self.call_id);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxId {
    pub uuid: Uuid,
    pub version: u32,
}

impl SyntaxId {
    pub const fn new(uuid: Uuid, version: u32) -> Self {
        Self { uuid, version }
    }

    pub fn tsg() -> Self {
        Self::new(TSG_INTERFACE_UUID, TSG_INTERFACE_VERSION)
    }

    pub fn ndr() -> Self {
        Self::new(NDR_TRANSFER_SYNTAX_UUID, NDR_TRANSFER_SYNTAX_VERSION)
    }

    fn parse(buf: &mut &[u8]) -> Result<Self, RpcError> {
        if buf.len() < SYNTAX_ID_SIZE {
            return Err(RpcError::BufferTooShort {
                needed: SYNTAX_ID_SIZE,
                have: buf.len(),
            });
        }

        let mut uuid_bytes = [0u8; 16];
        buf.copy_to_slice(&mut uuid_bytes);
        let version = buf.get_u32_le();

        Ok(Self {
            uuid: Uuid::from_bytes_le(uuid_bytes),
            version,
        })
    }

    fn write(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.uuid.to_bytes_le());
        buf.put_u32_le(self.version);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindPdu {
    pub header: RpcPduHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub num_contexts: u8,
    pub context_id: u16,
    pub num_transfer_syntaxes: u8,
    pub abstract_syntax: SyntaxId,
    pub transfer_syntax: SyntaxId,
}

impl BindPdu {
    pub fn parse(buf: &[u8]) -> Result<Self, RpcError> {
        let header = RpcPduHeader::parse(buf)?;
        if header.ptype != RpcPduType::Bind {
            return Err(RpcError::UnexpectedPduType {
                expected: RpcPduType::Bind,
                actual: header.ptype,
            });
        }

        let frag_length = header.frag_length as usize;
        let body_end = frag_length.checked_sub(header.auth_length as usize).ok_or(
            RpcError::InvalidFragmentLength {
                frag_length: header.frag_length,
            },
        )?;

        if body_end < RPC_HEADER_SIZE + BIND_FIXED_FIELDS_SIZE {
            return Err(RpcError::BufferTooShort {
                needed: RPC_HEADER_SIZE + BIND_FIXED_FIELDS_SIZE,
                have: body_end,
            });
        }

        let mut r = &buf[RPC_HEADER_SIZE..body_end];
        let max_xmit_frag = r.get_u16_le();
        let max_recv_frag = r.get_u16_le();
        let assoc_group_id = r.get_u32_le();
        let num_contexts = r.get_u8();
        if num_contexts == 0 {
            return Err(RpcError::InvalidContextCount(num_contexts));
        }
        r.advance(3);

        let mut first_context_id = 0;
        let mut first_num_transfer_syntaxes = 0;
        let mut first_abstract_syntax = None;
        let mut first_transfer_syntax = None;

        for context_index in 0..num_contexts {
            if r.len() < 4 {
                return Err(RpcError::BufferTooShort {
                    needed: 4,
                    have: r.len(),
                });
            }

            let context_id = r.get_u16_le();
            let num_transfer_syntaxes = r.get_u8();
            if num_transfer_syntaxes == 0 {
                return Err(RpcError::InvalidTransferSyntaxCount(num_transfer_syntaxes));
            }
            r.advance(1);

            let abstract_syntax = SyntaxId::parse(&mut r)?;
            let mut transfer_syntax = None;

            for transfer_index in 0..num_transfer_syntaxes {
                let parsed = SyntaxId::parse(&mut r)?;
                if transfer_index == 0 {
                    transfer_syntax = Some(parsed);
                }
            }

            if context_index == 0 {
                first_context_id = context_id;
                first_num_transfer_syntaxes = num_transfer_syntaxes;
                first_abstract_syntax = Some(abstract_syntax);
                first_transfer_syntax = transfer_syntax;
            }
        }

        let abstract_syntax = first_abstract_syntax.ok_or(RpcError::InvalidContextCount(0))?;
        let transfer_syntax =
            first_transfer_syntax.ok_or(RpcError::InvalidTransferSyntaxCount(0))?;

        Ok(Self {
            header,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            num_contexts,
            context_id: first_context_id,
            num_transfer_syntaxes: first_num_transfer_syntaxes,
            abstract_syntax,
            transfer_syntax,
        })
    }

    pub fn is_tsg_bind(&self) -> bool {
        self.abstract_syntax == SyntaxId::tsg() && self.transfer_syntax == SyntaxId::ndr()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindAckPdu {
    pub header: RpcPduHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub sec_addr: Bytes,
    pub result: u16,
    pub reason: u16,
    pub transfer_syntax: SyntaxId,
}

impl BindAckPdu {
    pub fn accepted(call_id: u32, assoc_group_id: u32, sec_addr: impl AsRef<[u8]>) -> Self {
        Self {
            header: RpcPduHeader::new(RpcPduType::BindAck, PFC_FIRST_AND_LAST_FRAG, 0, 0, call_id),
            max_xmit_frag: DEFAULT_MAX_XMIT_FRAG,
            max_recv_frag: DEFAULT_MAX_RECV_FRAG,
            assoc_group_id,
            sec_addr: Bytes::copy_from_slice(sec_addr.as_ref()),
            result: 0,
            reason: 0,
            transfer_syntax: SyntaxId::ndr(),
        }
    }

    pub fn encode(&self) -> Bytes {
        let sec_addr_len = self.sec_addr.len();
        let sec_addr_padding = pad_to_4(2 + sec_addr_len);
        let frag_length = RPC_HEADER_SIZE
            + 2
            + 2
            + 4
            + 2
            + sec_addr_len
            + sec_addr_padding
            + 1
            + 3
            + 2
            + 2
            + SYNTAX_ID_SIZE;

        let mut buf = BytesMut::with_capacity(frag_length);
        let mut header = self.header;
        header.frag_length = frag_length as u16;
        header.auth_length = 0;
        header.write(&mut buf);

        buf.put_u16_le(self.max_xmit_frag);
        buf.put_u16_le(self.max_recv_frag);
        buf.put_u32_le(self.assoc_group_id);
        buf.put_u16_le(sec_addr_len as u16);
        buf.extend_from_slice(&self.sec_addr);
        if sec_addr_padding > 0 {
            buf.extend(std::iter::repeat_n(0u8, sec_addr_padding));
        }
        buf.put_u8(1);
        buf.extend_from_slice(&[0u8; 3]);
        buf.put_u16_le(self.result);
        buf.put_u16_le(self.reason);
        self.transfer_syntax.write(&mut buf);

        buf.freeze()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPdu {
    pub header: RpcPduHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub stub_data: Bytes,
}

impl RequestPdu {
    pub fn parse(buf: &[u8]) -> Result<Self, RpcError> {
        let header = RpcPduHeader::parse(buf)?;
        if header.ptype != RpcPduType::Request {
            return Err(RpcError::UnexpectedPduType {
                expected: RpcPduType::Request,
                actual: header.ptype,
            });
        }

        let frag_length = header.frag_length as usize;
        let body_end = frag_length.checked_sub(header.auth_length as usize).ok_or(
            RpcError::InvalidFragmentLength {
                frag_length: header.frag_length,
            },
        )?;
        let needed = RPC_HEADER_SIZE + REQUEST_FIXED_FIELDS_SIZE;
        if body_end < needed {
            return Err(RpcError::BufferTooShort {
                needed,
                have: body_end,
            });
        }

        let mut r = &buf[RPC_HEADER_SIZE..body_end];
        let alloc_hint = r.get_u32_le();
        let context_id = r.get_u16_le();
        let opnum = r.get_u16_le();
        let stub_data = Bytes::copy_from_slice(r);

        Ok(Self {
            header,
            alloc_hint,
            context_id,
            opnum,
            stub_data,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsePdu {
    pub header: RpcPduHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub reserved: u8,
    pub stub_data: Bytes,
}

impl ResponsePdu {
    pub fn new(call_id: u32, context_id: u16, stub_data: impl Into<Bytes>) -> Self {
        let stub_data = stub_data.into();
        Self {
            header: RpcPduHeader::new(RpcPduType::Response, PFC_FIRST_AND_LAST_FRAG, 0, 0, call_id),
            alloc_hint: stub_data.len() as u32,
            context_id,
            cancel_count: 0,
            reserved: 0,
            stub_data,
        }
    }

    pub fn encode(&self) -> Bytes {
        let frag_length = RPC_HEADER_SIZE + RESPONSE_FIXED_FIELDS_SIZE + self.stub_data.len();
        let mut buf = BytesMut::with_capacity(frag_length);
        let mut header = self.header;
        header.frag_length = frag_length as u16;
        header.auth_length = 0;
        header.write(&mut buf);

        buf.put_u32_le(self.alloc_hint);
        buf.put_u16_le(self.context_id);
        buf.put_u8(self.cancel_count);
        buf.put_u8(self.reserved);
        buf.extend_from_slice(&self.stub_data);

        buf.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_syntax_id(buf: &mut BytesMut, syntax: &SyntaxId) {
        buf.extend_from_slice(&syntax.uuid.to_bytes_le());
        buf.put_u32_le(syntax.version);
    }

    #[test]
    fn parses_rpc_header() {
        let header = RpcPduHeader::new(RpcPduType::Bind, PFC_FIRST_AND_LAST_FRAG, 16, 0, 7);
        let mut buf = BytesMut::new();
        header.write(&mut buf);

        let parsed = RpcPduHeader::parse(&buf).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn parses_bind_pdu() {
        let abstract_syntax = SyntaxId::tsg();
        let transfer_syntax = SyntaxId::ndr();
        let frag_length =
            (RPC_HEADER_SIZE + BIND_FIXED_FIELDS_SIZE + 4 + SYNTAX_ID_SIZE + SYNTAX_ID_SIZE) as u16;

        let mut buf = BytesMut::with_capacity(frag_length as usize);
        RpcPduHeader::new(RpcPduType::Bind, PFC_FIRST_AND_LAST_FRAG, frag_length, 0, 3)
            .write(&mut buf);
        buf.put_u16_le(DEFAULT_MAX_XMIT_FRAG);
        buf.put_u16_le(DEFAULT_MAX_RECV_FRAG);
        buf.put_u32_le(0);
        buf.put_u8(1);
        buf.extend_from_slice(&[0u8; 3]);
        buf.put_u16_le(0);
        buf.put_u8(1);
        buf.put_u8(0);
        push_syntax_id(&mut buf, &abstract_syntax);
        push_syntax_id(&mut buf, &transfer_syntax);

        let bind = BindPdu::parse(&buf).unwrap();
        assert_eq!(bind.header.ptype, RpcPduType::Bind);
        assert_eq!(bind.context_id, 0);
        assert_eq!(bind.abstract_syntax, abstract_syntax);
        assert_eq!(bind.transfer_syntax, transfer_syntax);
        assert!(bind.is_tsg_bind());
    }

    #[test]
    fn generates_bind_ack() {
        let ack = BindAckPdu::accepted(9, 0x1234, Bytes::from_static(b"\\pipe\\tsgateway"));
        let encoded = ack.encode();

        let header = RpcPduHeader::parse(&encoded).unwrap();
        assert_eq!(header.ptype, RpcPduType::BindAck);
        assert_eq!(header.call_id, 9);

        let mut r = &encoded[RPC_HEADER_SIZE..];
        assert_eq!(r.get_u16_le(), DEFAULT_MAX_XMIT_FRAG);
        assert_eq!(r.get_u16_le(), DEFAULT_MAX_RECV_FRAG);
        assert_eq!(r.get_u32_le(), 0x1234);
        let sec_addr_len = r.get_u16_le() as usize;
        assert_eq!(sec_addr_len, "\\pipe\\tsgateway".len());
        assert_eq!(&r[..sec_addr_len], b"\\pipe\\tsgateway");
        r.advance(sec_addr_len + pad_to_4(2 + sec_addr_len));
        assert_eq!(r.get_u8(), 1);
        r.advance(3);
        assert_eq!(r.get_u16_le(), 0);
        assert_eq!(r.get_u16_le(), 0);

        let syntax = SyntaxId::parse(&mut r).unwrap();
        assert_eq!(syntax, SyntaxId::ndr());
    }

    #[test]
    fn parses_request_pdu() {
        let stub_data = [0xAA, 0xBB, 0xCC, 0xDD];
        let frag_length = (RPC_HEADER_SIZE + REQUEST_FIXED_FIELDS_SIZE + stub_data.len()) as u16;

        let mut buf = BytesMut::with_capacity(frag_length as usize);
        RpcPduHeader::new(
            RpcPduType::Request,
            PFC_FIRST_AND_LAST_FRAG,
            frag_length,
            0,
            11,
        )
        .write(&mut buf);
        buf.put_u32_le(stub_data.len() as u32);
        buf.put_u16_le(0);
        buf.put_u16_le(9);
        buf.extend_from_slice(&stub_data);

        let request = RequestPdu::parse(&buf).unwrap();
        assert_eq!(request.header.call_id, 11);
        assert_eq!(request.opnum, 9);
        assert_eq!(request.stub_data, Bytes::copy_from_slice(&stub_data));
    }

    #[test]
    fn generates_response_pdu() {
        let response = ResponsePdu::new(21, 0, Bytes::from_static(&[1, 2, 3]));
        let encoded = response.encode();

        let header = RpcPduHeader::parse(&encoded).unwrap();
        assert_eq!(header.ptype, RpcPduType::Response);
        assert_eq!(header.call_id, 21);

        let mut r = &encoded[RPC_HEADER_SIZE..];
        assert_eq!(r.get_u32_le(), 3);
        assert_eq!(r.get_u16_le(), 0);
        assert_eq!(r.get_u8(), 0);
        assert_eq!(r.get_u8(), 0);
        assert_eq!(r, &[1, 2, 3]);
    }
}
