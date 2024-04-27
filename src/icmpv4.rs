use crate::BufferView;
use std::io::{Error, ErrorKind, Result};

pub enum IcmpMessageType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    EchoRequest = 8,
}

impl IcmpMessageType {
    fn from_u8(n: u8) -> Result<Self> {
        match n {
            0 => Ok(Self::EchoReply),
            3 => Ok(Self::DestinationUnreachable),
            8 => Ok(Self::EchoRequest),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid ICMP message type",
            )),
        }
    }
}

pub struct IcmpV4Header {
    message_type: IcmpMessageType,
    code: u8,
    csum: u16,
    data: Vec<u8>,
}

impl IcmpV4Header {
    fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut view = BufferView::from_slice(&buf)?;
        let message_type = IcmpMessageType::from_u8(view.read_u8())?;
        let code = view.read_u8();
        let csum = view.read_u16();
        let data = view.read_slice(view.size - view.pos).to_vec();

        Ok(Self {
            message_type,
            code,
            csum,
            data,
        })
    }
}
