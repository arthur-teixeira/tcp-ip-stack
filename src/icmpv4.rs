use crate::BufferView;
use std::io::{Error, ErrorKind, Result};

pub enum IcmpV4MessageType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    EchoRequest = 8,
}

impl IcmpV4MessageType {
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

pub struct IcmpV4Header<'a> {
    message_type: IcmpV4MessageType,
    code: u8,
    csum: u16,
    data: IcmpV4Message<'a>,
}

impl<'a> IcmpV4Header<'a> {
    fn from_buffer(view: &'a mut BufferView) -> Result<Self> {
        let message_type = IcmpV4MessageType::from_u8(view.read_u8())?;
        let code = view.read_u8();
        let csum = view.read_u16();
        let data = IcmpV4Message::from_buffer(view, &message_type);

        Ok(Self {
            message_type,
            code,
            csum,
            data,
        })
    }
}

pub enum IcmpV4Message<'a> {
    Echo {
        id: u16,
        seq: u16,
        data: &'a [u8],
    },
    DstUnreachable {
        len: u8,
        var: u16,
        data: &'a [u8],
    },
}

impl<'a> IcmpV4Message<'a> {
    fn from_buffer(buf: &'a mut BufferView, msg_type: &IcmpV4MessageType) -> Self {
        match msg_type {
            IcmpV4MessageType::EchoRequest | IcmpV4MessageType::EchoReply => IcmpV4Message::build_echo_msg(buf),
            IcmpV4MessageType::DestinationUnreachable => IcmpV4Message::build_dst_unreachable_msg(buf),
        }
    }

    fn build_echo_msg(buf: &'a mut BufferView) -> Self {
        let id = buf.read_u16();
        let seq = buf.read_u16();
        let data = buf.read_slice(buf.size - buf.pos);

        Self::Echo {
            id,
            seq,
            data,
        }
    }

    fn build_dst_unreachable_msg(buf: &'a mut BufferView) -> Self {
        let _ = buf.read_u8();
        let len = buf.read_u8();
        let var = buf.read_u16();
        let data = buf.read_slice(buf.size - buf.pos);

        Self::DstUnreachable {
            len,
            var, 
            data,
        }
    }
}
