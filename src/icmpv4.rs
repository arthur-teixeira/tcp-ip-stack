use crate::{buf_writer::BufWriter, calculate_checksum, ipv4_data, BufferView};
use std::io::{Error, ErrorKind, Result};

#[derive(Clone, Copy)]
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

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf_writer = BufWriter::new();
        buf_writer.write_u8(self.message_type as u8);
        buf_writer.write_u8(self.code);
        buf_writer.write_u16(self.csum);
        buf_writer.write_slice(&self.data.to_bytes());

        buf_writer.buf
    }
}

pub enum IcmpV4Message<'a> {
    Echo { id: u16, seq: u16, data: &'a [u8] },
    DstUnreachable { len: u8, var: u16, data: &'a [u8] },
}

impl<'a> IcmpV4Message<'a> {
    fn from_buffer(buf: &'a mut BufferView, msg_type: &IcmpV4MessageType) -> Self {
        match msg_type {
            IcmpV4MessageType::EchoRequest | IcmpV4MessageType::EchoReply => {
                IcmpV4Message::build_echo_msg(buf)
            }
            IcmpV4MessageType::DestinationUnreachable => {
                IcmpV4Message::build_dst_unreachable_msg(buf)
            }
        }
    }

    fn build_echo_msg(buf: &'a mut BufferView) -> Self {
        let id = buf.read_u16();
        let seq = buf.read_u16();
        let data = buf.read_slice(buf.size - buf.pos);

        Self::Echo { id, seq, data }
    }

    fn build_dst_unreachable_msg(buf: &'a mut BufferView) -> Self {
        let _ = buf.read_u8();
        let len = buf.read_u8();
        let var = buf.read_u16();
        let data = buf.read_slice(buf.size - buf.pos);

        Self::DstUnreachable { len, var, data }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf_writer = BufWriter::new();
        match self {
            Self::Echo { id, seq, data } => {
                buf_writer.write_u16(*id);
                buf_writer.write_u16(*seq);
                buf_writer.write_slice(data);

                buf_writer.buf
            }
            Self::DstUnreachable { len, var, data } => {
                buf_writer.write_u8(*len);
                buf_writer.write_u16(*var);
                buf_writer.write_slice(data);

                buf_writer.buf
            }
        }
    }
}

fn icmpv4_reply(mut icmp_hdr: IcmpV4Header) -> Result<()> {
    icmp_hdr.message_type = IcmpV4MessageType::EchoReply;
    icmp_hdr.csum = 0;
    icmp_hdr.csum = calculate_checksum(&icmp_hdr.to_bytes(), 1);

    // TODO: wrap ICMP packet in an IP frame, and then wrap that into an Ethernet frame.
    // Isolate Ethernet / IP / ICMP frame formatting.

    Ok(())
}

pub fn icmpv4_incoming(ip_frame: &[u8]) -> Result<()> {
    let ip_data = ipv4_data(ip_frame);
    let mut buf_view = BufferView::from_slice(ip_data)?;
    let icmp_hdr = IcmpV4Header::from_buffer(&mut buf_view)?;

    match icmp_hdr.message_type {
        IcmpV4MessageType::EchoRequest => icmpv4_reply(icmp_hdr),
        IcmpV4MessageType::DestinationUnreachable => Err(Error::new(
            ErrorKind::Other,
            "ICMPv4 received destination unreachable",
        )),
        IcmpV4MessageType::EchoReply => unreachable!(),
    }
}
