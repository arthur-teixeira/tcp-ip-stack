use crate::BufferView;
use std::io::{Error, ErrorKind, Result};

#[derive(Debug)]
pub struct ArpHeader {
    pub hwtype: ArpHwType,
    pub protype: ArpProtocolType,
    pub hwsize: u8,
    pub prosize: u8,
    pub opcode: ArpOp,
    pub data: Box<[u8]>,
}

const ARP_ETHERNET: u16 = 0x0001;
#[derive(Debug, PartialEq)]
pub enum ArpHwType {
    ArpEthernet,
}

impl ArpHwType {
    fn from_u16(n: u16) -> Result<Self> {
        match n {
            ARP_ETHERNET => Ok(Self::ArpEthernet),
            _ => Err(Error::new(ErrorKind::Unsupported, "Unsupported HW type")),
        }
    }
}

const ARP_IPV4: u16 = 0x0800;
#[derive(Debug, PartialEq)]
pub enum ArpProtocolType {
    ArpIpv4,
}

#[derive(Debug, PartialEq)]
pub enum ArpOp {
    ArpRequest,
    ArpResponse,
    RarpRequest,
    RarpResponse,
}

impl ArpOp {
    fn from_u16(n: u16) -> Result<Self> {
        match n {
            1 => Ok(Self::ArpRequest),
            2 => Ok(Self::ArpResponse),
            3 => Ok(Self::RarpRequest),
            4 => Ok(Self::RarpResponse),
            _ => Err(Error::new(ErrorKind::InvalidData, "Invalid ARP opcode")),
        }
    }
}

impl ArpProtocolType {
    fn from_u16(n: u16) -> Result<Self> {
        match n {
            ARP_IPV4 => Ok(Self::ArpIpv4),
            _ => Err(Error::new(ErrorKind::Unsupported, "Unsupported protocol")),
        }
    }
}

impl ArpHeader {
    pub fn from_bytes(bs: &[u8], size: usize) -> Result<Self> {
        let mut sock_buff = BufferView::from_slice(bs, size)?;
        ArpHeader::from_buffer(&mut sock_buff)
    }

    fn from_buffer(buf: &mut BufferView) -> Result<Self> {
        Ok(Self {
            hwtype: ArpHwType::from_u16(buf.read_u16())?,
            protype: ArpProtocolType::from_u16(buf.read_u16())?,
            hwsize: buf.read_u8(),
            prosize: buf.read_u8(),
            opcode: ArpOp::from_u16(buf.read_u16())?,
            data: buf.read_slice(buf.size - buf.pos).into(),
        })
    }

    pub fn recv(&mut self) -> Result<()> {
        println!("ARP Packet: ${self:?}");
        Ok(())
    }
}
