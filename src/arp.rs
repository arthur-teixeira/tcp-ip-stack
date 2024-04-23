use crate::BufferView;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};

pub type ArpCache = HashMap<String, ArpIpv4>;

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

    fn to_u16(&self) -> u16 {
        match self {
            Self::ArpEthernet => ARP_ETHERNET,
        }
    }
}

const ARP_IPV4: u16 = 0x0800;
#[derive(Debug, PartialEq)]
pub enum ArpProtocolType {
    ArpIpv4,
}

impl ArpProtocolType {
    fn from_u16(n: u16) -> Result<Self> {
        match n {
            ARP_IPV4 => Ok(Self::ArpIpv4),
            _ => Err(Error::new(ErrorKind::Unsupported, "Unsupported protocol")),
        }
    }
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

#[derive(Debug)]
pub struct ArpHeader {
    pub hwtype: ArpHwType,
    pub protype: ArpProtocolType,
    pub hwsize: u8,
    pub prosize: u8,
    pub opcode: ArpOp,
    pub data: Box<[u8]>,
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
}

pub struct ArpIpv4 {
    smac: [u8; 6],
    sip: u32,
    dmac: [u8; 6],
    dip: u32,
}

impl ArpIpv4 {
    fn from_header(header: &ArpHeader) -> Result<Self> {
        let mut view = BufferView::from_slice(&header.data, header.data.len())?;
        let mut smac = [0 as u8; 6];
        smac.copy_from_slice(view.read_slice(6));

        let sip = view.read_u32();
        let mut dmac = [0 as u8; 6];
        dmac.copy_from_slice(view.read_slice(6));
        let dip = view.read_u32();

        Ok(Self {
            smac,
            sip,
            dmac,
            dip,
        })
    }
}

pub fn arp_recv(packet: &ArpHeader, cache: &mut ArpCache) -> Result<()> {
    let ipv4_packet = ArpIpv4::from_header(packet)?;

    let cache_key = format!("{}-{}", packet.hwtype.to_u16(), ipv4_packet.sip);

    let merge = match cache.get_mut(&cache_key) {
        Some(entry) => {
            entry.smac = ipv4_packet.smac;
            true
        }
        None => false,
    };

    // TODO: check if we are the target address

    if !merge {
        cache.insert(cache_key, ipv4_packet);
    }

    match packet.opcode {
        ArpOp::RarpRequest => {
            // TODO: reply
        }
        _ => {},
    }

    Ok(())
}
