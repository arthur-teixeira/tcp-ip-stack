use tun_tap::Iface;

use crate::{BufWriter, BufferView};
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;

pub type ArpCache = HashMap<String, ArpIpv4>;

static IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);
// const MAC_ADDR: &'static str = "00:0b:29:6f:50:24";
const MAC_OCTETS: [u8; 6] = [0, 0x0b, 0x29, 0x6f, 0x50, 0x24];

const ARP_ETHERNET: u16 = 0x0001;
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ArpHwType {
    ArpEthernet = ARP_ETHERNET as isize,
}

impl ArpHwType {
    fn from_u16(n: u16) -> Result<Self> {
        match n {
            ARP_ETHERNET => Ok(Self::ArpEthernet),
            _ => Err(Error::new(ErrorKind::Unsupported, "Unsupported HW type")),
        }
    }

    fn to_u16(&self) -> u16 {
        *self as u16
    }
}

const ARP_IPV4: u16 = 0x0800;
#[derive(Copy, Debug, PartialEq, Clone)]
pub enum ArpProtocolType {
    ArpIpv4 = ARP_IPV4 as isize,
}

impl ArpProtocolType {
    fn from_u16(n: u16) -> Result<Self> {
        match n {
            ARP_IPV4 => Ok(Self::ArpIpv4),
            _ => Err(Error::new(ErrorKind::Unsupported, "Unsupported protocol")),
        }
    }

    fn to_u16(&self) -> u16 {
        *self as u16
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ArpOp {
    ArpRequest = 1,
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

    fn to_u16(&self) -> u16 {
        *self as u16
    }
}

#[derive(Debug, Clone)]
pub struct ArpHeader {
    pub hwtype: ArpHwType,
    pub protype: ArpProtocolType,
    pub hwsize: u8,
    pub prosize: u8,
    pub opcode: ArpOp,
    pub data: Vec<u8>,
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

    fn to_buffer(&self) -> Vec<u8> {
        let mut buf_writer = BufWriter::new();
        buf_writer.write_u16(self.hwtype.to_u16());
        buf_writer.write_u16(self.protype.to_u16());
        buf_writer.write_u8(self.hwsize);
        buf_writer.write_u8(self.prosize);
        buf_writer.write_u16(self.opcode.to_u16());
        buf_writer.buf.extend(&self.data);

        buf_writer.buf
    }
}

#[derive(Clone, Debug)]
#[repr(packed)]
pub struct ArpIpv4 {
    smac: [u8; 6],
    sip: Ipv4Addr,
    dmac: [u8; 6],
    dip: Ipv4Addr,
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
            sip: Ipv4Addr::from(sip),
            dmac,
            dip: Ipv4Addr::from(dip),
        })
    }
}

unsafe fn struct_to_bytes<T: Sized>(p: &T) -> &[u8] {
    core::slice::from_raw_parts((p as *const T) as *const u8, core::mem::size_of::<T>())
}

fn arp_reply(mut header: ArpHeader, packet: &ArpIpv4, iface: &mut Iface) -> Result<()> {
    let response_packet = ArpIpv4 {
        dip: packet.sip,
        dmac: packet.smac,
        sip: IP_ADDR,
        smac: MAC_OCTETS,
    };

    header.opcode = ArpOp::ArpResponse;
    header.data = unsafe { struct_to_bytes(&response_packet) }.to_vec();

    let ether_frame = crate::Frame {
        dmac: response_packet.dmac,
        smac: response_packet.smac,
        ethertype: libc::ETH_P_ARP as u16,
        payload: &header.to_buffer(),
    };

    let ether_buf = ether_frame.to_buffer();
    let snt = iface.send(&ether_buf)?;

    eprintln!("Sent {snt} bytes");

    Ok(())
}

pub fn arp_recv(packet: &ArpHeader, cache: &mut ArpCache, iface: &mut Iface) -> Result<()> {
    let ipv4_packet = ArpIpv4::from_header(packet)?;

    let cache_key = format!("{}-{}", packet.hwtype.to_u16(), ipv4_packet.sip);

    let merge = match cache.get_mut(&cache_key) {
        Some(entry) => {
            entry.smac = ipv4_packet.smac;
            true
        }
        None => false,
    };

    if ipv4_packet.dip != IP_ADDR {
        eprintln!("ARP packet was not for us.");
        return Ok(());
    }

    if !merge {
        cache.insert(cache_key, ipv4_packet.clone());
    }

    match packet.opcode {
        ArpOp::ArpRequest => {
            arp_reply(packet.clone(), &ipv4_packet, iface)?;
        }
        _ => {}
    }

    Ok(())
}
