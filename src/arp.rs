use tun_tap::Iface;

use crate::{BufWriter, BufferView, Interface};
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;

pub trait TunInterface {
    fn snd(&mut self, buf: &[u8]) -> Result<usize>;
    fn rcv(&mut self, buf: &mut [u8]) -> Result<usize>;
}

impl TunInterface for Iface {
    fn snd(&mut self, buf: &[u8]) -> Result<usize> {
        self.send(buf)
    }

    fn rcv(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.recv(buf)
    }
}

pub type ArpCache = HashMap<String, ArpIpv4>;

pub static IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);
pub const MAC_OCTETS: [u8; 6] = [0, 0x0b, 0x29, 0x6f, 0x50, 0x24];

const ARP_ETHERNET: u16 = 0x0001;
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ArpHwType {
    Ethernet = ARP_ETHERNET as isize,
}

impl ArpHwType {
    pub fn from_u16(n: u16) -> Result<Self> {
        match n {
            ARP_ETHERNET => Ok(Self::Ethernet),
            _ => Err(Error::new(ErrorKind::Unsupported, "Unsupported HW type")),
        }
    }

    pub fn to_u16(&self) -> u16 {
        *self as u16
    }
}

const ARP_IPV4: u16 = 0x0800;
#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum ArpProtocolType {
    Ipv4 = ARP_IPV4 as isize,
}

impl ArpProtocolType {
    fn from_u16(n: u16) -> Result<Self> {
        match n {
            ARP_IPV4 => Ok(Self::Ipv4),
            _ => Err(Error::new(ErrorKind::Unsupported, "Unsupported protocol")),
        }
    }

    fn to_u16(&self) -> u16 {
        *self as u16
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpHeader {
    pub hwtype: ArpHwType,
    pub protype: ArpProtocolType,
    pub hwsize: u8,
    pub prosize: u8,
    pub opcode: ArpOp,
    pub data: Vec<u8>,
}

impl ArpHeader {
    pub fn from_bytes(bs: &[u8]) -> Result<Self> {
        let mut sock_buff = BufferView::from_slice(bs)?;
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(packed)]
pub struct ArpIpv4 {
    pub smac: [u8; 6],
    pub sip: Ipv4Addr,
    pub dmac: [u8; 6],
    pub dip: Ipv4Addr,
}

impl ArpIpv4 {
    fn from_header(header: &ArpHeader) -> Result<Self> {
        let mut view = BufferView::from_slice(&header.data)?;
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

fn arp_reply(
    mut header: ArpHeader,
    packet: &ArpIpv4,
    interface: &mut Interface,
) -> Result<usize> {
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
    interface.iface.snd(&ether_buf)
}

pub fn arp_recv(
    frame_data: &[u8],
    interface: &mut Interface,
) -> Result<usize> {
    let arp_hdr = ArpHeader::from_bytes(frame_data)?;
    let arp_ipv4 = ArpIpv4::from_header(&arp_hdr)?;

    let cache_key = format!("{}-{}", arp_hdr.hwtype.to_u16(), arp_ipv4.sip);

    let merge = match interface.arp_cache.get_mut(&cache_key) {
        Some(entry) => {
            entry.smac = arp_ipv4.smac;
            true
        }
        None => false,
    };

    if arp_ipv4.dip != IP_ADDR {
        eprintln!("ARP packet was not for us.");
        return Ok(0);
    }

    if !merge {
        interface.arp_cache.insert(cache_key, arp_ipv4.clone());
    }

    match arp_hdr.opcode {
        ArpOp::ArpRequest => arp_reply(arp_hdr, &arp_ipv4, interface),
        _ => Ok(0),
    }
}

#[cfg(test)]
mod arp_test {
    use std::{
        fs::{self, File, OpenOptions},
        io::Write,
        os::unix::fs::FileExt,
    };

    use crate::{ethernet::Frame, tcp::Connections};

    use super::*;
    const FRAME: &[u8] = &[
        0, 1, 8, 0, 6, 4, 0, 1, 42, 125, 214, 5, 152, 164, 192, 168, 100, 1, 0, 0, 0, 0, 0, 0, 10,
        0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    struct MockTun {
        pub file: File,
        pub path: &'static str,
    }

    impl MockTun {
        fn new(path: &'static str) -> Self {
            Self {
                file: OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(path)
                    .expect("Expected to open file"),
                path,
            }
        }
    }

    impl Drop for MockTun {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.path);
        }
    }
    impl TunInterface for MockTun {
        fn rcv(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.file.read_at(buf, 0)
        }

        fn snd(&mut self, buf: &[u8]) -> Result<usize> {
            self.file.write(buf)
        }
    }

    fn assert_eq_frame(actual: &Frame, expected: Frame) {
        assert_eq!(actual.ethertype, expected.ethertype);
        assert_eq!(actual.dmac, expected.dmac);
        assert_eq!(actual.smac, expected.smac);
    }

    fn assert_eq_arp_hdr(actual: &ArpHeader, expected: ArpHeader) {
        assert_eq!(actual.protype, expected.protype);
        assert_eq!(actual.prosize, expected.prosize);
        assert_eq!(actual.opcode, expected.opcode);
        assert_eq!(actual.hwtype, expected.hwtype);
        assert_eq!(actual.hwsize, expected.hwsize);
    }

    #[test]
    fn test_arp_recv() {
        let temp_file = MockTun::new("/tmp/mock_tun");
        let arp_cache = ArpCache::new();

        let mut interface = Interface {
            iface: Box::new(temp_file),
            arp_cache,
            tcp_connections: Connections::default()
        };

        let snt = arp_recv(FRAME, &mut interface)
            .expect("Expected to receive data correctly");

        assert_eq!(snt, 42);

        let mut response: [u8; 42] = [0; 42];
        let rcvd = interface.iface
            .rcv(&mut response)
            .expect("Expected to read response");

        assert_eq!(snt, rcvd);

        let mut view = BufferView::from_slice(&response).expect("Expected buffer view");

        let eth_frame = Frame::from_buffer(&mut view);
        assert_eq_frame(
            &eth_frame,
            Frame {
                dmac: [42, 125, 214, 5, 152, 164],
                smac: MAC_OCTETS,
                ethertype: libc::ETH_P_ARP as u16,
                payload: &[],
            },
        );

        let arp_hdr = ArpHeader::from_bytes(eth_frame.payload).expect("Expected valid arp header");

        assert_eq_arp_hdr(
            &arp_hdr,
            ArpHeader {
                hwtype: ArpHwType::Ethernet,
                protype: ArpProtocolType::Ipv4,
                hwsize: 6,
                prosize: 4,
                opcode: ArpOp::ArpResponse,
                data: vec![],
            },
        );

        let arp_ipv4 = ArpIpv4::from_header(&arp_hdr).expect("Expected valid ipv4 arp packet");

        assert_eq!(
            arp_ipv4,
            ArpIpv4 {
                smac: MAC_OCTETS,
                sip: Ipv4Addr::new(10, 0, 0, 7),
                dmac: [42, 125, 214, 5, 152, 164],
                dip: Ipv4Addr::new(192, 168, 100, 1),
            }
        );
    }
}
