use bitfield::bitfield;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;

use crate::arp::{arp_request, ArpHwType, TunInterface, MAC_OCTETS};
use crate::ethernet::Frame;
use crate::route::ROUTES;
use crate::utils::calculate_checksum;
use crate::{icmpv4, tcp, udp, Interface};

pub const IPV4: u8 = 0x04;
pub const IP_TCP: u8 = 0x06;
pub const IP_UDP: u8 = 0x11;
pub const ICMPV4: u8 = 0x01;

pub enum IpProtocol {
    TCP = IP_TCP as isize,
    UDP = IP_UDP as isize,
    ICMPV4 = ICMPV4 as isize,
}

bitfield! {
    pub struct IpV4Header (MSB0 [u8]);
    impl Debug;
    impl PartialEq;
    impl Eq;
    impl Copy;
    impl Hash;
    pub u8, version, set_version: 3, 0;
    pub u8, ihl, set_ihl: 7, 4;
    pub u8, tos, set_tos: 15, 8;
    pub u16, len, set_len: 31, 16;
    pub u16, id, set_id: 47, 32;
    pub u8, df, set_df: 49;
    pub u8, mf, set_mf: 50;
    pub u16, frag_offset, set_frag_offset: 63, 51;
    pub u8, ttl, set_ttl: 71, 64;
    pub u8, proto, set_proto: 79, 72;
    pub u16, checksum, set_checksum: 95, 80;
    pub u32, src_addr, set_src_addr: 127, 96;
    pub u32, dst_addr, set_dst_addr: 159, 128;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpV4Packet(pub Vec<u8>);

impl IpV4Packet {
    const IPV4_HEADER_SIZE: usize = 20;

    pub fn header(&self) -> IpV4Header<&[u8]> {
        IpV4Header(&self.0)
    }

    pub fn mut_header(&mut self) -> IpV4Header<&mut [u8]> {
        IpV4Header(&mut self.0)
    }

    pub fn mut_data(&mut self) -> &mut [u8] {
        &mut self.0[Self::IPV4_HEADER_SIZE..]
    }

    pub fn data(&self) -> &[u8] {
        &self.0[Self::IPV4_HEADER_SIZE..]
    }

    pub fn raw_header(&self) -> &[u8] {
        &self.0[0..Self::IPV4_HEADER_SIZE]
    }

    pub fn set_data(&mut self, data: &[u8]) {
        self.mut_data().copy_from_slice(data);
    }

    pub fn raw(&self) -> &[u8] {
        &self.0
    }
}

pub fn ipv4_recv<T: TunInterface>(
    frame_data: &[u8],
    interface: Interface<T>,
) -> Result<()> {
    let packet = IpV4Packet(frame_data.to_vec());
    let hdr = packet.header();

    if hdr.version() != 4 {
        return Err(Error::new(ErrorKind::Unsupported, "Ip version is not 4"));
    }

    if hdr.ihl() < 5 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Packet length must be at least 5",
        ));
    }

    if hdr.ttl() == 0 {
        return Err(Error::new(ErrorKind::InvalidData, "Datagram ttl reached 0"));
    }

    let header_length = hdr.ihl() as usize * 4;

    let csum = calculate_checksum(&frame_data[..header_length], 5);
    if csum != hdr.checksum() {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid checksum"));
    }

    match hdr.proto() {
        ICMPV4 => icmpv4::icmpv4_incoming(packet, interface),
        IP_TCP => tcp::tcp_incoming(packet, interface),
        IP_UDP => udp::udp_incoming(packet),
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            format!("Unsupported protocol {}", hdr.proto()),
        )),
    }
}

pub fn ipv4_send<T: TunInterface>(
    request: &IpV4Packet,
    data: &[u8],
    mut daddr: Ipv4Addr,
    protocol: IpProtocol,
    interface: Interface<T>,
) -> Result<()> {
    let rt = ROUTES.lookup(daddr);
    if rt.is_default_gateway {
        daddr = rt.gateway;
    }

    let len: u16 = data.len() as u16 + 20;
    let mut response_packet = IpV4Packet(vec![0; len as usize]);
    let mut hdr = response_packet.mut_header();
    hdr.set_version(IPV4);
    hdr.set_ihl(0x05);
    hdr.set_tos(0);
    hdr.set_len(len);
    hdr.set_id(request.header().id());
    hdr.set_frag_offset(0x4000);
    hdr.set_df(request.header().df());
    hdr.set_mf(request.header().mf());
    hdr.set_ttl(64);
    hdr.set_proto(protocol as u8);
    hdr.set_src_addr(crate::arp::IP_ADDR.into());
    hdr.set_dst_addr(daddr.into());
    hdr.set_checksum(0);
    response_packet.set_data(data);

    let csum = calculate_checksum(response_packet.raw_header(), 5);

    let mut hdr = response_packet.mut_header();
    hdr.set_checksum(csum);

    let k = format!("{}-{}", ArpHwType::Ethernet.to_u16(), daddr);

    let mut interface = interface.lock().unwrap();
    let arp_entry = match interface.arp_cache.get(&k) {
        Some(arp_entry) => arp_entry,
        // TODO: Send ARP request and retry later
        None => {
            arp_request(crate::arp::IP_ADDR, daddr, rt.netdev, &mut interface)?;
            return Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "MAC address was not in cache",
            ))
        }
    };

    let frame = Frame {
        smac: MAC_OCTETS,
        dmac: arp_entry.smac,
        ethertype: libc::ETH_P_IP as u16,
        payload: response_packet.raw(),
    };

    let response = &frame.to_buffer();
    let snt = interface.iface.snd(response)?;

    if snt != response.len() {
        Err(Error::new(ErrorKind::Other, "Could not send full response"))
    } else {
        Ok(())
    }
}
