use bitfield::bitfield;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;

use crate::arp::{ArpHwType, ArpCache, TunInterface, MAC_OCTETS};
use crate::ethernet::Frame;
use crate::{icmpv4, tcp, udp};
use crate::utils::calculate_checksum;

pub const IPV4: u8 = 0x04;
pub const IP_TCP: u8 = 0x06;
pub const IP_UDP: u8 = 0x11;
pub const ICMPV4: u8 = 0x01;

pub enum IpProtocol {
    IPV4 = IPV4 as isize,
    TCP = IP_TCP as isize,
    UDP = IP_UDP as isize,
    ICMPV4 = ICMPV4 as isize,
}

bitfield! {
    pub struct IpV4Header (MSB0 [u8]);
    impl Debug;
    impl PartialEq;
    impl Eq;
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

pub struct IpV4Packet<'a>(&'a [u8]);
pub struct WritableIpV4Packet<'a>(&'a mut [u8]);

impl IpV4Packet<'_> {
    const IPV4_HEADER_SIZE: usize = 20;

    pub fn header(&self) -> IpV4Header<&[u8]> {
        IpV4Header(self.0)
    }

    pub fn data(&self) -> &[u8] {
        &self.0[Self::IPV4_HEADER_SIZE..]
    }
}

impl<'a> WritableIpV4Packet<'a> {
    const IPV4_HEADER_SIZE: usize = 20;

    pub fn header(&mut self) -> IpV4Header<&mut [u8]> {
        IpV4Header(self.0)
    }

    pub fn data(&mut self) -> &mut [u8] {
        &mut self.0[Self::IPV4_HEADER_SIZE..]
    }

    pub fn raw_header(&self) -> &[u8] {
        &self.0[0..Self::IPV4_HEADER_SIZE]
    }

    pub fn set_data(&mut self, data: &[u8]) {
        self.data().copy_from_slice(data)
    }
}

pub fn ipv4_recv(
    frame_data: &[u8],
    arp_cache: &ArpCache,
    iface: &mut dyn TunInterface,
) -> Result<()> {
    let packet = IpV4Packet(frame_data);
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
        ICMPV4 => icmpv4::icmpv4_incoming(packet, arp_cache, iface),
        IP_TCP => {
            println!("Incoming TCP connection");
            tcp::tcp_incoming(packet, iface, arp_cache)
        }
        IP_UDP => udp::udp_incoming(packet),
        _ => Err(Error::new(ErrorKind::Unsupported, "Unsupported protocol")),
    }
}

pub fn ipv4_send(
    request: &IpV4Packet,
    data: &[u8],
    daddr: Ipv4Addr,
    arp_cache: &ArpCache,
    protocol: IpProtocol,
    iface: &mut dyn TunInterface,
) -> Result<()> {
    let len: u16 = data.len() as u16 + 20;
    let mut response_buffer = vec![0; len as usize];
    let mut response_packet = WritableIpV4Packet(&mut response_buffer);
    let mut hdr = response_packet.header();
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

    let mut hdr = response_packet.header();
    hdr.set_checksum(csum);

    let k = format!("{}-{}", ArpHwType::Ethernet.to_u16(), daddr);

    let arp_entry = match arp_cache.get(&k) {
        Some(arp_entry) => arp_entry,
        // TODO: Send ARP request and retry later
        None => {
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
        payload: &response_buffer,
    };

    let response = &frame.to_buffer();
    let snt = iface.snd(response)?;

    if snt != response.len() {
        Err(Error::new(ErrorKind::Other, "Could not send full response"))
    } else {
        Ok(())
    }
}
