use bitfield::bitfield;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;

use crate::{arp::ArpCache, icmpv4};

const IPV4: u8 = 0x04;
const IP_TCP: u8 = 0x06;
const ICMPV4: u8 = 0x01;

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

    pub fn raw(&self) -> &[u8] {
        &self.0
    }

    pub fn header(&self) -> IpV4Header<&[u8]> {
        IpV4Header(self.0)
    }

    pub fn data(&self) -> &[u8] {
        &self.0[Self::IPV4_HEADER_SIZE..]
    }
}

impl<'a> WritableIpV4Packet<'a> {
    const IPV4_HEADER_SIZE: usize = 20;

    pub fn init(buf: &'a mut [u8]) -> Self {
        Self(buf)
    }

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

pub fn calculate_checksum(data: &[u8], skipword: usize) -> u16 {
    if data.len() == 0 {
        return 0;
    }

    let len = data.len();
    let mut cur_data = &data[..];
    let mut sum = 0u32;
    let mut i = 0;

    while cur_data.len() >= 2 {
        if i != skipword {
            sum += u16::from_be_bytes(cur_data[0..2].try_into().unwrap()) as u32;
        }
        cur_data = &cur_data[2..];
        i += 1;
    }

    if i != skipword && len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

pub fn ipv4_recv(frame_data: &[u8], arp_cache: &ArpCache) -> Result<()> {
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
        ICMPV4 => icmpv4::icmpv4_incoming(packet, arp_cache),
        _ => Err(Error::new(ErrorKind::Unsupported, "Unsupported protocol")),
    }
}

pub fn ipv4_send(request: &IpV4Packet, data: &[u8], daddr: Ipv4Addr, arp_cache: &ArpCache) -> Result<()> {
    let mut response_buffer: Vec<u8> = Vec::new();
    let mut response_packet = WritableIpV4Packet(&mut response_buffer);
    let mut hdr = response_packet.header();
    hdr.set_version(IPV4);
    hdr.set_ihl(0x05);
    hdr.set_tos(0);
    hdr.set_len(data.len().try_into().unwrap());
    hdr.set_id(request.header().id());
    hdr.set_frag_offset(0x4000);
    hdr.set_ttl(64);
    hdr.set_proto(ICMPV4); // TODO: this is hardcoded
    hdr.set_src_addr(crate::arp::IP_ADDR.into());
    hdr.set_dst_addr(daddr.into());
    hdr.set_checksum(0);

    let csum = calculate_checksum(response_packet.raw_header(), 5);

    let mut hdr = response_packet.header();
    hdr.set_checksum(csum);

    // TODO: Look for destination hw address in ARP cache, build the ethernet frame and send it
    // through device.

    todo!()
}
