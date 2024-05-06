use std::{
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
};

use crate::{
    arp::{ArpCache, TunInterface},
    ipv4_send, utils, IpProtocol, IpV4Packet,
};

use bitfield::bitfield;
use libc::wait;

bitfield! {
    pub struct TcpHeader (MSB0 [u8]);
    impl Debug;
    impl PartialEq;
    impl Eq;
    pub u16, src_port, set_src_port: 15, 0;
    pub u16, dst_port, set_dst_port: 31, 16;
    pub u32, sequence_number, set_sequence_number: 63, 32;
    pub u32, ack_number, set_ack_number: 95, 64;
    pub u16, header_len, set_header_len: 99, 96;
    pub u16, rsvd, set_rsvd: 103, 100;
    pub u8, cwr, set_cwr: 104;
    pub u8, ece, set_ece: 105;
    pub u8, urg, set_urg: 106;
    pub u8, ack, set_ack: 107;
    pub u8, psh, set_psh: 108;
    pub u8, rst, set_rst: 109;
    pub u8, syn, set_syn: 110;
    pub u8, fin, set_fin: 111;
    pub u16, window_size, set_window_size: 127, 112;
    pub u16, checksum, set_checksum: 143, 128;
    pub u16, urgent_ptr, set_urgent_ptr: 159, 144;
}

#[derive(Debug)]
pub struct TcpPacket<'a>(&'a [u8]);

impl TcpPacket<'_> {
    const TCP_HEADER_SIZE: usize = 20;

    pub fn header(&self) -> TcpHeader<&[u8]> {
        TcpHeader(self.0)
    }

    pub fn data(&self) -> &[u8] {
        &self.0[Self::TCP_HEADER_SIZE..]
    }

    pub fn raw(&self) -> &[u8] {
        self.0
    }

    pub fn calculate_checksum(&self, packet: &IpV4Packet) -> u16 {
        let src_ip = &packet.header().src_addr().into();
        let dst_ip = &packet.header().dst_addr().into();

        utils::ipv4_checksum(&self.0, 8, src_ip, dst_ip, IpProtocol::TCP as u8)
    }
}

pub struct WritableTcpPacket<'a>(&'a mut [u8]);
impl WritableTcpPacket<'_> {
    const TCP_HEADER_SIZE: usize = 20;

    pub fn header(&mut self) -> TcpHeader<&mut [u8]> {
        TcpHeader(self.0)
    }

    pub fn raw(&mut self) -> &mut [u8] {
        self.0
    }

    pub fn calculate_checksum(&self, packet: &IpV4Packet) -> u16 {
        let src_ip = &packet.header().src_addr().into();
        let dst_ip = &packet.header().dst_addr().into();

        utils::ipv4_checksum(&self.0, 8, src_ip, dst_ip, IpProtocol::TCP as u8)
    }
}

fn tcp_new_connection(
    ip_packet: &IpV4Packet,
    packet: TcpPacket,
    iface: &mut dyn TunInterface,
    arp_cache: &ArpCache,
) -> Result<()> {
    let daddr = Ipv4Addr::from(ip_packet.header().src_addr());

    let mut response_buf = Vec::from(packet.raw());
    let mut response_packet = WritableTcpPacket(&mut response_buf);
    let mut response_header = response_packet.header();

    let src_port = response_header.dst_port();
    response_header.set_dst_port(response_header.src_port());
    response_header.set_src_port(src_port);

    response_header.set_ack(true);
    response_header.set_ack_number(packet.header().sequence_number() + 1);
    response_header.set_sequence_number(101);

    let checksum = response_packet.calculate_checksum(ip_packet);

    let mut response_header = response_packet.header();
    response_header.set_checksum(checksum);

    ipv4_send(
        ip_packet,
        response_packet.raw(),
        daddr,
        arp_cache,
        IpProtocol::TCP,
        iface,
    )
}

pub fn tcp_incoming(
    ip_packet: IpV4Packet,
    iface: &mut dyn TunInterface,
    arp_cache: &ArpCache,
) -> Result<()> {
    let tcp_packet = TcpPacket(ip_packet.data());
    let tcp_header = tcp_packet.header();

    if tcp_packet.calculate_checksum(&ip_packet) != tcp_header.checksum() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Checksum does not match",
        ));
    }

    if tcp_header.syn() && !tcp_header.ack() {
        return tcp_new_connection(&ip_packet, tcp_packet, iface, arp_cache);
    }

    Ok(())
}
