use std::{
    collections::HashMap,
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
};

use crate::{ipv4_send, utils, Interface, IpProtocol, IpV4Packet};

use bitfield::bitfield;

bitfield! {
    pub struct TcpHeader (MSB0 [u8]);
    impl Debug;
    impl PartialEq;
    impl Copy;
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

pub type Connections<'a> = HashMap<Quad, Connection<'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpPacket<'a>(&'a [u8]);

impl TcpPacket<'_> {
    pub fn header(&self) -> TcpHeader<&[u8]> {
        TcpHeader(self.0)
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
    interface: &mut Interface,
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
        IpProtocol::TCP,
        interface,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Quad {
    src: (Ipv4Addr, u32),
    dst: (Ipv4Addr, u32),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnState {
    Listen,
    SynSent,
    SynRecvd,
    Estabilished,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Connection<'a> {
    ip: IpV4Packet<'a>,
    tcp: TcpPacket<'a>,
    state: ConnState,
    seq_number: u32,
    ack_number: u32,
}

pub fn tcp_incoming(ip_packet: IpV4Packet, interface: &mut Interface) -> Result<()> {
    let tcp_packet = TcpPacket(ip_packet.data());
    let tcp_header = tcp_packet.header();

    if tcp_packet.calculate_checksum(&ip_packet) != tcp_header.checksum() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Checksum does not match",
        ));
    }

    if tcp_header.syn() && !tcp_header.ack() {
        return tcp_new_connection(&ip_packet, tcp_packet, interface);
    }

    Ok(())
}
