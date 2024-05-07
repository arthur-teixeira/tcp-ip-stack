use std::{
    collections::{hash_map::Entry, HashMap},
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

pub type Connections = HashMap<Quad, Connection>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpPacket(Vec<u8>);

impl TcpPacket {
    pub fn header(&self) -> TcpHeader<&Vec<u8>> {
        TcpHeader(&self.0)
    }

    pub fn mut_header(&mut self) -> TcpHeader<&mut Vec<u8>> {
        TcpHeader(&mut self.0)
    }

    pub fn data(&self) -> &[u8] {
        &self.0[self.header().header_len() as usize..]
    }

    pub fn raw(&self) -> &[u8] {
        &self.0
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

fn tcp_new_connection<'a>(
    ip_packet: IpV4Packet,
    tcp_packet: TcpPacket,
    interface: &mut Interface,
) -> Result<Connection> {
    let tcph = tcp_packet.header();

    let iss = 0;
    let wnd = 1024;
    let mut c = Connection {
        state: ConnState::SynRecvd,
        send: SendSequenceSpace {
            iss,
            una: iss,
            nxt: iss,
            wnd,
            up: false,
            wl1: 0,
            wl2: 0,
        },
        recv: ReceiveSequenceSpace {
            irs: tcph.sequence_number(),
            nxt: tcph.sequence_number() + 1,
            wnd: tcph.window_size(),
            up: false,
        },
        tcp: tcp_packet,
        ip: ip_packet,
    };

    c.tcp.mut_header().set_ack(true);
    c.tcp.mut_header().set_syn(true);

    c.send(interface)?;

    Ok(c)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnState {
    SynRecvd,
    Estabilished,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/*
    [RFC 793, Section 3.2, Figure 4]

          1         2          3          4
     ----------|----------|----------|----------
            SND.UNA    SND.NXT    SND.UNA
                                 +SND.WND

   1 - old sequence numbers which have been acknowledged
   2 - sequence numbers of unacknowledged data
   3 - sequence numbers allowed for new data transmission
   4 - future sequence numbers which are not yet allowed
*/
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SendSequenceSpace {
    // Send unacknowledged
    una: u32,
    // Send next
    nxt: u32,
    // Send window
    wnd: u16,
    // Send urgent pointer
    up: bool,
    // Segment sequence number used for last window update
    wl1: usize,
    // Segment ack number used for last window update
    wl2: usize,
    // Initial Send sequence number
    iss: u32,
}

/*
   [RFC 793, Section 3.2, Figure 5]

                  1           2          3
              ----------|----------|----------
                     RCV.NXT    RCV.NXT
                               +RCV.WND

   1 - old sequence numbers which have been acknowledged
   2 - sequence numbers allowed for new reception
   3 - future sequence numbers which are not yet allowed
*/

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReceiveSequenceSpace {
    // Receive next
    nxt: u32,
    // Receive window
    wnd: u16,
    // Receive urgent pointer
    up: bool,
    // Initial receive sequence number
    irs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Connection {
    ip: IpV4Packet,
    tcp: TcpPacket,
    state: ConnState,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
}

impl Connection {
    fn incoming_packet(
        &mut self,
        ip_packet: &IpV4Packet,
        tcp_packet: &TcpPacket,
        interface: &mut Interface,
    ) -> Result<()> {
        match self.state {
            ConnState::SynRecvd => {
                if tcp_packet.header().ack() {
                    self.state = ConnState::Estabilished;
                    eprintln!("Successfully estabilished connection");
                }
                Ok(())
            }
            _ => {
                eprintln!("Got another packet: {:?}", tcp_packet.header());
                Ok(())
            }
        }
    }

    fn send(&mut self, interface: &mut Interface) -> Result<()> {
        let daddr = Ipv4Addr::from(self.ip.header().src_addr());

        let mut response_buf = Vec::from(self.tcp.raw());
        let mut response_packet = WritableTcpPacket(&mut response_buf);
        let mut response_header = response_packet.header();

        let src_port = response_header.dst_port();
        response_header.set_dst_port(response_header.src_port());
        response_header.set_src_port(src_port);

        response_header.set_ack_number(self.recv.nxt);
        response_header.set_sequence_number(self.send.nxt);

        let checksum = response_packet.calculate_checksum(&self.ip);

        let mut response_header = response_packet.header();
        response_header.set_checksum(checksum);

        ipv4_send(
            &self.ip,
            response_packet.raw(),
            daddr,
            IpProtocol::TCP,
            interface,
        )
    }
}

pub fn tcp_incoming(
    ip_packet: IpV4Packet,
    interface: &mut Interface,
    tcp_connections: &mut Connections,
) -> Result<()> {
    let tcp_packet = TcpPacket(ip_packet.data().into());
    let tcp_header = tcp_packet.header();

    if tcp_packet.calculate_checksum(&ip_packet) != tcp_header.checksum() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Checksum does not match",
        ));
    }

    let quad = Quad {
        src: (ip_packet.header().src_addr().into(), tcp_header.src_port()),
        dst: (ip_packet.header().dst_addr().into(), tcp_header.dst_port()),
    };

    match tcp_connections.entry(quad) {
        Entry::Occupied(mut c) => c
            .get_mut()
            .incoming_packet(&ip_packet, &tcp_packet, interface),
        Entry::Vacant(e) => {
            e.insert(tcp_new_connection(ip_packet, tcp_packet, interface)?);
            Ok(())
        }
    }
}
