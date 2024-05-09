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
pub struct TcpPacket(pub Vec<u8>);

impl TcpPacket {
    pub const TCP_HEADER_SIZE: usize = 20;

    pub fn header(&self) -> TcpHeader<&Vec<u8>> {
        TcpHeader(&self.0)
    }

    pub fn mut_header(&mut self) -> TcpHeader<&mut Vec<u8>> {
        TcpHeader(&mut self.0)
    }

    pub fn raw(&self) -> &[u8] {
        &self.0
    }

    pub fn mut_raw(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn calculate_checksum(&self, packet: &IpV4Packet) -> u16 {
        let src_ip = &packet.header().src_addr().into();
        let dst_ip = &packet.header().dst_addr().into();

        utils::ipv4_checksum(&self.0, 8, src_ip, dst_ip, IpProtocol::TCP as u8)
    }

    // Rfc 793, Page 18
    pub fn maximum_segment_size(&self) -> Option<u16> {
        let option_section = &self.0[Self::TCP_HEADER_SIZE..];

        let mut state = 0;

        let mut bs = [0; 2];

        for byte in option_section {
            match state {
                // Looking for beggining of MSS section
                0 => match byte {
                    0 => return None, // End of Option list
                    1 => continue,    // No-Op
                    2 => state = 1,   // Beggining of MSS section
                    _ => unreachable!(),
                },

                // Looking for length of MSS section
                1 => match byte {
                    4 => state = 2, // Length of MSS section
                    _ => return None,
                },

                // Looking for first MSS byte
                2 => {
                    bs[0] = *byte;
                    state = 3;
                }
                // Looking for second MSS byte
                3 => {
                    bs[1] = *byte;
                    return Some(u16::from_be_bytes(bs));
                }
                _ => unreachable!(),
            }
        }

        None
    }

    pub fn data(&self) -> &[u8] {
        let option_section = &self.0[Self::TCP_HEADER_SIZE..];
        let mut end_of_option_section: isize = -1;

        for (idx, byte) in option_section.iter().enumerate() {
            match byte {
                0 => {
                    end_of_option_section = idx as isize;
                    break;
                }
                _ => continue,
            }
        }

        if end_of_option_section >= 0 {
            &option_section[end_of_option_section as usize + 1..]
        } else {
            option_section
        }
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
) -> Result<Option<Connection>> {
    let tcph = tcp_packet.header();

    if tcph.rst() {
        /*
        RFC793, "Segment Arrives"
        If the state is LISTEN then
        first check for an RST
        An incoming RST should be ignored.  Return.
        */
        return Ok(None);
    }

    if tcph.ack() {
        // TODO: Return an RST segment
        return Ok(None);
    }

    if !tcph.syn() {
        return Ok(None);
    }

    let iss = 0;
    let wnd = 1024;
    let mut c = Connection {
        state: ConnState::SynRecvd,
        send: SendSequenceSpace {
            iss,
            una: iss,
            nxt: iss + 1,
            wnd,
            up: false,
            wl1: 0,
            wl2: 0,
        },
        recv: ReceiveSequenceSpace {
            irs: tcph.sequence_number(),
            nxt: tcph.sequence_number().wrapping_add(1),
            wnd: tcph.window_size(),
            up: false,
        },
        tcp: tcp_packet,
        ip: ip_packet,
    };

    c.tcp.mut_header().set_ack(true);
    c.tcp.mut_header().set_syn(true);

    c.send(interface)?;
    c.send.nxt = c.send.nxt.wrapping_add(0);
    c.tcp.mut_header().set_syn(false);
    c.tcp.mut_header().set_rst(false);

    Ok(Some(c))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnState {
    Closed,
    Listen,
    SynRecvd,
    Estabilished,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl ConnState {
    fn should_keep(&self) -> bool {
        match self {
            Self::Closed | Self::Listen => false,
            _ => true,
        }
    }
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
    // RFC 793, Section 3.3
    fn check_sequence_number(&self, tcp_packet: &TcpPacket) -> bool {
        let hdr = tcp_packet.header();
        let seq = hdr.sequence_number();

        let mut seg_len = tcp_packet.data().len() as u32;
        seg_len += hdr.syn() as u32;
        seg_len += hdr.fin() as u32;

        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        if seg_len == 0 {
            if self.recv.wnd == 0 {
                return self.recv.nxt == seq;
            }

            return is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq, wend);
        }

        if self.recv.wnd == 0 {
            return false;
        }

        is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq, wend)
            && is_between_wrapped(
                self.recv.nxt.wrapping_sub(1),
                seq.wrapping_add(seg_len - 1),
                wend,
            )
    }

    fn incoming_packet(
        &mut self,
        ip_packet: &IpV4Packet,
        tcp_packet: &TcpPacket,
        interface: &mut Interface,
    ) -> Result<()> {
        let tcph = tcp_packet.header();
        eprintln!("HEADER: {:?}", tcph);
        // RFC 793, "Segment Arrives", Otherwise section

        // First, Check sequence number
        if !self.check_sequence_number(&tcp_packet) {
            eprintln!("Received Invalid segment");
            if !tcph.rst() {
                self.tcp.mut_header().set_ack(true);
                self.send(interface)?;
            }
            return Ok(());
        }

        // Second, check RST bit
        if tcph.rst() {
            match self.state {
                ConnState::SynRecvd => {
                    self.state = ConnState::Listen;
                    eprintln!("Received RST, returning to listen state");
                }
                ConnState::Estabilished
                | ConnState::FinWait1
                | ConnState::FinWait2
                | ConnState::CloseWait => {
                    // If the RST bit is set then, any outstanding RECEIVEs and SEND
                    // should receive "reset" responses.  All segment queues should be
                    // flushed.  Users should also receive an unsolicited general
                    // "connection reset" signal.  Enter the CLOSED state, delete the
                    // TCB, and return.
                    self.state = ConnState::Closed;
                    eprintln!("Received RST, closing connection");
                }
                ConnState::Closing | ConnState::LastAck | ConnState::TimeWait => {
                    // If the RST bit is set then, enter the CLOSED state, delete the
                    // TCB, and return.

                    self.state = ConnState::Closed;
                    eprintln!("Closing connection");
                }
                ConnState::Closed | ConnState::Listen => unreachable!(),
            }

            return Ok(());
        }

        // TODO: Third, check security and precedence

        // Fourth, Check the SYN bit
        if tcph.syn() {
            match self.state {
                ConnState::SynRecvd
                | ConnState::Estabilished
                | ConnState::FinWait1
                | ConnState::FinWait2
                | ConnState::CloseWait
                | ConnState::Closing
                | ConnState::LastAck
                | ConnState::TimeWait => {
                    // If the SYN is in the window it is an error, send a reset, any
                    // outstanding RECEIVEs and SEND should receive "reset" responses,
                    // all segment queues should be flushed, the user should also
                    // receive an unsolicited general "connection reset" signal, enter
                    // the CLOSED state, delete the TCB, and return.
                    self.send_rst(0, interface)?;
                    self.state = ConnState::Closed;
                }
                ConnState::Closed | ConnState::Listen => unreachable!(),
            }

            return Ok(());
        }

        // Fifth, check the ACK bit
        if !tcph.ack() {
            return Ok(());
        }

        match self.state {
            ConnState::SynRecvd => {
                // TODO: fix this
                eprintln!("SND.UNA: {}, SEG.ACK: {}, SND.NXT: {}", self.send.una, tcph.ack_number(), self.send.nxt);
                if is_between_wrapped(
                    self.send.una.wrapping_sub(1),
                    tcph.ack_number(),
                    self.send.nxt.wrapping_add(1),
                ) {
                    self.state = ConnState::Estabilished;
                    eprintln!("Successfully estabilished connection");
                } else {
                    eprintln!("Segment is not acceptable, sending RST");
                    self.send_rst(tcph.ack_number(), interface)?;
                }

                Ok(())
            }
            ConnState::Estabilished | ConnState::CloseWait => {
                // If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be ignored.
                if wrapping_lt(tcph.ack_number(), self.send.una) {
                    return Ok(());
                }
                if wrapping_lt(self.send.nxt, tcph.ack_number()) {
                    // If the ACK acks something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
                    // drop the segment, and return.
                    self.tcp.mut_header().set_ack(true);
                    return self.send(interface);
                }
                // If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
                // Any segments on the retransmission queue which are thereby
                // entirely acknowledged are removed.  Users should receive
                // positive acknowledgments for buffers which have been SENT and
                // fully acknowledged (i.e., SEND buffer should be returned with
                // "ok" response).
                if is_between_wrapped(
                    self.send.una,
                    tcph.ack_number(),
                    self.send.nxt.wrapping_add(1),
                ) {
                    self.send.una = tcph.ack_number();
                    self.update_window(&tcph);
                }

                Ok(())
            }
            ConnState::FinWait1 => {
                // TODO:
                // In addition to the processing for the ESTABLISHED state, if
                // our FIN is now acknowledged then enter FIN-WAIT-2 and continue
                // processing in that state.
                Ok(())
            }
            ConnState::FinWait2 => {
                // TODO:
                // In addition to the processing for the ESTABLISHED state, if
                // the retransmission queue is empty, the user's CLOSE can be
                // acknowledged ("ok") but do not delete the TCB.
                Ok(())
            }
            ConnState::Closing => {
                // TODO:
                // In addition to the processing for the ESTABLISHED state, if
                // the ACK acknowledges our FIN then enter the TIME-WAIT state,
                // otherwise ignore the segment.
                Ok(())
            }
            ConnState::LastAck => {
                // TODO:
                // The only thing that can arrive in this state is an
                // acknowledgment of our FIN.  If our FIN is now acknowledged,
                // delete the TCB, enter the CLOSED state, and return.
                Ok(())
            }

            ConnState::TimeWait => {
                // TODO:
                // The only thing that can arrive in this state is a
                // retransmission of the remote FIN.  Acknowledge it, and restart
                // the 2 MSL timeout.
                Ok(())
            }
            _ => {
                eprintln!("Got another packet: {:?}", tcp_packet.header());
                Ok(())
            }
        }
    }

    fn update_window(&mut self, tcph: &TcpHeader<&Vec<u8>>) {
        // If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
        // updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
        // SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
        // SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
        if wrapping_lt(self.send.wl1 as u32, tcph.sequence_number())
            || (self.send.wl1 as u32 == tcph.sequence_number()
                && self.send.wl2 as u32 <= tcph.ack_number())
        {
            self.send.wnd = tcph.window_size();
            self.send.wl1 = tcph.sequence_number() as usize;
            self.send.wl2 = tcph.ack_number() as usize;
        }
    }

    fn send_rst(&mut self, seq: u32, interface: &mut Interface) -> Result<()> {
        self.tcp.mut_header().set_rst(true);
        self.tcp.mut_header().set_sequence_number(seq);
        self.tcp.mut_header().set_ack_number(0);
        self.send(interface)
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
        Entry::Occupied(mut c) => {
            c.get_mut()
                .incoming_packet(&ip_packet, &tcp_packet, interface)?
        }
        Entry::Vacant(e) => {
            if let Some(c) = tcp_new_connection(ip_packet, tcp_packet, interface)? {
                e.insert(c);
            }
        }
    }

    tcp_connections.retain(|_, v| v.state.should_keep());

    Ok(())
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

#[cfg(test)]
mod tcp_test {
    use super::tcp_new_connection;
    use crate::{
        arp::{ArpCache, ArpIpv4},
        tcp::{ConnState, ReceiveSequenceSpace, SendSequenceSpace, TcpPacket},
        test_utils::{Ipv4PacketBuilder, MockTun, TcpPacketBuilder},
        Interface,
    };
    use std::net::Ipv4Addr;

    #[test]
    fn test_new_connection() {
        let iface = MockTun::new("/tmp/mock_tun");

        let mut interface = Interface {
            iface: Box::new(iface),
            arp_cache: ArpCache::default(),
        };

        let ip_packet = Ipv4PacketBuilder::new()
            .set_src_addr(Ipv4Addr::new(192, 168, 0, 1))
            .set_dst_addr(Ipv4Addr::new(10, 0, 0, 7))
            .build();

        let cache_key = format!("{}-{}", 1, Ipv4Addr::from(ip_packet.header().src_addr()));

        interface.arp_cache.insert(
            cache_key,
            ArpIpv4 {
                smac: [1, 2, 3, 4, 5, 6],
                sip: ip_packet.header().src_addr().into(),
                dip: ip_packet.header().dst_addr().into(),
                dmac: [7, 8, 9, 10, 11, 12],
            },
        );

        let tcp_packet = TcpPacketBuilder::new()
            .set_src_port(789)
            .set_dst_port(678)
            .set_rst(false)
            .set_ack(false)
            .set_syn(true)
            .set_sequence_number(10)
            .set_window_size(2)
            .set_checksum(&ip_packet)
            .build();

        let conn = tcp_new_connection(ip_packet, tcp_packet.clone(), &mut interface)
            .expect("Expected Ok")
            .expect("Expected connection to be created");

        assert_eq!(conn.state, ConnState::SynRecvd);
        assert_eq!(
            conn.recv,
            ReceiveSequenceSpace {
                irs: 10,
                nxt: 11,
                wnd: 2,
                up: false,
            }
        );
        assert_eq!(
            conn.send,
            SendSequenceSpace {
                iss: 0,
                una: 0,
                nxt: 0,
                wnd: 1024,
                up: false,
                wl1: 0,
                wl2: 0,
            }
        );

        let mut packet_sent = [0; 1500];
        let _ = interface
            .iface
            .rcv(&mut packet_sent)
            .expect("Expected packet to be sent");

        let tcp = TcpPacket(packet_sent[34..].to_vec());
        let tcph = tcp.header();

        assert!(tcph.syn());
        assert!(tcph.ack());
    }

    #[test]
    fn test_new_connection_with_rst() {
        let iface = MockTun::new("/tmp/mock_tun");

        let mut interface = Interface {
            iface: Box::new(iface),
            arp_cache: ArpCache::default(),
        };

        let ip_packet = Ipv4PacketBuilder::new()
            .set_src_addr(Ipv4Addr::new(192, 168, 0, 1))
            .set_dst_addr(Ipv4Addr::new(10, 0, 0, 7))
            .build();

        let tcp_packet = TcpPacketBuilder::new()
            .set_src_port(789)
            .set_dst_port(678)
            .set_rst(true)
            .set_ack(false)
            .set_syn(true)
            .set_sequence_number(10)
            .set_window_size(2)
            .set_checksum(&ip_packet)
            .build();

        let conn =
            tcp_new_connection(ip_packet, tcp_packet, &mut interface).expect("Expected no errors");
        assert_eq!(conn, None);
    }

    #[test]
    fn test_new_connection_without_syn() {
        let iface = MockTun::new("/tmp/mock_tun");

        let mut interface = Interface {
            iface: Box::new(iface),
            arp_cache: ArpCache::default(),
        };

        let ip_packet = Ipv4PacketBuilder::new()
            .set_src_addr(Ipv4Addr::new(192, 168, 0, 1))
            .set_dst_addr(Ipv4Addr::new(10, 0, 0, 7))
            .build();

        let tcp_packet = TcpPacketBuilder::new()
            .set_src_port(789)
            .set_dst_port(678)
            .set_rst(false)
            .set_ack(false)
            .set_syn(false)
            .set_sequence_number(10)
            .set_window_size(2)
            .set_checksum(&ip_packet)
            .build();

        let conn =
            tcp_new_connection(ip_packet, tcp_packet, &mut interface).expect("Expected no errors");
        assert_eq!(conn, None);
    }
}
