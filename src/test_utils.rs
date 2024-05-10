#![cfg(test)]
#![allow(dead_code)]

use std::{
    fs::{self, File, OpenOptions},
    io::{Result, Write},
    net::Ipv4Addr,
    os::unix::fs::FileExt,
};

use crate::{arp::TunInterface, ipv4::IpV4Packet, tcp::TcpPacket, utils, WritableIpV4Packet};

pub struct TcpPacketBuilder {
    packet: TcpPacket,
}

impl TcpPacketBuilder {
    pub fn new() -> Self {
        Self {
            packet: TcpPacket(vec![0; 1500]),
        }
    }

    pub fn set_src_port(mut self, port: u16) -> Self {
        self.packet.mut_header().set_src_port(port);
        self
    }

    pub fn set_dst_port(mut self, port: u16) -> Self {
        self.packet.mut_header().set_dst_port(port);
        self
    }

    pub fn set_sequence_number(mut self, num: u32) -> Self {
        self.packet.mut_header().set_sequence_number(num);
        self
    }

    pub fn set_ack_number(mut self, ack_number: u32) -> Self {
        self.packet.mut_header().set_ack_number(ack_number);
        self
    }

    pub fn set_header_len(mut self, header_len: u16) -> Self {
        self.packet.mut_header().set_header_len(header_len);
        self
    }

    pub fn set_rsvd(mut self, rsvd: u16) -> Self {
        self.packet.mut_header().set_rsvd(rsvd);
        self
    }

    pub fn set_cwr(mut self, cwr: bool) -> Self {
        self.packet.mut_header().set_cwr(cwr);
        self
    }

    pub fn set_ece(mut self, ece: bool) -> Self {
        self.packet.mut_header().set_ece(ece);
        self
    }

    pub fn set_urg(mut self, urg: bool) -> Self {
        self.packet.mut_header().set_urg(urg);
        self
    }

    pub fn set_ack(mut self, ack: bool) -> Self {
        self.packet.mut_header().set_ack(ack);
        self
    }

    pub fn set_psh(mut self, psh: bool) -> Self {
        self.packet.mut_header().set_psh(psh);
        self
    }

    pub fn set_rst(mut self, rst: bool) -> Self {
        self.packet.mut_header().set_rst(rst);
        self
    }

    pub fn set_syn(mut self, syn: bool) -> Self {
        self.packet.mut_header().set_syn(syn);
        self
    }

    pub fn set_fin(mut self, fin: bool) -> Self {
        self.packet.mut_header().set_fin(fin);
        self
    }

    pub fn set_window_size(mut self, window_size: u16) -> Self {
        self.packet.mut_header().set_window_size(window_size);
        self
    }

    pub fn set_checksum(mut self, ip_packet: &IpV4Packet) -> Self {
        let checksum = self.packet.calculate_checksum(&ip_packet);
        self.packet.mut_header().set_checksum(checksum);
        self
    }

    pub fn set_urgent_ptr(mut self, urgent_ptr: u16) -> Self {
        self.packet.mut_header().set_urgent_ptr(urgent_ptr);
        self
    }

    pub fn set_data(mut self, data: &[u8]) -> Self {
        self.packet.mut_raw()[TcpPacket::TCP_HEADER_SIZE..].copy_from_slice(data);
        self
    }

    pub fn build(self) -> TcpPacket {
        self.packet
    }
}

pub struct MockTun {
    pub file: File,
    pub path: &'static str,
}

impl MockTun {
    pub fn new(path: &'static str) -> Self {
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

#[derive(Clone)]
pub struct Ipv4PacketBuilder {
    packet: IpV4Packet,
}

impl Ipv4PacketBuilder {
    pub fn new() -> Self {
        Self {
            packet: IpV4Packet(vec![0; 1500]),
        }
    }

    pub fn set_version(mut self, p: u8) -> Self {
        self.packet.mut_header().set_version(p);
        self
    }
    pub fn set_ihl(mut self, p: u8) -> Self {
        self.packet.mut_header().set_ihl(p);
        self
    }
    pub fn set_tos(mut self, p: u8) -> Self {
        self.packet.mut_header().set_tos(p);
        self
    }
    pub fn set_len(mut self, p: u16) -> Self {
        self.packet.mut_header().set_len(p);
        self
    }
    pub fn set_id(mut self, p: u16) -> Self {
        self.packet.mut_header().set_id(p);
        self
    }
    pub fn set_df(mut self, p: bool) -> Self {
        self.packet.mut_header().set_df(p);
        self
    }
    pub fn set_mf(mut self, p: bool) -> Self {
        self.packet.mut_header().set_mf(p);
        self
    }
    pub fn set_frag_offset(mut self, p: u16) -> Self {
        self.packet.mut_header().set_frag_offset(p);
        self
    }
    pub fn set_ttl(mut self, p: u8) -> Self {
        self.packet.mut_header().set_ttl(p);
        self
    }
    pub fn set_proto(mut self, p: u8) -> Self {
        self.packet.mut_header().set_proto(p);
        self
    }
    pub fn set_checksum(mut self, p: u16) -> Self {
        self.packet.mut_header().set_checksum(p);
        self
    }
    pub fn set_src_addr(mut self, p: Ipv4Addr) -> Self {
        self.packet.mut_header().set_src_addr(p.into());
        self
    }
    pub fn set_dst_addr(mut self, p: Ipv4Addr) -> Self {
        self.packet.mut_header().set_dst_addr(p.into());
        self
    }

    pub fn build(self) -> IpV4Packet {
        let csum = utils::calculate_checksum(self.packet.data(), 5);
        self.set_checksum(csum).packet
    }
}
