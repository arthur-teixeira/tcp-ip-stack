use arp::ArpCache;
use libc::c_int;
use std::fmt::Display;
use std::io::Result;
use tun_tap::{Iface, Mode};

use crate::arp::{arp_recv, ArpHeader};
mod arp;

struct BufferView {
    buf: Box<[u8]>,
    size: usize,
    pos: usize,
}

impl BufferView {
    fn read_u8(&mut self) -> u8 {
        let val = self.buf[self.pos];
        self.pos += 1;

        val
    }

    fn read_u16(&mut self) -> u16 {
        (self.read_u8() as u16) << 8 | (self.read_u8() as u16)
    }

    fn read_u32(&mut self) -> u32 {
        (self.read_u16() as u32) << 16 | (self.read_u16() as u32)
    }

    fn read_slice(&mut self, size: usize) -> &[u8] {
        let val = &self.buf[self.pos..self.pos + size];
        self.pos += size;
        val
    }

    fn from_iface(f: &mut Iface) -> Result<Self> {
        let mut buffer = [0; 1500];
        let nb = f.recv(&mut buffer)?;
        Ok(Self {
            buf: Box::new(buffer),
            size: nb,
            pos: 0,
        })
    }

    fn from_slice(s: &[u8], size: usize) -> Result<Self> {
        Ok(Self {
            buf: s.into(),
            size,
            pos: 0,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Frame<'a> {
    dmac: [u8; 6],
    smac: [u8; 6],
    ethertype: u16,
    payload: &'a [u8],
}

impl Display for Frame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dmac = format!(
            "{:#2x}:{:#2x}:{:#2x}:{:#2x}:{:#2x}:{:#2x}",
            self.dmac[0], self.dmac[1], self.dmac[2], self.dmac[3], self.dmac[4], self.dmac[5]
        );
        let smac = format!(
            "{:#2x}:{:#2x}:{:#2x}:{:#2x}:{:#2x}:{:#2x}",
            self.smac[0], self.smac[1], self.smac[2], self.smac[3], self.smac[4], self.smac[5]
        );

        let t = self.ethertype;
        let ethertype = format!("{:#4x}", t);

        write!(
            f,
            "dmac: ({dmac}), smac: ({smac}), ethertype: ({ethertype})"
        )?;

        write!(f, "{:x?}", self.payload)
    }
}

impl<'a> Frame<'a> {
    fn from_buffer(buffer: &'a mut BufferView) -> Self {
        let mut dmac = [0; 6];
        dmac.copy_from_slice(buffer.read_slice(6));

        let mut smac = [0; 6];
        smac.copy_from_slice(buffer.read_slice(6));

        Self {
            dmac,
            smac,
            ethertype: buffer.read_u16(),
            payload: buffer.read_slice(buffer.size - buffer.pos),
        }
    }
}

fn main() -> Result<()> {
    let mut iface = Iface::without_packet_info("tap1", Mode::Tap)?;
    let mut arp_cache = ArpCache::new();

    loop {
        let mut sock_buff = BufferView::from_iface(&mut iface)?;
        let frame = Frame::from_buffer(&mut sock_buff);

        match frame.ethertype as c_int {
            libc::ETH_P_ARP => {
                eprintln!("Receiving ARP packet");
                let packet = ArpHeader::from_bytes(frame.payload, frame.payload.len())?;
                arp_recv(&packet, &mut arp_cache)?;
            },
            libc::ETH_P_IP => eprintln!("Receiving IP packet"),
            libc::ETH_P_IPV6 => eprintln!("Receiving IPv6 packet"),
            _ => {
                // println!("Unknown protocol");
                continue;
            }
        }
        eprintln!("Payload: {:x?}", &frame.payload[..]);
    }
}
