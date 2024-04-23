use std::fs::File;
use std::io::{Read, Result};
use libc::c_int;


mod tuntap;

struct SocketBuffer {
    buf: [u8; 4096],
    size: usize,
    pos: usize,
}

impl SocketBuffer {
    fn read_u8(&mut self) -> u8 {
        let val = self.buf[self.pos];
        self.pos += 1;

        val
    }

    fn read_u16(&mut self) -> u16 {
        (self.read_u8() as u16) << 8 | (self.read_u8() as u16)
    }

    fn read_slice(&mut self, size: usize) -> &[u8] {
        let val = &self.buf[self.pos..self.pos + size];
        self.pos += size;
        val
    }

    fn from_file(f: &mut File) -> Result<Self> {
        let mut buffer = [0; 4096];
        let nb = f.read(&mut buffer)?;
        Ok(Self {
            buf: buffer,
            size: nb,
            pos: 0,
        })
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, PartialEq)]
struct Frame<'a> {
    dmac: [u8; 6],
    smac: [u8; 6],
    ethertype: u16,
    payload: &'a [u8],
}

impl<'a> Frame<'a> {
    fn from_buffer(buffer: &'a mut SocketBuffer) -> Self {
        let mut dmac = [0; 6];
        dmac.copy_from_slice(buffer.read_slice(6));

        let mut smac = [0; 6];
        smac.copy_from_slice(buffer.read_slice(6));

        Self {
            dmac,
            smac,
            ethertype: u16::from_be(buffer.read_u16()),
            payload: buffer.read_slice(buffer.size - buffer.pos),
        }
    }
}

fn main() -> Result<()> {
    let mut file = tuntap::tun_init("tap0")?;

    loop {
        let mut sock_buff = SocketBuffer::from_file(&mut file)?;
        let frame = Frame::from_buffer(&mut sock_buff);

        match frame.ethertype as c_int {
            libc::ETH_P_ARP | libc::ETH_P_IP | libc::ETH_P_IPV6 => {
                println!("Protocol is known");
            }
            _ => {
                println!("Unknown protocol");
            }
        }
        eprintln!("Frame: {frame:?}");
    }
}

