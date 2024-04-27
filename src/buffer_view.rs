use std::io::Result;

use crate::arp::TunInterface;

pub struct BufferView {
    pub buf: Box<[u8]>,
    pub size: usize,
    pub pos: usize,
}

impl BufferView {
    pub fn read_u8(&mut self) -> u8 {
        let val = self.buf[self.pos];
        self.pos += 1;

        val
    }

    pub fn read_u16(&mut self) -> u16 {
        (self.read_u8() as u16) << 8 | (self.read_u8() as u16)
    }

    pub fn read_u32(&mut self) -> u32 {
        (self.read_u16() as u32) << 16 | (self.read_u16() as u32)
    }

    pub fn read_slice(&mut self, size: usize) -> &[u8] {
        let val = &self.buf[self.pos..self.pos + size];
        self.pos += size;
        val
    }

    pub fn from_iface(f: &mut dyn TunInterface) -> Result<Self> {
        let mut buffer = [0; 1500];
        let nb = f.rcv(&mut buffer)?;
        Ok(Self {
            buf: Box::new(buffer),
            size: nb,
            pos: 0,
        })
    }

    pub fn from_slice(s: &[u8]) -> Result<Self> {
        Ok(Self {
            buf: s.into(),
            size: s.len(),
            pos: 0,
        })
    }
}
