pub struct BufWriter {
    pub buf: Vec<u8>,
    pub pos: usize,
}

impl BufWriter {
    pub fn new() -> Self {
        BufWriter {
            buf: vec![],
            pos: 0,
        }
    }

    pub fn write_u8(&mut self, val: u8) {
        self.buf.push(val);
        self.pos += 1;
    }

    pub fn write_u16(&mut self, val: u16) {
        self.write_u8((val >> 8) as u8);
        self.write_u8((val & 0xFF) as u8);
    }

    pub fn write_u32(&mut self, val: u32) {
        self.write_u16((val >> 16) as u16);
        self.write_u16((val & 0xFFFF) as u16);
    }

    pub fn write_slice(&mut self, val: &[u8]) {
        self.buf.extend(val);
    }
}
