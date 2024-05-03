use crate::BufWriter;
use crate::BufferView;
use std::fmt::Display;

#[derive(Debug, Clone, PartialEq)]
pub struct Frame<'a> {
    pub dmac: [u8; 6],
    pub smac: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
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
        let p = self.payload;
        write!(f, "{:x?}", p)
    }
}

impl<'a> Frame<'a> {
    pub fn from_buffer(buffer: &'a mut BufferView) -> Self {
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

    pub fn to_buffer(&self) -> Vec<u8> {
        let mut buf = BufWriter::new();
        buf.write_slice(&self.dmac);
        buf.write_slice(&self.smac);
        buf.write_u16(self.ethertype);
        buf.write_slice(self.payload);

        buf.buf
    }
}
