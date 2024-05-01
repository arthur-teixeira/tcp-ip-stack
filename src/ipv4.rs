use bitfield::bitfield;
use libc::c_void;
use std::io::{Error, ErrorKind, Result};

extern "C" {
    fn checksum(addr: *const c_void, count: i32) -> u16;
}

bitfield! {
    pub struct IpV4Header (MSB0 [u8]);
    impl Debug;
    impl PartialEq;
    impl Eq;
    pub u8, version, set_version: 3, 0;
    pub u8, ihl, set_ihl: 7, 4;
    pub u8, tos, set_tos: 15, 8;
    pub u16, len, set_len: 31, 16;
    pub u16, id, set_id: 47, 32;
    pub u8, df, set_df: 49;
    pub u8, mf, set_mf: 50;
    pub u16, frag_offset, set_frag_offset: 63, 51;
    pub u8, ttl, set_ttl: 71, 64;
    pub u8, proto, set_proto: 79, 72;
    pub u16, checksum, set_checksum: 95, 80;
    pub u32, src_addr, set_src_addr: 127, 96;
    pub u32, dst_addr, set_dst_addr: 159, 128;
}

pub fn calculate_checksum(data: &[u8], skipword: usize) -> u16 {
    if data.len() == 0 {
        return 0;
    }

    let len = data.len();
    let mut cur_data = &data[..];
    let mut sum = 0u32;
    let mut i = 0;

    while cur_data.len() >= 2 {
        if i != skipword {
            sum += u16::from_be_bytes(cur_data[0..2].try_into().unwrap()) as u32;
        }
        cur_data = &cur_data[2..];
        i += 1;
    }

    if i != skipword && len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

pub fn ipv4_recv(frame_data: &[u8]) -> Result<()> {
    let hdr = IpV4Header(frame_data);
    if hdr.version() != 4 {
        return Err(Error::new(ErrorKind::Unsupported, "Ip version is not 4"));
    }

    if hdr.ihl() < 5 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Packet length must be at least 5",
        ));
    }

    if hdr.ttl() == 0 {
        return Err(Error::new(ErrorKind::InvalidData, "Datagram ttl reached 0"));
    }

    let header_length = hdr.ihl() as usize * 4;

    let csum = calculate_checksum(&frame_data[..header_length], 5);
    if csum != hdr.checksum() {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid checksum"));
    }

    Ok(())
}
