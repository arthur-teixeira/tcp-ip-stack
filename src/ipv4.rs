use bitfield::bitfield;
use libc::c_void;

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

pub fn calculate_checksum(hdr: &u8, count: i32) -> u16 {
    unsafe {
        checksum(hdr as *const u8 as *const c_void, count)
    }
}
