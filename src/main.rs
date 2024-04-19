use std::io::{Read, Result, Error};
use std::os::fd::FromRawFd;
use std::fs::File;

use ifstructs::ifreq;
use libc::{c_short, c_ulong, c_void, close, ioctl, open, IFF_NO_PI, IFF_TAP, O_RDWR};

#[repr(C, packed)]
struct EthHeader {
    dmac: [u8; 6],
    smac: [u8; 6],
    ethertype: u16,
    payload: [u8],
}

fn main() -> Result<()> {
    let mut file = tun_alloc("tap0")?;

    loop {
        let mut buffer = [0; 4096];
        let nb = file.read(&mut buffer)?;
        eprintln!("Read {nb} bytes: {buf:?}", buf = &buffer[..nb]);
    }
}

const TUNSETIFF: c_ulong = 1074025674;
fn tun_alloc(name: &str) -> Result<File> {
    unsafe {
        let fd = open("/dev/net/tap\0".as_ptr() as *const i8, O_RDWR);
        if fd < 0 {
            return Err(Error::from_raw_os_error(-fd));
        }

        let mut ifreq = ifreq::from_name(name).unwrap();
        ifreq.set_flags(IFF_TAP as c_short | IFF_NO_PI as c_short);

        let err = ioctl(fd, TUNSETIFF, &ifreq as *const ifreq as *const c_void);
        if err < 0 {
            close(fd);
            return Err(Error::from_raw_os_error(-err));
        }

        Ok(File::from_raw_fd(fd))
    }
}
