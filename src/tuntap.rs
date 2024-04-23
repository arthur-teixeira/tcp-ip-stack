use std::ffi::CString;
use std::fs::File;
use std::io::{Error, Result};
use std::os::fd::FromRawFd;

use ifstructs::ifreq;
use libc::{c_short, c_ulong, c_void, close, ioctl, open, system, IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, O_RDWR};

static TAP_ADDR: &str = "10.0.0.5";
static TAP_ROUTE: &str = "10.0.0.0/24";


pub fn tun_init(name: &str) -> Result<File> {
    let dev = tun_alloc(name)?;

    set_if_up(name)?;
    set_if_route(name, TAP_ROUTE)?;
    set_if_addr(name, TAP_ADDR)?;

    Ok(dev)
}

const TUNSETIFF: c_ulong = 1074025674;
fn tun_alloc(name: &str) -> Result<File> {
    unsafe {
        let fd = open("/dev/net/tap\0".as_ptr() as *const i8, O_RDWR);
        if fd < 0 {
            return Err(Error::from_raw_os_error(-fd));
        }

        let mut ifreq = ifreq::from_name(name).unwrap();
        ifreq.set_flags(IFF_TAP as c_short | IFF_NO_PI as c_short | IFF_VNET_HDR as c_short);

        let err = ioctl(fd, TUNSETIFF, &ifreq as *const ifreq as *const c_void);
        if err < 0 {
            close(fd);
            return Err(Error::from_raw_os_error(-err));
        }

        Ok(File::from_raw_fd(fd))
    }
}

fn set_if_up(dev: &str) -> Result<()> {
    let cmd = format!("ip link set dev {dev} up");
    run_cmd(&cmd)
}

fn set_if_addr(dev: &str, cidr: &str) -> Result<()> {
    let cmd = format!("ip address add dev {dev} local {cidr}");
    run_cmd(&cmd)
}

fn set_if_route(dev: &str, cidr: &str) -> Result<()> {
    let cmd = format!("ip route add dev {dev} {cidr}");
    run_cmd(&cmd)
}

fn run_cmd(cmd: &str) -> Result<()> {
    unsafe {
        let c_str = CString::new(cmd).unwrap();

        if system(c_str.as_ptr()) < 0 {
            return Err(Error::last_os_error());
        };

        Ok(())
    }
}
