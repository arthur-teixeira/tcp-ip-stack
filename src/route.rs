use std::net::Ipv4Addr;

use crate::arp::{IP_ADDR, MAC_OCTETS};

#[derive(Copy, Clone)]
pub struct Netdev {
    pub addr: Ipv4Addr,
    pub addr_len: u8,
    pub hwaddr: [u8; 6],
    pub mtu: u32,
}

pub struct Route {
    pub dst: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub netmask: u32,
    pub is_default_gateway: bool,
    pub metrics: u32,
    pub netdev: Netdev,
}

pub struct RouteTable([Route; 3]);
impl RouteTable {
    pub fn lookup(&'static self, addr: Ipv4Addr) -> &'static Route {
        self.0
            .iter()
            .find(|rt| {
                let addr: u32 = addr.into();
                let daddr: u32 = rt.dst.into();
                addr & rt.netmask == daddr & rt.netmask
            })
            .or(self.0.last()) // Defaults to default gateway
            .expect("Should only be called on ROUTES static table")
    }
}

pub const ROUTES: RouteTable = RouteTable([
    Route {
        dst: Ipv4Addr::new(127, 0, 0, 1),
        gateway: Ipv4Addr::new(0, 0, 0, 0),
        netmask: 0xff000000,
        is_default_gateway: false,
        metrics: 0,
        netdev: Netdev {
            addr: Ipv4Addr::new(127, 0, 0, 1),
            addr_len: 6,
            hwaddr: [0; 6],
            mtu: 1500,
        },
    },
    Route {
        dst: IP_ADDR,
        gateway: Ipv4Addr::new(0, 0, 0, 0),
        netmask: 0xffffff00,
        is_default_gateway: false,
        metrics: 0,
        netdev: Netdev {
            addr: IP_ADDR,
            addr_len: 6,
            hwaddr: MAC_OCTETS,
            mtu: 1500,
        },
    },
    Route {
        dst: Ipv4Addr::new(0, 0, 0, 0),
        gateway: Ipv4Addr::new(192, 168, 100, 1),
        netmask: 0,
        is_default_gateway: true,
        metrics: 0,
        netdev: Netdev {
            addr: IP_ADDR,
            addr_len: 6,
            hwaddr: MAC_OCTETS,
            mtu: 1500,
        },
    },
]);
