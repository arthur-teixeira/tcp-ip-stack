use std::{
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
};

use crate::{
    arp::TunInterface,
    socket::{SockState, SockType},
    utils, BufWriter, BufferView, IpProtocol, IpV4Packet,
};

#[derive(Debug)]
pub struct UserDatagram<'a> {
    src_port: u16,
    dst_port: u16,
    len: u16,
    checksum: u16,
    data: &'a [u8],
}

impl<'a> UserDatagram<'a> {
    pub fn from_buffer(buffer: &'a mut BufferView) -> Self {
        let src_port = buffer.read_u16();
        let dst_port = buffer.read_u16();
        let len = buffer.read_u16();
        let checksum = buffer.read_u16();
        let data = buffer.read_slice(buffer.size - buffer.pos);

        Self {
            src_port,
            dst_port,
            len,
            checksum,
            data,
        }
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        let mut buf = BufWriter::new();
        buf.write_u16(self.src_port);
        buf.write_u16(self.dst_port);
        buf.write_u16(self.len);
        buf.write_u16(self.checksum);
        buf.write_slice(&self.data);

        buf.buf
    }

    pub fn validate_checksum(&self, packet: &IpV4Packet) -> bool {
        let src_ip = &packet.header().src_addr().into();
        let dst_ip = &packet.header().dst_addr().into();

        let result =
            utils::ipv4_checksum(&self.to_buffer(), 3, src_ip, dst_ip, IpProtocol::UDP as u8);

        result == self.checksum
    }
}

pub fn udp_incoming(packet: IpV4Packet) -> Result<()> {
    let mut buf_view = BufferView::from_slice(packet.data())?;
    let dgram = UserDatagram::from_buffer(&mut buf_view);

    if !dgram.validate_checksum(&packet) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Checksum does not match",
        ));
    }

    let cm = crate::socket::cm().lock().expect("Poisoned lock");

    for (i, sock) in cm.connections.iter().enumerate() {
        if sock.stype != SockType::Udp {
            continue;
        }

        if let SockState::Bound(port) = sock.state {
            if port == dgram.dst_port {
                // TODO: send data to recv/read call on this fd.
                eprintln!("Received UDP datagram on socket {i}");
            }
        }
    }

    // TODO: integrate into future socket API and send data to destination port
    Ok(())
}
