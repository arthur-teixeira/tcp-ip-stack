use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::exit,
};

use crate::{sock_types::*, socket::_socket};

use libc::{
    printf, S_IRGRP, S_IROTH, S_IRUSR, S_IWGRP, S_IWOTH, S_IWUSR, S_IXGRP, S_IXOTH, S_IXUSR,
};

pub fn start_ipc_listener() -> () {
    std::thread::spawn(move || {
        let sockname = "/tmp/tcpip.socket";
        let _ = std::fs::remove_file(sockname);

        let sock = UnixListener::bind(sockname)
            .map_err(|e| {
                eprintln!("Error creating IPC listener: {e:?}");
                exit(1);
            })
            .unwrap();

        // let as_file = File::open(sockname)
        //     .map_err(|e| {
        //         eprintln!("Error opening socket as file: {e:?}");
        //         exit(1)
        //     })
        //     .unwrap();
        //
        // let mut perms = as_file
        //     .metadata()
        //     .map_err(|e| {
        //         eprintln!("Could not get file metadata: {e:?}");
        //         exit(1);
        //     })
        //     .unwrap()
        //     .permissions();
        // let mode =
        //     S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH;
        // perms.set_mode(mode);
        //
        // as_file
        //     .set_permissions(perms)
        //     .map_err(|e| {
        //         eprintln!("Could not set permission for socket: {e:?}");
        //         exit(1);
        //     })
        //     .unwrap();

        loop {
            let (mut stream, _addr) = sock
                .accept()
                .map_err(|e| {
                    eprintln!("Could not accept connection: {e:?}");
                    exit(1);
                })
                .unwrap();

            std::thread::spawn(move || {
                let mut buf = [0; 8192];
                'reactor: loop {
                    let nb = match stream.read(&mut buf) {
                        Ok(nb) => nb,
                        Err(e) => {
                            eprintln!("Error reading from ipc socket: {e:?}");
                            exit(1);
                        }
                    };
                    if nb == 0 {
                        break 'reactor;
                    }

                    match process_ipc_call(&mut stream, &buf[..nb]) {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Error processing IPC call: {e:?}");
                            break 'reactor;
                        }
                    }
                }
            });
        }
    });
}

fn process_ipc_call(stream: &mut UnixStream, msg: &[u8]) -> Result<usize, std::io::Error> {
    let hdr: MessageHeader = MessageHeader::read_from_buffer(&msg);
    eprintln!("Message received: {:?}", msg);

    match hdr.kind {
        MessageKind::Socket => process_socket_call(stream, msg),
        MessageKind::Bind => todo!(),
        MessageKind::Listen => todo!(),
        MessageKind::Accept => todo!(),
        MessageKind::Read => todo!(),
        MessageKind::Write => todo!(),
        MessageKind::Error => todo!(),
    }
}

fn process_socket_call(stream: &mut UnixStream, msg: &[u8]) -> Result<usize, std::io::Error> {
    let payload = SocketMessage::read_from_buffer(&msg[MessageHeader::SIZE..]);

    let sockfd = _socket(payload.domain, payload.ptype, payload.protocol, None);
    let errno = if sockfd < 0 { -sockfd } else { 0 };

    let response_header = MessageHeader::read_from_buffer(msg);
    let response_message = ErrorMessage { errno, rc: sockfd };

    let mut buf = Vec::new();
    response_header.write_to_buffer(&mut buf);
    response_message.write_to_buffer(&mut buf);

    stream.write(&buf)
}
