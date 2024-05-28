use std::{
    fs::File,
    io::Read,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    process::exit,
};

use crate::sock_types::*;

use libc::{S_IRGRP, S_IROTH, S_IRUSR, S_IWGRP, S_IWOTH, S_IWUSR, S_IXGRP, S_IXOTH, S_IXUSR};

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
                loop {
                    let nb = match stream.read(&mut buf) {
                        Ok(nb) => nb,
                        Err(e) => {
                            eprintln!("Error reading from ipc socket: {e:?}");
                            exit(1);
                        }
                    };
                    if nb == 0 {
                        break;
                    }

                    process_ipc_call(&mut stream, &buf)
                }
            });
        }
    });
}

fn buf_to_struct<T>(buf: &[u8]) -> T {
    let size = std::mem::size_of::<T>();
    assert!(buf.len() >= size);

    unsafe { std::ptr::read(buf.as_ptr() as *const _) }
}

fn process_ipc_call(stream: &mut UnixStream, msg: &[u8]) -> () {
    let message: SocketMessage = buf_to_struct(msg);
    eprintln!("GOT IPC MESSAGE: {message:?}");
}
