#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut command = match std::str::from_utf8(data) {
        Ok(slice) => slice.split("\r\n"),
        Err(_) => return,
    };

    let mut stream = std::net::TcpStream::connect("0.0.0.0:10025").unwrap();
    let timeout = std::time::Duration::from_nanos(1);
    stream.set_read_timeout(Some(timeout)).unwrap();
    stream.set_write_timeout(Some(timeout)).unwrap();

    let mut buffer = [0; 1024];
    loop {
        match std::io::Read::read(&mut stream, &mut buffer) {
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(e) => panic!("{e:?}"),
        }

        if let Some(i) = command.next() {
            std::io::Write::write_all(&mut stream, i.as_bytes()).unwrap();
        } else {
            return;
        }
    }
});
