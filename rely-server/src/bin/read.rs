use std::{collections::HashMap, sync::Arc, io::{Write, Read}, net::TcpStream};

fn read_body(len: u16, reader: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let len = len as usize;
    let mut buf = Vec::new();
    buf.resize(len as usize, b'\0');
    let mut read_len = 0;
    loop {
        match reader.read(&mut buf[read_len..]){
            Ok(size) => {
                if size == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "",
                    ));
                }
                read_len += size;
                if read_len == len {
                    return Ok(buf);
                } else {
                    continue;
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}
fn main(){
    let mut socket = std::net::TcpStream::connect("192.168.1.139:3000").unwrap();
    let mut buff = [0u8;2];
	let mut read_len = 0;
	loop{
		match socket.read(& mut buff[read_len..]){
			Ok(size)=>{
				if size == 0{
					return;
				}
				read_len+=size;
				if read_len == 2{
					let len = u16::from_be_bytes(buff);
					let r = read_body(len,& mut socket).unwrap();
					println!("read from peer {r:?}");
					return;
				}else{
					continue;
				}
			}
			Err(_)=>{}
		}
	}
}