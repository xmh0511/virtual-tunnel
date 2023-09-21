use std::{collections::HashMap, sync::Arc, io::Write};
fn main(){
    let mut socket = std::net::TcpStream::connect("127.0.0.1:3000").unwrap();
	loop{
		let buff = b"123456789abcdefg";
		let mut w_buf = Vec::new();
		let len = (buff.len() as u16).to_be_bytes();
		w_buf.extend_from_slice(&len);
		w_buf.extend_from_slice(buff);
		socket.write_all(&w_buf).unwrap();
		std::thread::sleep(std::time::Duration::from_secs(2));
	}
}