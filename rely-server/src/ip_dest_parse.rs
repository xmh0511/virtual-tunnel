use packet::ip;

pub fn get_dest_ip(buf:&Vec<u8>)->Option<String>{
	match ip::Packet::new(&buf[..]) {
		Ok(ip::Packet::V4(pkt)) => {
			Some(pkt.destination().to_string())
		}
		Err(_) => {
			None
		}
		_ => {
			None
		}
	}
}