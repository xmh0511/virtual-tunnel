use packet::ip;

pub fn get_dest_ip(buf: &[u8]) -> Option<(String, String)> {
    match ip::Packet::new(&buf) {
        Ok(ip::Packet::V4(pkt)) => Some((pkt.source().to_string(), pkt.destination().to_string())),
        Err(_) => None,
        _ => None,
    }
}
