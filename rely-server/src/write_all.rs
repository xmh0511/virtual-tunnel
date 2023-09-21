use std::sync::Arc;
use tokio::net::tcp::OwnedWriteHalf;

pub async fn write_all(writer: Arc<OwnedWriteHalf>, buff: Vec<u8>) {
    let len = buff.len() as u16;
    let bytes = len.to_be_bytes();
    let mut write_buffer = Vec::new();
    write_buffer.extend_from_slice(&bytes);
    write_buffer.extend_from_slice(&buff);
    let total_size = write_buffer.len();
    let mut write_size = 0;
    loop {
        let _ = writer.writable().await;
        match writer.try_write(&write_buffer[write_size..]) {
            Ok(size) => {
                write_size += size;
                if write_size >= total_size {
                    break;
                }
            }
            Err(_) => {}
        }
    }
}
