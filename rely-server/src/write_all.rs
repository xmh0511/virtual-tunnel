use tokio::{net::tcp::OwnedWriteHalf, io::AsyncWriteExt};

pub async fn write_all(writer: & mut OwnedWriteHalf, buff: Vec<u8>)->Result<(),std::io::Error> {
    let len = buff.len() as u16;
    let bytes = len.to_be_bytes();
    let mut write_buffer = Vec::new();
    write_buffer.extend_from_slice(&bytes);
    write_buffer.extend_from_slice(&buff);
	writer.write_all(&write_buffer).await?;
	Ok(())
}
