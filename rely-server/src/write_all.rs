use tokio::{io::AsyncWriteExt, net::tcp::OwnedWriteHalf};

pub async fn write_all(writer: &mut OwnedWriteHalf, buff: Vec<u8>) -> Result<(), std::io::Error> {
    //let buff = dbg!(buff);
    let len = buff.len() as u16;
    let bytes = len.to_be_bytes();
    let mut write_buffer = Vec::new();
    write_buffer.extend_from_slice(&bytes);
    write_buffer.extend_from_slice(&buff);
    tokio::select! {
        v = writer.write_all(&write_buffer) =>{
            v?
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(8)) =>{
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, ""));
        }
    };
    Ok(())
}
