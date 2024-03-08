use std::{collections::HashMap, sync::Arc};

// use rand::Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener,
    },
    sync::Mutex,
};

use byte_aes::Decryptor;
use base64::Engine;

//use tun::TunPacket;

pub mod write_all;

pub mod ip_dest_parse;

//mod mock_reply;

use time::{macros::format_description, UtcOffset};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::time::OffsetTime;

pub fn init_log() -> Option<WorkerGuard> {
    let local_time = OffsetTime::new(
        UtcOffset::from_hms(8, 0, 0).unwrap(),
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"),
    );
    if !cfg!(debug_assertions) {
        let file_appender = tracing_appender::rolling::daily("logs", "tunnel");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        tracing_subscriber::fmt()
            .with_timer(local_time)
            .with_max_level(tracing::Level::INFO)
            .with_writer(non_blocking)
            .init();
        Some(guard)
    } else {
        tracing_subscriber::fmt().with_timer(local_time).init();
        None
    }
}

#[allow(dead_code)]
enum Message {
    Add((String, WriterHandle)),
    Data((String, Vec<u8>)),
    Remove((String, i64)),
    Mock((String, Vec<u8>)),
}
#[derive(Debug)]
struct WriterHandle {
    timestamp: i64,
    vir_addr: String,
    socket: Arc<Mutex<OwnedWriteHalf>>,
    #[allow(dead_code)]
    physical_addr: String,
    identifier: String,
}

async fn read_body(len: u16, reader: &mut OwnedReadHalf) -> Result<Vec<u8>, std::io::Error> {
    let len = len as usize;
    let mut buf = Vec::new();
    buf.resize(len as usize, b'\0');
    let mut read_len = 0;
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_secs(10))=>{
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "",
            ));
        }
        r = async {
            loop {
                match reader.read(&mut buf[read_len..]).await {
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
        }=>{
            return r;
        }
    };
}

async fn find_another(map: &HashMap<String, WriterHandle>, me: String) -> Option<&WriterHandle> {
    map.iter()
        .find(|(_key, value)| value.vir_addr == me)
        .map(|(_, v)| v)
}

// enum AsyncMessage {
//     Add((String, JoinHandle<()>)),
//     Remove(String),
// }
use serde::Deserialize;

#[derive(Deserialize)]
struct Host {
    identifier: String,
    vir: String,
}

#[derive(Deserialize)]
struct NodeConfig {
    host: Vec<Host>,
}

#[derive(Deserialize)]
struct SerConfig {
    bind: String,
	encrypt_key:String
}

use config_file::FromConfigFile;

fn read_node_list() -> HashMap<String, String> {
    match NodeConfig::from_config_file("./node.toml") {
        Ok(config) => {
            let config_hosts: HashMap<String, String> = {
                let vec = config.host;
                vec.iter()
                    .map(|v| (v.identifier.clone(), v.vir.clone()))
                    .collect()
            };
            config_hosts
        }
        Err(_) => Default::default(),
    }
}

fn descrypt_bytes(data:Vec<u8>,key:&String)->Vec<u8>{
	let mut de = Decryptor::from(data);
	base64::engine::general_purpose::STANDARD.decode(de.decrypt_with(key)).unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let config = SerConfig::from_config_file("./rely_config.toml").unwrap();
    let _ = NodeConfig::from_config_file("./node.toml").unwrap();

    let _log_guard = init_log();

    let listen = TcpListener::bind(config.bind).await.unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let tx = Arc::new(tx);
    //let (tx_async, mut rx_async) = tokio::sync::mpsc::unbounded_channel::<AsyncMessage>();

    // let establish_task = tokio::spawn(async move {
    //     let mut save_tasks = HashMap::new();
    //     loop {
    //         match rx_async.recv().await {
    //             Some(AsyncMessage::Add((id, task))) => {
    //                 save_tasks.insert(id, task);
    //             }
    //             Some(AsyncMessage::Remove(id)) => {
    //                 //println!("task complete, so removed");
    //                 save_tasks.remove(&id);
    //             }
    //             None => {}
    //         }
    //     }
    // });
    let weak_tx = tx.downgrade();
	let encrpt_key = config.encrypt_key;
    let write_tasks = tokio::spawn(async move {
        let mut map: HashMap<String, WriterHandle> = HashMap::new();
        loop {
            //println!("execute");
            match rx.recv().await {
                Some(Message::Add((num, writer))) => {
					println!("add add add add!!!!!!!!!!");
                    match map.iter().find(|(index, _)| **index == num) {
                        Some(v) => {
                            if ((*v.1).timestamp) <= writer.timestamp {
                                map.insert(num, writer);
                            }else{
								tracing::info!("new added writer's version is older than that of the saved one");
							}
                        }
                        None => {
                            map.insert(num, writer);
                        }
                    }
                }
                Some(Message::Data((_num, buff))) => {
					let cleartext_buff = descrypt_bytes(buff.clone(),&encrpt_key);
					if cleartext_buff.len() < 20 {
						tracing::info!("Receive an invalid packet from peer, len = {}",cleartext_buff.len());
						continue;
					}
					//println!("receive data from {_num}:\n{cleartext_buff:?}");
                    match ip_dest_parse::get_dest_ip(&cleartext_buff) {
                        Some((source, dest)) => match find_another(&map, dest.clone()).await {
                            Some(writer) => {
                                let timestamp = writer.timestamp;
                                let writer_identifier = writer.identifier.clone();
                                let writer = Arc::clone(&writer.socket);
                                let self_sender_weak = weak_tx.clone();
                                tokio::spawn(async move {
                                    let mut writer = writer.lock().await;
                                    match write_all::write_all(&mut writer, buff).await {
                                        Ok(()) => {}
                                        Err(e) => {
                                            tracing::info!("Removed, {source} writing to {dest} has an error: {e:?}");
                                            match self_sender_weak.upgrade() {
                                                Some(tx) => {
                                                    let _ = tx.send(Message::Remove((
                                                        writer_identifier,
                                                        timestamp,
                                                    )));
                                                }
                                                None => {}
                                            }
                                            let _ = writer.shutdown().await;
                                        }
                                    }
                                });
                            }
                            None => {}
                        },
                        None => {}
                    }
                }
                Some(Message::Remove((index, version))) => {
                    //println!("remove {index}, {version}, {map:?}");
                    match map.iter().find(|(ip, _handler)| **ip == index) {
                        Some((index, handler)) => {
                            if handler.timestamp <= version {
                                tracing::info!(
                                    "{}, {}, {} removed successfully from the group",
                                    handler.identifier,
                                    handler.physical_addr,
                                    handler.vir_addr
                                );
                                let index = index.to_owned();
                                let writer = map.remove(&index);
                                match writer {
                                    Some(v) => {
                                        let _ = v.socket.lock().await.shutdown().await;
                                    }
                                    None => {}
                                }
                            } else {
                                println!("Outdate remove: key {index}, saved key {}, remove version {version}, saved version {},",handler.identifier,handler.timestamp);
                                tracing::info!("Outdate remove: key {index}, saved key {}, remove version {version}, saved version {},",handler.identifier,handler.timestamp);
                            }
                        }
                        None => {
                            println!("not found {index}, {version} in {map:?}");
                            tracing::info!("{index} {version} not found in the map when removing");
                        }
                    }
                }
                Some(Message::Mock((_num, _buff))) => {
                    //println!("mock buff:\n {buff:?}");
                    // let writer = map.get(&num).unwrap().clone();
                    // let uuid = uuid::Uuid::new_v4().to_string();
                    // let tx_async_copy = tx_async.clone();
                    // let _ = tx_async.send(AsyncMessage::Add((
                    //     uuid.clone(),
                    //     tokio::spawn(async move {
                    //         let time = rand::thread_rng().gen_range(100..3000);
                    //         tokio::time::sleep(std::time::Duration::from_millis(time)).await;
                    //         mock_reply::parse_tun_packet(Some(Ok(TunPacket::new(buff))), writer)
                    //             .await;
                    //         let _ = tx_async_copy.send(AsyncMessage::Remove(uuid));
                    //     }),
                    // )));
                    //writer.write_all(src)
                }
                None => {
                    return;
                }
            };
        }
    });
    // let mut join_set = JoinSet::new();
    //let mut index = 0;
    while let Ok((mut stream, socket_addr)) = listen.accept().await {
        println!("socket_addr {socket_addr:?}");
        //println!("{socket_ip:?}");
        let its_identifier = {
            let mut buf = [0u8; 32];
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) =>{
                    continue;
                }
                result = stream.read_exact(&mut buf) =>{
                    match result {
                        Ok(size) => {
                            if size == 0 || size != 32 {
                                continue;
                            }
                            match String::from_utf8(buf.to_vec()) {
                                Ok(index) => index,
                                Err(e) => {
									tracing::info!("an error occurs during parsing the identifier {e:?}");
                                    continue;
                                }
                            }
                        }
                        Err(_) => {
                            continue;
                        }
                    }
                }
            }
        };
        println!(r#"its identifier "{}""#,its_identifier.replace('\n', "\\n").replace('\r', "\\r"));
        let index = its_identifier;
        let vir_addr = match read_node_list().get(&index) {
            Some(v) => v.to_owned(),
            None => {
				let index = index.replace('\n', "\\n").replace('\r', "\\r");
				tracing::info!(r#"The identifier "{index}" does not exist in the group, shutdown the connection"#);
                let _ = stream.shutdown().await;
                continue;
            }
        };
        let (mut reader, writer) = stream.into_split();
        let timestamp = chrono::Local::now().timestamp_nanos();
        let writer = WriterHandle {
            timestamp,
            vir_addr: vir_addr.clone(),
            socket: Arc::new(Mutex::new(writer)),
            physical_addr: socket_addr.ip().to_string(),
            identifier: index.clone(),
        };
        println!("{index}, {socket_addr}, {vir_addr} adds to the group");
        tracing::info!("{index}, {socket_addr}, {vir_addr} adds to the group");
        let _ = tx.send(Message::Add((index.clone(), writer)));
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            let mut read_header_len = 0;
            loop {
                let index = index.clone();
                match reader.read(&mut len_buf[read_header_len..]).await {
                    Ok(size) => {
                        //println!("read in comming {size}");
                        if size == 0 {
                            tracing::info!("Removed, {index}<=>{vir_addr} may partially shutdown during read len with size 0");
                            let _ = tx.send(Message::Remove((index, timestamp)));
                            return;
                        }
                        read_header_len += size;
                        if read_header_len == 2 {
                            read_header_len = 0;
                            let body_len = u16::from_be_bytes(len_buf);
                            //println!("body len {body_len}");
                            match read_body(body_len, &mut reader).await {
                                Ok(buf) => {
                                    //println!("ready body:\n {buf:?}");
                                    let _ = tx.send(Message::Data((index, buf)));
                                    //let _ = tx.send(Message::Mock((index, buf)));
                                }
                                Err(e) => {
                                    tracing::info!("Removed, {index}<=>{vir_addr} has an error during read packet body: {e:?}");
                                    let _ = tx.send(Message::Remove((index, timestamp)));
                                    return;
                                }
                            }
                        } else {
                            continue;
                        }
                    }
                    Err(e) => {
                        tracing::info!("Removed, {index}<=>{vir_addr} has an error during read body len: {e:?}");
                        let _ = tx.send(Message::Remove((index, timestamp)));
                        return;
                    }
                }
            }
        });
    }
    write_tasks.await.unwrap();
}
