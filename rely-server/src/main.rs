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

//use tun::TunPacket;

pub mod write_all;

pub mod ip_dest_parse;

//mod mock_reply;

#[allow(dead_code)]
enum Message {
    Add((String, WriterHandle)),
    Data((String, Vec<u8>)),
    Remove((String, i64)),
    Mock((String, Vec<u8>)),
}

struct WriterHandle {
    timestamp: i64,
    vir_addr: String,
    socket: Arc<Mutex<OwnedWriteHalf>>,
    #[allow(dead_code)]
    physical_addr:String
}

async fn read_body(len: u16, reader: &mut OwnedReadHalf) -> Result<Vec<u8>, std::io::Error> {
    let len = len as usize;
    let mut buf = Vec::new();
    buf.resize(len as usize, b'\0');
    let mut read_len = 0;
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
}

async fn find_another(
    map: &HashMap<String, WriterHandle>,
    me: String,
) -> Option<&Arc<Mutex<OwnedWriteHalf>>> {
    for i in map {
        if *i.1.vir_addr == me {
            return Some(&i.1.socket);
        }
    }
    return None;
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
struct SerConfig{
	bind:String
}

use config_file::FromConfigFile;

fn read_node_list()->HashMap<String, String>{
	match NodeConfig::from_config_file("./node.toml"){
		Ok(config)=>{
			let config_hosts: HashMap<String, String> = {
				let vec = config.host;
				vec.iter()
					.map(|v| (v.identifier.clone(), v.vir.clone()))
					.collect()
			};
			config_hosts
		}
		Err(_)=>{
			Default::default()
		}
	}
}

#[tokio::main]
async fn main() {

	let config  = SerConfig::from_config_file("./rely_config.toml").unwrap();
    let _ = NodeConfig::from_config_file("./node.toml").unwrap();

    let listen = TcpListener::bind(config.bind).await.unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
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
    let write_tasks = tokio::spawn(async move {
        let mut map: HashMap<String, WriterHandle> = HashMap::new();
        loop {
            //println!("execute");
            match rx.recv().await {
                Some(Message::Add((num, writer))) => {
                    match map.iter().find(|(index, _)| **index == num) {
                        Some(v) => {
                            if ((*v.1).timestamp) <= writer.timestamp {
                                map.insert(num, writer);
                            }
                        }
                        None => {
                            map.insert(num, writer);
                        }
                    }
                }
                Some(Message::Data((_num, buff))) => {
                    //println!("receive data from {num}:\n{buff:?}");
                    match ip_dest_parse::get_dest_ip(&buff) {
                        Some(dest) => match find_another(&map, dest).await {
                            Some(writer) => {
                                let writer = Arc::clone(writer);
								tokio::spawn(async move {
									let mut writer = writer.lock().await;
									match write_all::write_all(& mut writer, buff).await{
										Ok(())=>{}
										Err(_)=>{
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
                    //println!("remove {num}");
                    match map
                        .iter()
                        .find(|(ip, handler)| **ip == index && handler.timestamp == version)
                    {
                        Some((index, _)) => {
                            let index = index.to_owned();
                            map.remove(&index);
                        }
                        None => {}
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
        //println!("socket_addr {socket_addr:?}");
        //println!("{socket_ip:?}");
        let its_identifier = {
            let mut buf = [0u8; 32];
            match stream.read_exact(&mut buf).await {
                Ok(size) => {
                    if size != 32{
                        continue;
                    }
                    match String::from_utf8(buf.to_vec()){
                        Ok(index)=>{
                            index
                        }
                        Err(_)=>{
                            continue;
                        }
                    }
                },
                Err(_) => {
                    continue;
                },
            }
        };
        //println!("its identifier {its_identifier}");
        let index = its_identifier;
        let vir_addr = match read_node_list().get(&index) {
            Some(v) => v.to_owned(),
            None => {
                let _ = stream.shutdown().await;
                continue;
            }
        };
        let (mut reader, writer) = stream.into_split();
        let timestamp = chrono::Local::now().timestamp_nanos();
        let writer = WriterHandle {
            timestamp,
            vir_addr,
            socket: Arc::new(Mutex::new(writer)),
            physical_addr:socket_addr.ip().to_string()
        };
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
                                Err(_) => {
                                    let _ = tx.send(Message::Remove((index, timestamp)));
                                    return;
                                }
                            }
                        } else {
                            continue;
                        }
                    }
                    Err(_) => {
                        let _ = tx.send(Message::Remove((index, timestamp)));
                        return;
                    }
                }
            }
        });
    }
    write_tasks.await.unwrap();
}
