use std::{net::SocketAddr, sync::Arc};

use config_file::FromConfigFile;
use futures::{SinkExt, StreamExt};

use packet::{builder::Builder, icmp, ip, ip::Protocol, Packet};
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream, sync::Mutex,
};
use tun::{Configuration, TunPacket};

use packet::Error as PktError;
use std::io::Error as StdError;

#[derive(Debug)]
enum Error {
    Packet(PktError),
    IO(StdError),
    Network(StdError),
    NoNeedProcess(String),
}

impl From<PktError> for Error {
    fn from(value: PktError) -> Self {
        Error::Packet(value)
    }
}

impl From<StdError> for Error {
    fn from(value: StdError) -> Self {
        Error::IO(value)
    }
}

//struct Reconnection;

async fn write_packet_to_socket(
    packet: TunPacket,
    stream: &mut OwnedWriteHalf,
) -> Result<(), Error> {
    let buff = packet.get_bytes();
    let len = buff.len() as u16;
    let bytes = len.to_be_bytes();
    let mut write_buffer = Vec::new();
    write_buffer.extend_from_slice(&bytes);
    write_buffer.extend_from_slice(buff);
    match stream.write_all(&write_buffer).await {
        Ok(()) => {}
        Err(e) => {
            return Err(Error::Network(e));
        }
    }
    Ok(())
}

fn build_icmp_reply_packet<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    pkt: &ip::v4::Packet<T>,
    icmp: &icmp::echo::Packet<U>,
) -> Result<Vec<u8>, Error> {
    Ok(ip::v4::Builder::default()
        .id(0x42)?
        .ttl(64)?
        .source(pkt.destination())?
        .destination(pkt.source())?
        .icmp()?
        .echo()?
        .reply()?
        .identifier(icmp.identifier())?
        .sequence(icmp.sequence())?
        .payload(icmp.payload())?
        .build()?)
}

enum WriteType {
    ToSocket(TunPacket),
    ToTun(TunPacket),
}

async fn parse_tun_packet(raw_pkt: TunPacket, current_ip: Ipv4Addr) -> Result<WriteType, Error> {
    match ip::Packet::new(raw_pkt.get_bytes()) {
        Ok(ip::Packet::V4(pkt)) => {
            //println!("");
            // IP V4 packet
            if pkt.protocol() == Protocol::Icmp {
                match icmp::Packet::new(pkt.payload()) {
                    Ok(icmp) => {
                        // packet is icmp echo
                        match icmp.echo() {
                            Ok(icmp) => {
                                if pkt.destination() == current_ip {
                                    //target myself
                                    let reply = build_icmp_reply_packet(&pkt, &icmp)?;
                                    //tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                    //framed.next().await;
                                    //println!("reply to {}",icmp.sequence());
                                    return Ok(WriteType::ToTun(TunPacket::new(reply)));
                                } else {
                                    return Ok(WriteType::ToSocket(raw_pkt));
                                }
                            }
                            _ => {
                                // println!("icmp packet from tun but not echo");
                                // write_packet_to_socket(raw_pkt, stream).await;
                                return Err(Error::NoNeedProcess(
                                    "icmp packet from tun but not echo".into(),
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        return Err(Error::Packet(e.into()));
                    }
                }
            } else {
                // maybe TCP, UDP or other packets
                if pkt.destination() == current_ip {
                    //target myself
                    return Ok(WriteType::ToTun(raw_pkt));
                } else {
                    return Ok(WriteType::ToSocket(raw_pkt));
                }
            }
        }
        Err(err) => {
            //println!("Received an invalid packet: {:?}", err);
            return Err(Error::Packet(err.into()));
        }
        _ => {
            //println!("non-ip-v4 packet!!!!!");
            return Err(Error::NoNeedProcess("non-ip-v4 packet".into()));
        }
    };
}

async fn parse_socket_packet(raw_pkt: TunPacket, current_ip: Ipv4Addr) -> Result<WriteType, Error> {
    match ip::Packet::new(raw_pkt.get_bytes()) {
        Ok(ip::Packet::V4(pkt)) => {
            //println!("ip v4 packet from socket");
            // IP V4 packet
            if pkt.protocol() == Protocol::Icmp {
                match icmp::Packet::new(pkt.payload()) {
                    Ok(icmp) => {
                        // packet is icmp echo
                        //println!("icmp packet from socket!!!!!");
                        match icmp.echo() {
                            Ok(icmp) => {
                                if pkt.destination() == current_ip {
                                    //target myself
                                    if icmp.is_request() {
                                        let reply = build_icmp_reply_packet(&pkt, &icmp)?;
                                        return Ok(WriteType::ToSocket(TunPacket::new(reply)));
                                    } else if icmp.is_reply() {
                                        return Ok(WriteType::ToTun(raw_pkt));
                                    }
                                }
                            }
                            _ => {
                                // println!("icmp packet but not icmp echo");
                                // framed.send(raw_pkt).await.unwrap();
                                // return;
                                return Err(Error::NoNeedProcess(
                                    "icmp packet but not icmp echo from socket".into(),
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        return Err(Error::Packet(e.into()));
                    }
                }
            } else {
                // maybe TCP, UDP packet or other packets
                //println!("tcp packet from socket!!!!!");
                if pkt.destination() == current_ip {
                    //target myself
                    return Ok(WriteType::ToTun(raw_pkt));
                }
                return Err(Error::NoNeedProcess("destination is not me".into()));
            }
            return Err(Error::NoNeedProcess(
                "neither ICMP nor {TCP, UDP} socket".into(),
            ));
        }
        Err(err) => {
            //println!("Received an invalid packet: {:?}", err);
            return Err(Error::Packet(err.into()));
        }
        _ => {
            //println!("non-ip-v4 packet!!!!!");
            return Err(Error::NoNeedProcess("non-ip-v4 packet".into()));
        }
    };
}

async fn read_data_len(stream: &mut OwnedReadHalf) -> Option<u16> {
    let mut buff_len = [0u8; 2];
    let mut read_size = 0;
    loop {
        match stream.read(&mut buff_len[read_size..]).await {
            Ok(size) => {
                if size == 0 {
                    return None;
                }
                read_size += size;
                if read_size == 2 {
                    let len = u16::from_be_bytes(buff_len);
                    return Some(len);
                } else {
                    continue;
                }
            }
            Err(_) => {
                return None;
            }
        }
    }
}

async fn read_body(len: u16, reader: &mut OwnedReadHalf) -> Option<Vec<u8>> {
    let len = len as usize;
    let mut buf = Vec::new();
    buf.resize(len as usize, b'\0');
    let mut read_len = 0;
    loop {
        match reader.read(&mut buf[read_len..]).await {
            Ok(size) => {
                if size == 0 {
                    return None;
                }
                read_len += size;
                if read_len == len {
                    return Some(buf);
                } else {
                    continue;
                }
            }
            Err(_) => {
                return None;
            }
        }
    }
}

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    rely: String,
    vir_addr: String,
    #[allow(dead_code)]
    route: String,
    try_times: i32,
    identifier: String,
}

#[tokio::main]
async fn main() {
    let config_file = Config::from_config_file("./config.toml").unwrap();

    let rely_server: SocketAddr = config_file.rely.parse().unwrap();
    let current_vir_ip: Ipv4Addr = config_file.vir_addr.parse().unwrap();

    let unique_identifier = config_file.identifier;
    if unique_identifier.len() != 32 {
        panic!("invalid identifier, whose len is not 32");
    }
    println!("your identifier is {unique_identifier}");

    let mut config = Configuration::default();

    config
        .address(current_vir_ip.clone())
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let dev = tun::create_as_async(&config).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));

    #[cfg(target_os = "macos")]
    {
        let s = format!(
            "sudo route -n add -net {} {}",
            config_file.route, config_file.vir_addr
        );
        let command = std::process::Command::new("sh")
            .arg("-c")
            .arg(s)
            .output()
            .unwrap();
        if !command.status.success() {
            panic!("cannot establish route to tun device");
        }
    };

    let framed = dev.into_framed();

    let stream = match TcpStream::connect(rely_server.clone()).await {
        Ok(mut stream) => {
            stream
                .write_all(unique_identifier.as_bytes())
                .await
                .unwrap(); // must panic
            stream
        }
        Err(e) => {
            panic!("cannot connection {e:?}");
        }
    };

    let (mut tun_writer, mut tun_reader) = framed.split();

    let (tun_writer_tx, mut tun_writer_rx) = tokio::sync::mpsc::unbounded_channel();
    let (socket_writer_tx, socket_writer_rx) = tokio::sync::mpsc::unbounded_channel();
    let _tun_writer_task = tokio::spawn(async move {
        loop {
            match tun_writer_rx.recv().await {
                Some(pkt) => match tun_writer.send(pkt).await {
                    Ok(_) => {}
                    Err(_) => {}
                },
                None => {
                    break;
                }
            }
        }
    });

    let tun_writer_tx_in_tun_read = tun_writer_tx.clone();
    let socket_writer_tx_in_tun_read = socket_writer_tx.clone();
    let _tun_read_task = tokio::spawn(async move {
        while let Some(v) = tun_reader.next().await {
            match v {
                Ok(packet) => match parse_tun_packet(packet, current_vir_ip).await {
                    Ok(WriteType::ToTun(pkt)) => {
                        let _ = tun_writer_tx_in_tun_read.send(pkt);
                    }
                    Ok(WriteType::ToSocket(pkt)) => {
                        let _ = socket_writer_tx_in_tun_read.send(pkt);
                    }
                    Err(e) => {
                        println!("from tun:\n{e:?}");
                    }
                },
                Err(_) => {}
            }
        }
    });

    let try_to_reconnect_network = move |mut times: i32| {
        //let rely_server = rely_server.clone();
        async move {
            let total_times = times;
            while times > 0 {
                println!("try to reconnect!!!!");
                match TcpStream::connect(rely_server.clone()).await {
                    Ok(mut new_stream) => {
                        new_stream
                            .write_all(unique_identifier.as_bytes())
                            .await
                            .unwrap(); // must panic
                        let (socket_reader, socket_writer) = new_stream.into_split();
                        return (socket_reader, socket_writer);
                    }
                    Err(e) => {
                        println!("reconnect fail due to {e:?}");
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                };
                times -= 1;
            }
            panic!("cannot reconnect to server in {total_times} times");
        }
    };

    let (mut socket_reader, mut socket_writer) = stream.into_split();

    //let _ = tx_in_socket.send(Message::SetSocketWriter(Arc::new(Mutex::new(socket_writer))));
    let socket_writer_rx = Arc::new(Mutex::new(socket_writer_rx));
    loop {
        let (recon_tx, mut recon_rx) = tokio::sync::mpsc::unbounded_channel();
        let tun_writer_tx_in_socket_read = tun_writer_tx.clone();
        let socket_writer_tx_in_socket_read = socket_writer_tx.clone();
        let recon_tx_0 = recon_tx.clone();
        let socket_read_task = tokio::spawn(async move {
            loop {
                match read_data_len(&mut socket_reader).await {
                    Some(size) => match read_body(size, &mut socket_reader).await {
                        Some(buf) => {
                            match parse_socket_packet(TunPacket::new(buf), current_vir_ip).await {
                                Ok(WriteType::ToSocket(pkt)) => {
                                    let _ = socket_writer_tx_in_socket_read.send(pkt);
                                }
                                Ok(WriteType::ToTun(pkt)) => {
                                    let _ = tun_writer_tx_in_socket_read.send(pkt);
                                }
                                Err(e) => {
                                    println!("from socket:\n{e:?}");
                                }
                            }
                        }
                        None => {
                            let _ = recon_tx_0.send(());
                            return;
                        }
                    },
                    None => {
                        let _ = recon_tx_0.send(());
                        return;
                    }
                }
            }
        });

		let socket_writer_rx = socket_writer_rx.clone();
        let socket_writer_task = tokio::spawn(async move {
			let mut guard = socket_writer_rx.lock().await;
            loop {
                match guard.recv().await {
                    Some(pkt) => match write_packet_to_socket(pkt, &mut socket_writer).await {
                        Ok(_) => {}
                        Err(e) => {
                            println!("write socket error: {e:?}");
                            let _ = recon_tx.send(());
                            return;
                        }
                    },
                    None => {
                        return;
                    }
                }
            }
        });

        let _ = recon_rx.recv().await;

        socket_read_task.abort();
        socket_writer_task.abort();
        let (r, w) = (try_to_reconnect_network.clone())(config_file.try_times).await;
        socket_reader = r;
        socket_writer = w;
    }
}
