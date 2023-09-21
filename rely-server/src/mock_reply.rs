use packet::{builder::Builder, icmp, ip, Packet};
use std::{io::Error, sync::Arc};
use tun::TunPacket;

use tokio::net::tcp::OwnedWriteHalf;

use super::write_all;

// async fn write_packet_to_socket(packet: TunPacket, stream: &mut OwnedWriteHalf) {
//     let buff = packet.get_bytes();
//     let len = buff.len() as u16;
//     let bytes = len.to_be_bytes();
//     let mut write_buffer = Vec::new();
//     write_buffer.extend_from_slice(&bytes);
//     write_buffer.extend_from_slice(buff);
//     stream.write(&write_buffer).await.unwrap();
// }

pub async fn parse_tun_packet(
    packet: Option<Result<TunPacket, Error>>,
    stream: Arc<OwnedWriteHalf>,
) {
    match packet {
        Some(packet) => match packet {
            Ok(raw_pkt) => match ip::Packet::new(raw_pkt.get_bytes()) {
                Ok(ip::Packet::V4(pkt)) => {
                    //println!("");
                    // IP V4 packet
                    match icmp::Packet::new(pkt.payload()) {
                        Ok(icmp) => {
                            // packet is icmp echo
                            match icmp.echo() {
                                Ok(icmp) => {
                                    let reply = ip::v4::Builder::default()
                                        .id(0x42)
                                        .unwrap()
                                        .ttl(64)
                                        .unwrap()
                                        .source(pkt.destination())
                                        .unwrap()
                                        .destination(pkt.source())
                                        .unwrap()
                                        .icmp()
                                        .unwrap()
                                        .echo()
                                        .unwrap()
                                        .reply()
                                        .unwrap()
                                        .identifier(icmp.identifier())
                                        .unwrap()
                                        .sequence(icmp.sequence())
                                        .unwrap()
                                        .payload(icmp.payload())
                                        .unwrap()
                                        .build()
                                        .unwrap();

									write_all::write_all(stream, reply).await;
                                    //write_packet_to_socket(TunPacket::new(reply), stream).await;
                                    return;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                Err(err) => {
                    println!("Received an invalid packet: {:?}", err);
                }
                _ => {}
            },
            Err(err) => {
                println!("Error: {:?}", err);
            }
        },
        None => {}
    }
}
