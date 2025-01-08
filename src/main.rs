mod helpers;
use core::panic;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{
    transport_channel,
    TransportChannelType,
    TransportProtocol::Ipv4,
    icmp_packet_iter,
};
use std::process;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: sudo ./target/release/my_ping HOSTNAME");
        process::exit(1);
    }
    let peer_addr = &args[1];
    
    let ip = helpers::get_ip_by_name(peer_addr.as_str());
    println!("{ip}");
    let (mut tx, mut rx) = 
        transport_channel(
            helpers::PACKET_SIZE,
            TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Icmp))
        ).unwrap();

    let id: u16 = process::id().try_into().unwrap();
    let packet = helpers::create_echo_request_packet(id, 0).unwrap();

    let res = match tx.send_to(packet, ip) {
        Ok(v) => v,
        Err(e) => panic!("error on send: {}", e)
    };
    
    println!("sent {res} bytes");
    let mut iter = icmp_packet_iter(&mut rx);
    match iter.next() {
        Ok((packet, _)) => {
            if helpers::check_response(packet, id) {
                println!("Response received");
            } else {
                println!("WARNING: Received unreleated message!");
            }
        }
        Err(e) => { 
            panic!("error on reading iter: {}", e);
        }
    }
}
