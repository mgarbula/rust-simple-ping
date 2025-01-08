use dns_lookup::lookup_host;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
use pnet::packet::icmp::{IcmpTypes, IcmpCode, IcmpPacket};
use pnet::packet::Packet;

pub const PACKET_SIZE: usize = 64;
const ICMP_HEADER_SIZE: usize = 16;

pub fn get_ip_by_name(peer_addr: &str) -> std::net::IpAddr {
    let mut ips: Vec<std::net::IpAddr> = lookup_host(&peer_addr).unwrap();
    ips = ips.into_iter().filter(|ip| ip.is_ipv4()).collect();
    ips[0]
}

fn calculate_checksum(buffer: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < buffer.len() - 1 {
        sum += u16::from_be_bytes([buffer[i], buffer[i + 1]]) as u32;
        i += 2;
    }

    if i < buffer.len() {
        sum += buffer[i] as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

pub fn create_echo_request_packet(id: u16, sequence: u16) -> Result<EchoRequestPacket<'static>, String> {
    // create initial packet
    let mut packet = MutableEchoRequestPacket::owned(vec![0u8; PACKET_SIZE]).unwrap();
    packet.set_identifier(id);
    packet.set_sequence_number(sequence);
    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode(0));

    // fill and set payload
    let mut payload = vec![0u8; PACKET_SIZE - ICMP_HEADER_SIZE];
    for i in 0..PACKET_SIZE - ICMP_HEADER_SIZE {
        payload[i] = (i as u8) + b'0';
    }
    packet.set_payload(&payload);

    // calculate its checksum (currently checksum = 0)
    let checksum = calculate_checksum(packet.packet());

    // copy packet 
    packet.set_checksum(checksum);
    
    let ret_packet = packet.consume_to_immutable();
    Ok(ret_packet)
}

pub fn check_response(packet: IcmpPacket, id: u16) -> bool {
    let packet_type = packet.get_icmp_type();
    let buffer = packet.packet().to_vec();
    let mutable_packet = MutableEchoReplyPacket::owned(buffer).unwrap();
    let packet_id = mutable_packet.get_identifier();

    if packet_type == IcmpTypes::EchoReply && id == packet_id {
        return true
    }

    false
}