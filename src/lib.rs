use pcap::{Active, Capture, Offline};
use pnet::packet::{ethernet::EthernetPacket, Packet};
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use std::fmt;
use std::net::{Ipv4Addr, IpAddr, Ipv6Addr};

pub fn list_devices() {
    for device in pcap::Device::list().expect("device lookup failed!") {
        println!(
            "Found device name {:?} - {:?}",
            device.name,
            device.desc.unwrap()
        );
    }
}

#[derive(Debug, Clone)]
pub struct HwAddress([u8; 6]);

#[derive(Debug, Clone)]
pub struct IPv4Address([u8; 4]);

#[derive(Debug, Clone)]
pub struct IPv6Address([u8; 6]);

#[derive(Debug, Clone)]
pub enum IPAddress {
    IPv4Address,
    IPv6Address,
}

#[derive(Debug, Clone)]
pub struct FlowID {
    src_mac: HwAddress,
    dst_mac: HwAddress,
    src_ip: IPAddress,
    dst_ip: IPAddress,
    sport: u16,
    dport: u16,
    vlan_id: u8,
    transport_proto: u8,
}

impl fmt::Display for IPv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}.{:?}.{:?}.{:?}",
            self.0[0], self.0[1], self.0[2], self.0[3],
        )
    }
}

impl fmt::Display for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }
}

impl fmt::Display for HwAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FlowID {
    pub fn to_string(&self) -> String {
        format!(
            "{:?}-{:?}-{:?}-{:?}-{:?}-{:?}-{:?}-{:?}",
            self.src_mac,
            self.dst_mac,
            self.src_ip,
            self.dst_ip,
            self.sport,
            self.dport,
            self.vlan_id,
            self.transport_proto
        )
    }

    pub fn array_test(self) {
        let new_mac: HwAddress = HwAddress([0, 0, 0, 0, 0, 0]);
        println!("{:?}", new_mac);
    }
}

pub struct FlowStats {}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x08DD;
// const 

enum PcapHandle {
    IfaceSource(Capture<Active>),
    FileSource(Capture<Offline>),
}

enum IpPdu<'a> {
    Ip4(Ipv4Packet<'a>),
    Ip6(Ipv6Packet<'a>)
}

pub struct Meter {
    handle: PcapHandle,
    flow_cache: Option<std::collections::HashMap<FlowID, FlowStats>>,
}

impl Meter {
    pub fn new(source: &str) -> Result<Self, pcap::Error> {
        let path: &std::path::Path = std::path::Path::new(&source);
        if path.exists() {
            let handle = Capture::from_file(source)?;
            return Result::Ok(Meter {
                handle: PcapHandle::FileSource(handle),
                flow_cache: None,
            });
        }
        let dev: Capture<Active> = Capture::from_device(source)?.open()?;
        Result::Ok(Meter {
            handle: PcapHandle::IfaceSource(dev),
            flow_cache: None,
        })
    }

    pub fn consume(&mut self) -> Result<(), ()>{
        let buf: Result<pcap::Packet<'_>, pcap::Error> = match &mut self.handle {
            PcapHandle::FileSource(handle) => handle.next_packet(),
            PcapHandle::IfaceSource(handle) => handle.next_packet(),
        };
        if buf.is_err() {
            println!("Should have exited!");
        }
        if let Some(eth_pdu) = EthernetPacket::new(buf.unwrap().data) {
            println!("{:?}", eth_pdu.get_ethertype());
            let et: u16 = eth_pdu.get_ethertype().0;
            let src_ip: IpAddr;
            let dst_ip: IpAddr;
            let src_port: u16;
            let dst_port: u16;
            let mut payload: &[u8];
            let ip_pdu: IpPdu;
            match et {
                ETHERTYPE_IPV4 => {
                    let ip_pdu: Option<Ipv4Packet<'_>> = Ipv4Packet::new(eth_pdu.payload());
                    src_ip = IpAddr::V4(ip_pdu.as_ref().unwrap().get_source());
                    dst_ip = IpAddr::V4(ip_pdu.as_ref().unwrap().get_destination());
                }
                ETHERTYPE_IPV6 => {
                    let ip6_pdu: Option<Ipv6Packet<'_>> = Ipv6Packet::new(eth_pdu.payload());
                    src_ip = IpAddr::V6(ip6_pdu.as_ref().unwrap().get_source());
                    dst_ip = IpAddr::V6(ip6_pdu.as_ref().unwrap().get_destination());
                }
                _ => return Err(()),
            }
            // match ip_pdu {

            // }

        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_devices() {
        list_devices();
    }
}
