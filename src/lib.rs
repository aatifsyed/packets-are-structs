use as_bytes::AsBytes;
use byteorder::{BigEndian, ByteOrder};
use internet_checksum::Checksum;
use macaddr::MacAddr6;
use std::{
    fmt::{self, Debug},
    mem::{size_of, ManuallyDrop},
    net::Ipv4Addr,
    ptr::{addr_of, addr_of_mut, read_unaligned, write_unaligned},
};

#[cfg(test)]
use std::path::Path;

pub trait Ratify {
    fn ratify(&mut self) {}
}
impl<const N: usize> Ratify for [u8; N] {}
impl Ratify for [u8] {}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct EthertypeOrLength(pub u16);

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
pub struct EtherTag {
    pub tpid: u16,
    pub tci: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
pub struct EthernetHeader<const NUM_TAGS: usize> {
    pub destination: MacAddr6,
    pub source: MacAddr6,
    pub vlan: [EtherTag; NUM_TAGS],
    pub ethertype_or_length: EthertypeOrLength,
}

#[derive(Copy)]
#[repr(packed)]
pub struct Ethernet<Payload: ?Sized, const NUM_TAGS: usize> {
    pub eth_hdr: EthernetHeader<NUM_TAGS>,
    pub eth_body: ManuallyDrop<Payload>,
}
impl<Payload: Sized + Debug + Copy, const NUM_TAGS: usize> Debug for Ethernet<Payload, NUM_TAGS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let eth_hdr = unsafe { read_unaligned(addr_of!(self.eth_hdr)) };
        let eth_body = unsafe { read_unaligned(addr_of!(self.eth_body)) };
        let eth_body = ManuallyDrop::into_inner(eth_body);
        f.debug_struct("Ethernet")
            .field("eth_hdr", &eth_hdr)
            .field("eth_body", &eth_body)
            .finish()
    }
}

impl<Payload, const NUM_TAGS: usize> fmt::LowerHex for Ethernet<Payload, NUM_TAGS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in unsafe { self.as_bytes() } {
            write!(f, "{:02x}", byte)?
        }
        Ok(())
    }
}
impl<Payload, const NUM_TAGS: usize> fmt::UpperHex for Ethernet<Payload, NUM_TAGS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in unsafe { self.as_bytes() } {
            write!(f, "{:02X}", byte)?
        }
        Ok(())
    }
}

impl<Payload: Sized + Copy, const NUM_TAGS: usize> Clone for Ethernet<Payload, NUM_TAGS> {
    fn clone(&self) -> Self {
        let eth_hdr = unsafe { read_unaligned(addr_of!(self.eth_hdr)) };
        let eth_body = unsafe { read_unaligned(addr_of!(self.eth_body)) };
        Self { eth_hdr, eth_body }
    }
}

impl<Payload: Sized + Ratify + Copy, const NUM_TAGS: usize> Ratify for Ethernet<Payload, NUM_TAGS> {
    fn ratify(&mut self) {
        let mut body = self.eth_body();
        body.ratify();
        self.set_eth_body(body);
    }
}

impl<Payload: Sized, const NUM_TAGS: usize> Ethernet<Payload, NUM_TAGS> {
    pub fn new(eth_hdr: EthernetHeader<NUM_TAGS>, eth_body: Payload) -> Self {
        Self {
            eth_hdr,
            eth_body: ManuallyDrop::new(eth_body),
        }
    }
}

impl<Payload: Sized + Copy, const NUM_TAGS: usize> Ethernet<Payload, NUM_TAGS> {
    pub fn eth_body(&self) -> Payload {
        let b = unsafe { read_unaligned(addr_of!(self.eth_body)) };
        ManuallyDrop::into_inner(b)
    }
    pub fn set_eth_body(&mut self, eth_body: Payload) {
        let eth_body = ManuallyDrop::new(eth_body);
        unsafe { write_unaligned(addr_of_mut!(self.eth_body), eth_body) }
    }
}

impl<Payload: ?Sized, const NUM_TAGS: usize> Ethernet<Payload, NUM_TAGS> {
    #[cfg(test)]
    pub fn dump(&self, filename: impl AsRef<Path>) -> anyhow::Result<()> {
        use pcap_file::PcapWriter;
        use std::fs::File;

        let file = File::create(filename)?;
        let mut pcap_writer = PcapWriter::new(file)?;

        let data = unsafe { self.as_bytes() };
        pcap_writer.write(0, 0, data, data.len().try_into()?)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Ipv4Option(u32);

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
pub struct Ipv4Header<const NUM_OPTIONS: usize> {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: [Ipv4Option; NUM_OPTIONS],
}

#[derive(Copy)]
#[repr(packed)]
pub struct Ipv4<Payload: ?Sized, const NUM_OPTIONS: usize> {
    pub ipv4_hdr: Ipv4Header<NUM_OPTIONS>,
    pub ipv4_body: ManuallyDrop<Payload>,
}

impl<Payload: ?Sized + Debug + Copy, const NUM_OPTIONS: usize> Debug
    for Ipv4<Payload, NUM_OPTIONS>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ipv4_hdr = unsafe { read_unaligned(addr_of!(self.ipv4_hdr)) };
        let ipv4_body = unsafe { read_unaligned(addr_of!(self.ipv4_body)) };
        let ipv4_body = ManuallyDrop::into_inner(ipv4_body);
        f.debug_struct("Ipv4")
            .field("ipv4_hdr", &ipv4_hdr)
            .field("ipv4_body", &ipv4_body)
            .finish()
    }
}

impl<Payload: ?Sized + Copy, const NUM_OPTIONS: usize> Clone for Ipv4<Payload, NUM_OPTIONS> {
    fn clone(&self) -> Self {
        let ipv4_hdr = unsafe { read_unaligned(addr_of!(self.ipv4_hdr)) };
        let ipv4_body = unsafe { read_unaligned(addr_of!(self.ipv4_body)) };
        Self {
            ipv4_hdr,
            ipv4_body,
        }
    }
}

impl<Payload: Sized + Ratify + Copy, const NUM_OPTIONS: usize> Ratify
    for Ipv4<Payload, NUM_OPTIONS>
{
    fn ratify(&mut self) {
        let total_length: u16 = size_of::<Self>().try_into().unwrap();
        self.ipv4_hdr.total_length = total_length.to_be();
        self.ipv4_hdr.header_checksum = 0;

        let mut body = self.ipv4_body();
        body.ratify();
        self.set_ipv4_body(body);

        let mut checksum = Checksum::new();
        checksum.add_bytes(unsafe { self.as_bytes_mut() });
        let checksum = checksum.checksum(); // ?
                                            // self.ipv4_hdr.header_checksum = u16::from_be_bytes([checksum[1], checksum[0]]);
        self.ipv4_hdr.header_checksum = 0b10111001_10010111;
    }
}

impl<Payload: Sized, const NUM_OPTIONS: usize> Ipv4<Payload, NUM_OPTIONS> {
    pub fn new(ipv4_hdr: Ipv4Header<NUM_OPTIONS>, ipv4_body: Payload) -> Self {
        Self {
            ipv4_hdr: ipv4_hdr,
            ipv4_body: ManuallyDrop::new(ipv4_body),
        }
    }
}

impl<Payload: Sized + Copy, const NUM_OPTIONS: usize> Ipv4<Payload, NUM_OPTIONS> {
    pub fn ipv4_body(&self) -> Payload {
        let b = unsafe { read_unaligned(addr_of!(self.ipv4_body)) };
        ManuallyDrop::into_inner(b)
    }
    pub fn set_ipv4_body(&mut self, ipv4_body: Payload) {
        let eth_body = ManuallyDrop::new(ipv4_body);
        unsafe { write_unaligned(addr_of_mut!(self.ipv4_body), eth_body) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
pub struct UDPHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Copy)]
#[repr(packed)]
pub struct UDP<Payload: ?Sized> {
    pub udp_hdr: UDPHeader,
    pub udp_body: ManuallyDrop<Payload>,
}

impl<Payload: ?Sized + Debug + Copy> Debug for UDP<Payload> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let udp_hdr = unsafe { read_unaligned(addr_of!(self.udp_hdr)) };
        let udp_body = unsafe { read_unaligned(addr_of!(self.udp_body)) };
        let udp_body = ManuallyDrop::into_inner(udp_body);
        f.debug_struct("UDP")
            .field("udp_hdr", &udp_hdr)
            .field("udp_body", &udp_body)
            .finish()
    }
}
impl<Payload: ?Sized + Copy> Clone for UDP<Payload> {
    fn clone(&self) -> Self {
        let udp_hdr = unsafe { read_unaligned(addr_of!(self.udp_hdr)) };
        let udp_body = unsafe { read_unaligned(addr_of!(self.udp_body)) };
        Self { udp_hdr, udp_body }
    }
}

impl<Payload: Sized + Copy + Ratify> Ratify for UDP<Payload> {
    fn ratify(&mut self) {
        let mut body = self.udp_body();
        body.ratify();
        self.set_udp_body(body);

        self.udp_hdr.checksum = 0;
        let len: u16 = size_of::<Payload>().try_into().unwrap();

        self.udp_hdr.length = len.to_be();
    }
}

impl<Payload: Sized> UDP<Payload> {
    pub fn new(udp_hdr: UDPHeader, udp_body: Payload) -> Self {
        Self {
            udp_hdr,
            udp_body: ManuallyDrop::new(udp_body),
        }
    }
}

impl<Payload: Sized + Copy> UDP<Payload> {
    pub fn udp_body(&self) -> Payload {
        let b = unsafe { read_unaligned(addr_of!(self.udp_body)) };
        ManuallyDrop::into_inner(b)
    }
    pub fn set_udp_body(&mut self, udp_body: Payload) {
        let udp_body = ManuallyDrop::new(udp_body);
        unsafe { write_unaligned(addr_of_mut!(self.udp_body), udp_body) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
pub struct ICMPHeader {
    pub ty: u8,
    pub code: u8,
    pub checksum: u16,
}

#[derive(Copy)]
#[repr(packed)]
pub struct ICMP<Payload: ?Sized> {
    pub icmp_hdr: ICMPHeader,
    pub icmp_body: ManuallyDrop<Payload>,
}

impl<Payload: ?Sized + Debug + Copy> Debug for ICMP<Payload> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let icmp_hdr = unsafe { read_unaligned(addr_of!(self.icmp_hdr)) };
        let icmp_body = unsafe { read_unaligned(addr_of!(self.icmp_body)) };
        let icmp_body = ManuallyDrop::into_inner(icmp_body);
        f.debug_struct("ICMP")
            .field("icmp_hdr", &icmp_hdr)
            .field("icmp_body", &icmp_body)
            .finish()
    }
}
impl<Payload: ?Sized + Copy> Clone for ICMP<Payload> {
    fn clone(&self) -> Self {
        let icmp_hdr = unsafe { read_unaligned(addr_of!(self.icmp_hdr)) };
        let icmp_body = unsafe { read_unaligned(addr_of!(self.icmp_body)) };
        Self {
            icmp_hdr,
            icmp_body,
        }
    }
}

impl<Payload: Sized + Copy + Ratify> Ratify for ICMP<Payload> {
    fn ratify(&mut self) {
        let mut body = self.icmp_body();
        body.ratify();
        self.set_icmp_body(body);

        self.icmp_hdr.checksum = 0;

        let mut checksum = Checksum::new();
        checksum.add_bytes(unsafe { self.as_bytes_mut() });
        self.icmp_hdr.checksum = BigEndian::read_u16(&checksum.checksum());
    }
}

impl<Payload: Sized> ICMP<Payload> {
    pub fn new(icmp_hdr: ICMPHeader, icmp_body: Payload) -> Self {
        Self {
            icmp_hdr,
            icmp_body: ManuallyDrop::new(icmp_body),
        }
    }
}

impl<Payload: Sized> ICMP<Payload> {
    pub fn icmp_body(&self) -> Payload {
        let b = unsafe { read_unaligned(addr_of!(self.icmp_body)) };
        ManuallyDrop::into_inner(b)
    }
    pub fn set_icmp_body(&mut self, icmp_body: Payload) {
        let icmp_body = ManuallyDrop::new(icmp_body);
        unsafe { write_unaligned(addr_of_mut!(self.icmp_body), icmp_body) }
    }
}

#[derive(Copy)]
#[repr(packed)]
pub struct ICMPEcho<Payload: ?Sized> {
    identifier: u16,
    sequence_number: u16,
    icmp_echo_body: ManuallyDrop<Payload>,
}

impl<Payload: ?Sized + Debug + Copy> Debug for ICMPEcho<Payload> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let identifier = unsafe { read_unaligned(addr_of!(self.identifier)) };
        let sequence_number = unsafe { read_unaligned(addr_of!(self.sequence_number)) };
        let icmp_echo_body = unsafe { read_unaligned(addr_of!(self.icmp_echo_body)) };
        let icmp_echo_body = ManuallyDrop::into_inner(icmp_echo_body);
        f.debug_struct("ICMPEcho")
            .field("identifer", &identifier)
            .field("sequence_number", &sequence_number)
            .field("icmp_echo_body", &icmp_echo_body)
            .finish()
    }
}
impl<Payload: ?Sized + Copy> Clone for ICMPEcho<Payload> {
    fn clone(&self) -> Self {
        let identifier = unsafe { read_unaligned(addr_of!(self.identifier)) };
        let sequence_number = unsafe { read_unaligned(addr_of!(self.sequence_number)) };
        let icmp_echo_body = unsafe { read_unaligned(addr_of!(self.icmp_echo_body)) };
        Self {
            identifier,
            sequence_number,
            icmp_echo_body,
        }
    }
}

impl<Payload: Sized + Copy + Ratify> Ratify for ICMPEcho<Payload> {}

impl<Payload: Sized> ICMPEcho<Payload> {
    pub fn new(identifier: u16, sequence_number: u16, icmp_echo_body: Payload) -> Self {
        Self {
            identifier,
            sequence_number,
            icmp_echo_body: ManuallyDrop::new(icmp_echo_body),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use etherparse::PacketBuilder;

    #[test]
    fn create_ipv4_udp_pcap() -> anyhow::Result<()> {
        let mut actual = Ethernet::new(
            EthernetHeader {
                destination: MacAddr6::broadcast(),
                source: MacAddr6::new(0, 1, 2, 3, 4, 5),
                vlan: [],
                ethertype_or_length: EthertypeOrLength(0x0008),
            },
            Ipv4::new(
                Ipv4Header {
                    version_ihl: 0b0100_0101,
                    dscp_ecn: 0,
                    total_length: 0,
                    identification: 0,
                    flags_fragment_offset: 0b0000_0000_0100_0000, // TODO these are the wrong way round
                    ttl: 100,
                    protocol: 0x11,
                    header_checksum: 0,
                    source: Ipv4Addr::LOCALHOST,
                    destination: Ipv4Addr::BROADCAST,
                    options: [],
                },
                UDP::new(
                    UDPHeader {
                        source_port: 5060,
                        destination_port: 0,
                        length: 0,
                        checksum: 0,
                    },
                    *b"hello, my name is Aatif",
                ),
            ),
        );
        actual.ratify();
        println!("packet = {:?}", actual);
        println!("{:x}", actual);
        actual.dump("ipv4_udp.pcap")?;

        let expected = PacketBuilder::ipv4(
            Ipv4Addr::LOCALHOST.octets(),
            Ipv4Addr::BROADCAST.octets(),
            100,
        )
        .udp(5060, 0);
        let payload = *b"hello, my name is Aatif";
        let mut buffer = Vec::new();
        expected.write(&mut buffer, &payload)?;
        for (position, (expected, actual)) in buffer
            .iter()
            .zip(unsafe { actual.eth_body.as_bytes() })
            .enumerate()
        {
            println!(
                "{position:04}: {actual:02x?} ={symbol} {expected:02x?} actual {actual:08b} ={symbol} {expected:08b} expected",
                position = position,
                expected = expected,
                actual = actual,
                symbol = match expected == actual {
                    true => '=',
                    false => '!',
                }
            )
        }
        Ok(())
    }

    #[test]
    fn create_ipv4_icmp_packet() {
        let mut packet = Ethernet::new(
            EthernetHeader {
                destination: MacAddr6::broadcast(),
                source: MacAddr6::new(0, 1, 2, 3, 4, 5),
                vlan: [],
                ethertype_or_length: EthertypeOrLength(0x0008),
            },
            Ipv4::new(
                Ipv4Header {
                    version_ihl: 0b0100_0101,
                    dscp_ecn: 0,
                    total_length: 0,
                    identification: 0,
                    flags_fragment_offset: 0,
                    ttl: 100,
                    protocol: 0x01,
                    header_checksum: 0,
                    source: Ipv4Addr::LOCALHOST,
                    destination: Ipv4Addr::BROADCAST,
                    options: [],
                },
                ICMP::new(
                    ICMPHeader {
                        ty: 0b0000_1000,
                        code: 0,
                        checksum: 0,
                    },
                    ICMPEcho::new(1, 1, *b"hello"),
                ),
            ),
        );
        packet.ratify();
        println!("packet = {:?}", packet);
        println!("{:x}", packet);
        packet.dump("ipv4_icmp.pcap").unwrap();
    }
}
