import sys
import struct
import itertools
from binascii import crc32

# http://wiki.wireshark.org/Development/LibpcapFileFormat

"""
typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;
"""

int64, uint64 = 'q', 'Q'
int32, uint32 = 'i', 'I'
int16, uint16 = 'h', 'H'
int8, uint8 = 'b', 'B'

uint24 = '3s' # weird

assert [struct.calcsize(n) for n in (int8, uint8, int16, uint16, int32, uint32, int64, uint64)] == [1,1,2,2,4,4,8,8]

pcap_header = [
    ('magic_number', uint32), 
    ('version_major', uint16), 
    ('version_minor', uint16),
    ('thiszone', int32),
    ('sigfigs',  uint32),
    ('snaplen', uint32), 
    ('network', uint32)
]

"""
typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
"""

# TCP -> create objects, poke at them, they keep state, tear them down?

pcap_packet_header = [
    ('ts_sec', uint32),
    ('ts_usec', uint32),
    ('incl_len', uint32),
    ('orig_len', uint32)
]

class EOD(IOError): pass 

def read(fd, length):
    data = fd.read(length)
    if len(data) != length:
        raise EOD()
    return data

def getfmt(meta):
    return "".join([v for (k,v) in meta])

def readstruct(fd, meta):
    size = struct.calcsize(getfmt(meta))
    data = read(fd, size)
    return readstring(data, meta)

def readstring(data, meta, endian = ''):
    return dict([(k,v) for ((k, vfmt), v) in zip(meta, struct.unpack(endian + getfmt(meta), data))])

def read1string(data, type):
    result, = struct.unpack(type, data)
    return result
    
def format_endpoint((ip, port)):
    return format_ip(ip) + ":" + str(port)
    
class Packet(object):
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.pcap = None
    
    def __repr__(self):
        return "[Packet " + format_endpoint(self.source) + " -> " +  format_endpoint(self.destination) + " at " + str(self.timestamp) + "]"
    
    @property
    def timestamp(self):
        if self.pcap:
            return self.pcap['ts_sec'] + self.pcap['ts_usec'] / 1000000.0
        return 0
        
    def parse(self):
        self.parse_mac()
        self.parse_ip()
        self.parse_tcp()

    def parse_ip(self):
        self.ip = readstring(self.ip_data[:20], ip_header)
        self.ihl = (self.ip['info'] & 0xF)
        self.tcp_data = self.ip_data[self.ihl*4:]

    def parse_mac(self):
        self.mac = self.raw_data[0:6]
        self.mac2 = self.raw_data[6:12]
        self.ethertype = read1string(self.raw_data[12:14], uint16)
        self.ip_data = self.raw_data[14:]        
            
    def parse_tcp(self):
        self.header = readstring(self.tcp_data[0:20], tcp_header, endian='!')

        self.tcp_header_length = (ord(self.tcp_data[12])>>4) * 4
        control_bits = ord(self.tcp_data[13])
        
        self.control = parse_control(control_bits)
        self.source = (self.ip['source'], self.header['source_port'])
        self.destination = (self.ip['destination'], self.header['destination_port'])
        self.socket = frozenset((self.source, self.destination))
        self.data = self.tcp_data[self.tcp_header_length:]

def read_packets(filename, my_mac = None, modulo=None, n=None):
    fd = file(filename, 'rb')
    data = readstruct(fd, pcap_header)
    assert data['magic_number'] == 0xa1b2c3d4, "If you see this, odds are you need to flip the byte order ('<' or '>' before every struct format)"

    try:
        while True:
            packet = readstruct(fd, pcap_packet_header)
            p = Packet(read(fd, packet['incl_len']))
            p.pcap = packet
            yield p
    except EOD:
        return

def good_hex(n):
    digits = '0123456789ABCDEF'
    return digits[n // 16] + digits[n % 16]

def format_mac(mac):
    return ":".join([good_hex(ord(n)) for n in mac])

def format_ip(ip):
    return ".".join([str((ip>>(8*n)) % 0x100) for n in range(4)])

ip_header = [
    ('info', uint8),
    ('tos', uint8),
    ('length', uint16),
    ('identification', uint16),
    ('offset', uint16),
    ('ttl', uint8),
    ('protocol', uint8),
    ('checksum', uint16),
    ('source', uint32),
    ('destination', uint32),
]

tcp_header = [
    ('source_port', uint16),
    ('destination_port', uint16),
    ('sequence_number', uint32),
    ('ack_number', uint32),
    ('meta', uint16),
    ('window', uint16),
    ('checksum', uint16),
    ('urgent', uint16),
]

control_names =('CWR', 'ECN', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN')[::-1]
parse_control = lambda control_bits:  frozenset([name for (n,name) in enumerate(control_names) if control_bits & (2**n)])

bin = lambda i, m: 'b' + ''.join(str((i>>n) & 1) for n in range(m))
    
def collapse_tcp_streams(packets, ConnFactory, progress = lambda: None):
    sockets = {}
    for packet in packets:
        packet.parse()
        progress()
        
        if 'SYN' in packet.control:
            sockets[packet.socket] = ConnFactory()
        elif 'FIN' in packet.control:
            try:
                del sockets[packet.socket]
            except KeyError:
                pass
        
        sock = sockets.get(packet.socket, None)
        if sock:
            sock.saw_packet(packet)
        # Packets from connections we're just now seeing are ignored. Bad idea? Maybe, but interjecting into a steram is annoying
                
import unittest

class TestTCPParser(unittest.TestCase):
    
    def test_goddamnit(self):
        raw_packet = "\x00\x19\xb9\xb4s\xe4\x00\x19\xb9\xf3\xb4\xb5\x08\x00E\x08\x02\x06\xcds@\x00@\x06L$\n\x05\x068\n\x07\x05\x0f\x8c\x97\x0c\xea\xc6\x90\xb8\xcc\xcfY\x962\x80\x18\x037!K\x00\x00\x01\x01\x08\n\xb1ia\xcdJ\xcdB0\xce\x01\x00\x00\x03/* Avatar Homepages */ \r\n            /*shard db://nrt-readonly */\r\n            /*cache-class customer://38030117/wishlist_panel*/\r\n            SELECT\r\n                DISTINCT CW.products_id\r\n            FROM customers_wishlist CW, products P\r\n            WHERE 1\r\n            AND CW.products_id = P.products_id\r\n            AND CW.customers_id = 38030117\r\n            AND P.products_mature != '2' AND P.products_mature = 'N' LIMIT 20 /* /catalog/web_404.php */"
        packet = Packet(raw_packet)
        packet.parse()
        self.assertEqual(32, packet.tcp_header_length)
        self.assertEqual(frozenset(['ACK', 'PSH']), packet.control)
        
    def test_again(self):
        raw_packet = '\x00\x19\xb9\xb4s\xe4\x00\x19\xb9\xf3\xb4\xb5\x08\x00E\x08\x004\xcdt@\x00@\x06M\xf5\n\x05\x068\n\x07\x05\x0f\x8c\x97\x0c\xea\xc6\x90\xba\x9e\xcfY\x96v\x80\x10\x0373d\x00\x00\x01\x01\x08\n\xb1ia\xcdJ\xcdBJ'
        packet = Packet(raw_packet)
        packet.parse()
        self.assertEqual(32, packet.tcp_header_length)
        self.assertEqual(frozenset(['ACK']), packet.control)
    
if __name__ == "__main__":
    unittest.main()