from decimal import * 
import sys

# This is a constant to convert from bits to bytes.
SECOND_PER_BYTE_WIRE = Decimal(8.0 / 10000000000.0)
preamble_length = 8.0
preamble_wire_length = Decimal(preamble_length) * SECOND_PER_BYTE_WIRE
trailer_length = 16.0
DEBUG = False

HEADER_IP = 1
HEADER_TCP = 2
SYN_FLAG = 4
RST_FLAG = 8
FIN_FLAG = 16
PADDING_PACKET = 32
ENABLED = 64
# Everything but 'ENABLED'.  This is used to '&' remove the ENABLED flag.
NOT_ENABLED = HEADER_IP + HEADER_TCP + SYN_FLAG + RST_FLAG + FIN_FLAG + PADDING_PACKET
# These are flasg for extracting from our combnined data types.
FIRST_32 = 0xFFFFFFFF00000000
LAST_32 = 0x00000000FFFFFFFF
FIRST_16 = 0xFFFF0000
LAST_16 = 0x0000FFFF

class ExpcapPacket(object):
    # This results in a massive space saving.  Instead of using
    # dictionary lookups, it uses something else.
    # More importantly, it doesn't overallocate like a dictionary
    # does.
    __slots__ = ("start_time", "flags", "src_addr_dst_addr", "src_port_dst_port", "tcp_data_length", "length")

    def __init__(self, input_string, skip=False):
        self.start_time = None
        self.flags = None
        self.src_addr_dst_addr = None
        self.src_port_dst_port = None
        self.tcp_data_length = None
        self.length = None
        if skip:
            # This is used if we are loading one of these from a backup file.
            return
        # This can be used to check if all the fields have
        # been filled in, e.g. in the case of a non-IP packet
        # they won't  be.  Packet is enabled by default.
        self.flags = ENABLED
        # Split the packet up.
        input_string = input_string.split(',')
        # self.number = int(input_string[0])
        self.start_time = Decimal(input_string[7])
        packet_data = input_string[8]
        # Note: the length of the input string isn't really
        # representative.  It seems to be trimmed at 64 bytes.
        self.length = int(input_string[4]) - 8
        # 24 is 8 preamble, 12 trailer, 4 FCS.  Assuming Ethernet here.

        # The wire start time is different from the recorded time.
        ethertype = packet_data[24:28]
        if ethertype == "ffff":
            if DEBUG:
                print "Expcap format packet: do not use."
            self.flags |= PADDING_PACKET
            return

        if ethertype != '0800':
            print "Error: Packet with unsupported ethertype",
            if DEBUG:
                print ethertype
                print input_string
                print ethertype
            return

        # And the IP Source and destination addresses.
        # These are often used separatedly, but it requires
        # less space to store them in the same number.
        self.src_addr_dst_addr = int(packet_data[52:68], 16)
        # self.dst_addr = int(packet_data[60:68], 16)
        ip_protocol = packet_data[46:48]
        # This is an offset for all future headers.
        ip_hdr_len = int(packet_data[29:30], 16)
        ip_length = int(packet_data[32:36], 16)
        self.flags |= HEADER_IP

        # The offset is the 'normal' header length times 4 (to convert to bytes) times 2 (to convert to hex characters, which is what we work in.
        offset = (ip_hdr_len - 5) * 4 * 2

        if ip_protocol == "06":
            # This is a TCP packet.
            self.flags |= HEADER_TCP
            # We combine these into a single object to save space.
            self.src_port_dst_port = int(packet_data[68 + offset:76 + offset], 16)
            # self.dst_port = int(packet_data[72 + offset:76 + offset], 16)
            # self.tcp_seq_no = packet_data[76 + offset:84 + offset]
            # self.tcp_ack_no = packet_data[84 + offset:92 + offset]
            tcp_header_length = int(packet_data[92 + offset:93 + offset], 16)

            tcp_flags = int(packet_data[94 + offset:96 + offset], 16)
            is_tcp_rst = tcp_flags & (2 ** 2)
            is_tcp_syn = tcp_flags & (2 ** 1)
            is_tcp_fin = tcp_flags & (2 ** 0)
            if is_tcp_rst:
                self.flags |= RST_FLAG
            if is_tcp_syn:
                self.flags |= SYN_FLAG
            if is_tcp_fin:
                self.flags |= FIN_FLAG

            # -20 for IP header and -4 * tcp_header length
            # for TCP header.
            self.tcp_data_length = ip_length - 20 - (4 * tcp_header_length)
            if DEBUG and is_tcp_syn:
                print "Is syn!"
                print packet_data
            if DEBUG and is_tcp_fin:
                print "Is Fin!"
                print packet_data
            if DEBUG and is_tcp_rst:
                print "Is RST!"
                print packet_data

    def length_time(self):
        return self.end_time() - self.start_time

    def wire_length_time(self):
        return self.wire_end_time() - self.wire_start_time()

    def wire_start_time(self):
        return self.start_time - preamble_wire_length

    def end_time(self):
        return self.start_time + Decimal(self.length) * SECOND_PER_BYTE_WIRE

    def wire_end_time(self):
        return self.wire_start_time() + Decimal(self.wire_length()) * SECOND_PER_BYTE_WIRE

    def wire_length(self):
        return self.length + 24.0

    def src_addr(self):
        return (self.src_addr_dst_addr & FIRST_32) >> 32

    def dst_addr(self):
        return (self.src_addr_dst_addr & LAST_32)

    def src_port(self):
        return (self.src_port_dst_port & FIRST_16) >> 16

    def dst_port(self):
        return (self.src_port_dst_port & LAST_16)

    def is_tcp_rst(self):
        return (self.flags & RST_FLAG)

    def is_tcp_syn(self):
        return self.flags & SYN_FLAG

    def is_tcp_fin(self):
        return self.flags & FIN_FLAG

    def is_ip(self):
        return self.flags & HEADER_IP

    def is_tcp(self):
        return self.flags & HEADER_TCP

    def is_padding(self):
        return self.flags & PADDING_PACKET

    def set_enabled(self):
        self.flags = self.flags | ENABLED

    def set_disabled(self):
        self.flags = self.flags & NOT_ENABLED

    def is_enabled(self):
        return self.flags & ENABLED

    def is_disabled(self):
        return not self.flags & ENABLED

    def get_state(self):
        ("start_time", "flags", "src_addr_dst_addr", "src_port_dst_port", "tcp_data_length", "length")
        fields_list = [self.start_time, self.flags, self.src_addr_dst_addr, self.src_port_dst_port, self.tcp_data_length, self.length]
        assert len(fields_list) == len(self.__slots__)
        # You need to add extra fields to the pickle string if you're going to do this.

        return ",".join([str(x) for x in fields_list])

    def __decimal_or_none(self, x):
        if x == "None":
            return None
        else:
            return Decimal(x)

    def __int_or_none(self, x):
        if x == "None":
            return None
        else:
            return int(x)

    def set_state(self, string):
        elements = string.split(',')
        self.start_time = self.__decimal_or_none(elements[0])
        self.flags = self.__int_or_none(elements[1])
        self.src_addr_dst_addr = self.__int_or_none(elements[2])
        self.src_port_dst_port = self.__int_or_none(elements[3])
        self.tcp_data_length = self.__int_or_none(elements[4])
        self.length = self.__int_or_none(elements[5])

def get_size(obj, seen=None):
    """Recursively finds size of objects"""
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    # Important mark as seen *before* entering recursion to gracefully handle
    # self-referential objects
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        dict_size = get_size(obj.__dict__, seen)
        size += dict_size
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    elif hasattr(obj, '__slots__'):
        size += get_size(obj.__slots__, seen)
    return size


def double_list_save_expcaps_to(f, expcap_list):
    strings = []
    for sub_list in expcap_list:
        strings.append('_'.join([x.get_state() for x in sub_list]))

    f.write("+".join(strings))


def double_list_load_expcaps_from(f):
    lines = f.readlines()
    if len(lines) == 0:
        return []
    bursts = lines[0].split("+")
    for j in range(len(bursts)):
        line = bursts[j]
        if line == '':
            bursts[j] = []
        else:
            packets = line.split('_')
            for i in range(len(packets)):
                packet = ExpcapPacket('', skip=True)
                packet.set_state(packets[i])
                packets[i] = packet
            bursts[j] = packets

    return bursts


def print_expcap_list_size(elist):
    print "List size is", get_size(elist)


if __name__ == "__main__":
    import sys
    # Test the extracting of the packet.
    packet = ExpcapPacket("0000,0ns,66763.781883179,84,68,0,0,66763.781883179000,00000c9ff00114dda911781a080045000032000100004011f867c0a80001c0a801010001007b001e4db461616161616161616161616161616161616161616161")
    print "Object size is", get_size(packet)

