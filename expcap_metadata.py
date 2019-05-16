from decimal import * 

# This is a constant to convert from bits to bytes.
SECOND_PER_BYTE_WIRE = Decimal(8.0 / 10000000000.0)
DEBUG = False


class ExpcapPacket(object):
    def __init__(self, input_string):
        # This can be used to check if all the fields have
        # been filled in, e.g. in the case of a non-IP packet
        # they won't  be.
        self.fully_processed_ip = False
        # Split the packet up.
        input_string = input_string.split(',')
        self.number = int(input_string[0])
        self.arrival_time = Decimal(input_string[7])
        packet_data = input_string[8]
        # Note: the length of the input string isn't really
        # representative.  It seems to be trimmed at 64 bytes.
        self.length = int(input_string[4]) - 8
        # 24 is 8 preamble, 12 trailer, 4 FCS.  Assuming Ethernet here.
        self.preamble_length = 8.0
        self.trailer_length = 16.0
        self.wire_length = self.length + 24.0

        # Calculate the end time assuming a 10G link.
        self.start_time = self.arrival_time
        # The wire start time is different from the recorded time.
        self.wire_start_time = self.start_time - Decimal(self.preamble_length) * SECOND_PER_BYTE_WIRE
        self.end_time = self.start_time + Decimal(self.length) * SECOND_PER_BYTE_WIRE
        self.wire_end_time = self.wire_start_time + Decimal(self.wire_length) * SECOND_PER_BYTE_WIRE

        self.length_time = self.end_time - self.start_time
        self.wire_length_time = self.wire_end_time - self.wire_start_time

        self.ethertype = packet_data[24:28]
        if self.ethertype == "ffff":
            if DEBUG:
                print "Expcap format packet: do not use."
            self.padding_packet = True
            return
        else:
            self.padding_packet = False

        if self.ethertype != '0800':
            print "Error: Packet with unsupported ethertype",
            if DEBUG:
                print self.ethertype
                print input_string
                print self.ethertype
            return

        # And the IP Source and destination addresses.
        self.is_ip = True
        self.src_addr = packet_data[52:60]
        self.dst_addr = packet_data[60:68]
        self.ip_protocol = packet_data[46:48]
        # This is an offset for all future headers.
        self.ip_hdr_len = int(packet_data[29:30], 16)
        self.ip_length = int(packet_data[32:36], 16)
        self.fully_processed_ip = True

        # The offset is the 'normal' header length times 4 (to convert to bytes) times 2 (to convert to hex characters, which is what we work in.
        offset = (self.ip_hdr_len - 5) * 4 * 2

        if self.ip_protocol == "06":
            # This is a TCP packet.
            self.is_tcp = True
            self.src_port = packet_data[68 + offset:72 + offset]
            self.dst_port = packet_data[72 + offset:76 + offset]
            self.tcp_seq_no = packet_data[76 + offset:84 + offset]
            self.tcp_ack_no = packet_data[84 + offset:92 + offset]
            print packet_data[92 + offset:93 + offset]
            self.tcp_header_length = int(packet_data[92 + offset:93 + offset], 16)

            tcp_flags = int(packet_data[94 + offset:96 + offset], 16)
            print tcp_flags
            self.is_tcp_rst = tcp_flags & (2 ** 2)
            self.is_tcp_syn = tcp_flags & (2 ** 1)
            self.is_tcp_fin = tcp_flags & (2 ** 0)
            # -20 for IP header and -4 * tcp_header length
            # for TCP header.
            self.tcp_data_length = self.ip_length - 20 - (4 * self.tcp_header_length)
            if DEBUG and self.is_tcp_syn:
                print "Is syn!"
                print packet_data
            if DEBUG and self.is_tcp_fin:
                print "Is Fin!"
                print packet_data
            if DEBUG and self.is_tcp_rst:
                print "Is RST!"
                print packet_data
            self.fully_processed_tcp = True
        else:
            self.is_tcp = False



if __name__ == "__main__":
    # Test the extracting of the packet.
    packet = ExpcapPacket("0000,0ns,66763.781883179,84,68,0,0,66763.781883179000,00000c9ff00114dda911781a080045000032000100004011f867c0a80001c0a801010001007b001e4db461616161616161616161616161616161616161616161")

    print "Packet ethertype", packet.ethertype
    print "Packet Source", packet.src_addr
    print "Packet dest", packet.dst_addr
    print "Packet length in bytes", packet.length
    print "Packet wire length in bytes", packet.wire_length
    print "Packet length in seconds", packet.length_time
    print "Packet wire length in seconds", packet.wire_length_time
