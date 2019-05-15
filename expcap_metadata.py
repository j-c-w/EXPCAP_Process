from decimal import * 

# This is a constant to convert from bits to bytes.
SECOND_PER_BYTE_WIRE = Decimal(8.0 / 10000000000.0)


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
        self.packet_data = input_string[8]
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

        self.ethertype = self.packet_data[24:28]
        if self.ethertype == "ffff":
            print "Expcap format packet: do not use."
            self.padding_packet = True
            self.packet_data = None
            return
        else:
            self.padding_packet = False

        if self.ethertype != '0800':
            print "Error: Packet with unsupported ethertype",
            print self.ethertype
            print input_string
            print self.ethertype
            self.packet_data = None
            return

        # And the IP Source and destination addresses.
        self.is_ip = True
        self.src_addr = self.packet_data[52:60]
        self.dst_addr = self.packet_data[60:68]
        self.ip_protocol = self.packet_data[46:48]
        self.ip_length = int(self.packet_data[42:46], 16)
        self.fully_processed_ip = True

        if self.ip_protocol == "06":
            # This is a TCP packet.
            self.is_tcp = True
            self.src_port = self.packet_data[68:72]
            self.dst_port = self.packet_data[72:76]
            self.tcp_seq_no = self.packet_data[76:84]
            self.tcp_ack_no = self.packet_data[84:92]

            tcp_flags = int(self.packet_data[94:96], 16)
            print tcp_flags
            self.is_tcp_rst = tcp_flags & (2 ** 2)
            self.is_tcp_syn = tcp_flags & (2 ** 1)
            self.is_tcp_fin = tcp_flags & (2 ** 0)
            # -20 for IP header and -20 for TCP header.
            self.tcp_data_length = self.ip_length - 20 - 20
            if self.is_tcp_syn:
                print "Is syn!"
            if self.is_tcp_fin:
                print "Is Fin!"
            self.fully_processed_tcp = True
        else:
            self.is_tcp = False

        self.packet_data = None


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
