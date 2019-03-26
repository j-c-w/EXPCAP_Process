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
        # This isn't the full length: it's the length
        # of the packet as visible to IP (I think?)
        self.length = len(self.packet_data) / 2
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
            return
        else:
            self.padding_packet = False

        if self.ethertype != '0800':
            print "Error: Packet with unsupported ethertype"
            print input_string
            print self.ethertype
            return

        # And the IP Source and destination addresses.
        self.src_addr = self.packet_data[52:60]
        self.dst_addr = self.packet_data[60:68]
        self.fully_processed_ip = True


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
