from decimal import *

class ExpcapPacket(object):
    def __init__(self, input_string):
        # Split the packet up.
        input_string = input_string.split(',')
        self.number = int(input_string[0])
        self.arrival_time = Decimal(input_string[7])
        self.packet_data = input_string[8]
        self.length = len(self.packet_data[4:])
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

if __name__ == "__main__":
    # Test the extracting of the packet.
    packet = ExpcapPacket("0003,70ns,1552324919.660477296,84,68,0,0,1552324919.660477296500,00000c9ff0016805ca419334080045000032000100004011f867c0a80001c0a801010001007b001e4db461616161616161616161616161616161616161616161")

    assert packet.number == 3
    print packet.ethertype
    print packet.src_addr
    print packet.dst_addr
    print packet.length
