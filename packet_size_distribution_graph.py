import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import process_csv
import process_txt
import process_pcap
import expcap_metadata

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file')
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True, help="IP of the machine that the card is directory connected to")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file

    if pcap_file.endswith('.csv'):
        outgoing_packet_sizes = process_csv.extract_sizes(pcap_file, from_ip=args.server_ip)
        incoming_packet_sizes = process_csv.extract_sizes(pcap_file, to_ip=args.server_ip)
        both_packet_sizes = process_csv.extract_sizes(pcap_file)

    # Plot the server packet sizes.
    range = [min(outgoing_packet_sizes), max(outgoing_packet_sizes)]
    print "Range is ", range
    print "Median is ", np.median(outgoing_packet_sizes)
    print "Deviation is ", np.std(outgoing_packet_sizes)
    outgoing_packet_sizes = np.asarray(outgoing_packet_sizes)

    bins = 1000
    plt.hist(outgoing_packet_sizes, bins=bins, cumulative=True,
             histtype='step', normed=True)
    plt.ylabel("Fraction of Packets")
    plt.title("Cumlative Frequency Distribution of Packet Sizes")
    plt.xlabel("Sizes (B)")
    plt.savefig(pcap_file + '_sizes.eps', format='eps')
    print "Done! File is in ", pcap_file + '_outgoing_sizes.eps'

    # Plot the client packet sizes.
    range = [min(incoming_packet_sizes), max(incoming_packet_sizes)]
    print "Range is ", range
    print "Median is ", np.median(incoming_packet_sizes)
    print "Deviation is ", np.std(incoming_packet_sizes)
    incoming_packet_sizes = np.asarray(incoming_packet_sizes)

    bins = 1000
    plt.hist(incoming_packet_sizes, bins=bins, cumulative=True,
             histtype='step', normed=True)
    plt.ylabel("Fraction of Packets")
    plt.title("Cumlative Frequency Distribution of Packet Sizes")
    plt.xlabel("Sizes (B)")
    plt.savefig(pcap_file + '_incoming_sizes.eps', format='eps')
    print "Done! File is in ", pcap_file + '_incoming_sizes.eps'

    # Plot the packet sizes for both.
    range = [min(both_packet_sizes), max(both_packet_sizes)]
    print "Range is ", range
    print "Median is ", np.median(both_packet_sizes)
    print "Deviation is ", np.std(both_packet_sizes)
    both_packet_sizes = np.asarray(both_packet_sizes)

    bins = 1000
    plt.hist(both_packet_sizes, bins=bins, cumulative=True, histtype='step', normed=True)
    plt.ylabel("Fraction of Packets")
    plt.title("Cumlative Frequency Distribution of Packet Sizes")
    plt.xlabel("Sizes (B)")
    plt.savefig(pcap_file + '_all_sizes.eps', format='eps')
    print "Done! File is in ", pcap_file + '_all_sizes.eps'
