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
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file

    if pcap_file.endswith('.csv'):
        packet_sizes = process_csv.extract_sizes(pcap_file)

    range = [min(packet_sizes), max(packet_sizes)]
    print "Range is ", range
    print "Median is ", np.median(packet_sizes)
    print "Deviation is ", np.std(packet_sizes)
    packet_sizes = np.asarray(packet_sizes)

    bins = 1000
    plt.hist(packet_sizes, bins=bins, cumulative=True, histtype='step', normed=True)
    plt.ylabel("Fraction of Packets")
    plt.xlabel("Sizes (B)")
    plt.savefig(pcap_file + '_sizes.eps', format='eps')
    print "Done! File is in ", pcap_file + '_sizes.eps'
