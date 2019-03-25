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
    parser.add_argument('--window-size', type=int, dest='window_size', help="How long to average over.  In ps.", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file
    window_size = args.window_size

    if pcap_file.endswith('.csv'):
        x_values, bandwidths = process_csv.extract_bandwidths(pcap_file, window_size)
    plt.plot(x_values, bandwidths)
    plt.ylabel("Time")
    plt.xlabel("Bandwidth Used Mbps")
    plt.savefig(pcap_file + '_bandwidth.eps', format='eps')
    print "Done! File is in ", pcap_file + '_bandwidth.eps'
