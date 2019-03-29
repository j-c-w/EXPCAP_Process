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
    parser.add_argument('--window', type=int, dest='window', help="Window size (ps)", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file
    window = args.window

    if pcap_file.endswith('.csv'):
        windows, packet_sizes = process_csv.extract_sizes_by_window(pcap_file, window)

    median_sizes = [np.median(x) for x in packet_sizes]
    windows = [x[0] for x in windows]
    plt.plot(windows, median_sizes)
    plt.ylabel("Median Packet sizes through time")
    plt.xlabel("Time (s)")
    plt.savefig(pcap_file + '_sizes_through_time.eps', format='eps')
    print "Done! File is in ", pcap_file + '_sizes_through_time.eps'
