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
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--window-size', type=int, nargs=2, dest='window_size', action='append', help="How long to average over.  In ps. (Also needs a label)", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title', required=False, default=None)
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    for pcap_file, label in args.pcap_files:
        for window in args.windows:
            if pcap_file.endswith('.csv'):
                windows, packet_sizes = process_csv.extract_sizes_by_window(pcap_file, window)

            median_sizes = [np.median(x) for x in packet_sizes]
            windows = [x[0] for x in windows]
            plt.plot(windows, median_sizes, label)

    if args.title:
        plt.title(args.title)

    plt.ylabel("Median Packet sizes through time")
    plt.xlabel("Time (s)")
    plt.savefig(args.output_name + '_sizes_through_time.eps', format='eps')
    print "Done! File is in ", args.output_name + '_sizes_through_time.eps'
