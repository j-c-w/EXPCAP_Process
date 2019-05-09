import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import process_csv
import process_txt
import process_pcap

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--bins', type=int, dest='bins', help="Number of bins", default=30)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title', required=False, default=None)
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    for pcap_file, label in args.input_files:
        if pcap_file.endswith('.pcap'):
            timestamp_deltas = process_pcap.extract_deltas(pcap_file)
        elif pcap_file.endswith('.csv'):
            timestamp_deltas = process_csv.extract_deltas(pcap_file)
        else:
            timestamp_deltas = process_txt.extract_deltas(pcap_file)

        # Convert to ns before starting:
        for i in range(len(timestamp_deltas)):
            timestamp_deltas[i] = 1000000000.0 * timestamp_deltas[i]

        range = [min(timestamp_deltas), max(timestamp_deltas)]
        print "Range is ", range
        print "Median is ", np.median(timestamp_deltas)
        print "Deviation is ", np.std(timestamp_deltas)
        timestamp_deltas = np.asarray(timestamp_deltas, dtype='float')

        plt.hist(timestamp_deltas, bins=args.bins, label=label)

    if args.title:
        plt.title(args.title)

    plt.ylabel("Number of Packets")
    plt.xlabel("Inter-arrival time (ns)")
    plt.savefig(args.output_name + '_interarrival.eps', format='eps')
    print "Done! File is in ", args.output_name + '_interarrival.eps'
