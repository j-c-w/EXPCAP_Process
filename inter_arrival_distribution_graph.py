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
    parser.add_argument('input_file')
    parser.add_argument('--bins', type=int, dest='bins', help="Number of bins", default=30)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file

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

    plt.hist(timestamp_deltas, bins=args.bins)
    plt.ylabel("Number of Packets")
    plt.xlabel("Inter-arrival time (ns)")
    plt.savefig(pcap_file + '_interarrival.eps', format='eps')
    print "Done! File is in ", pcap_file + '_interarrival.eps'
