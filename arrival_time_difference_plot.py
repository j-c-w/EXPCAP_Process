import argparse
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import graph_utils
import os
import process_csv
import process_txt
import process_pcap
import sys


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("first_file")
    parser.add_argument("second_file")

    args = parser.parse_args(args)

    first_file = args.first_file
    second_file = args.second_file

    if args.first_file.endswith('.pcap'):
        first_times = np.array(process_pcap.extract_times(first_file))
    elif args.first_file.endswith('.csv'):
        first_times = np.array(process_csv.extract_times(first_file))
    else:
        first_times = np.array(process_txt.extract_times(first_file))

    if args.second_file.endswith('.pcap'):
        second_times = np.array(process_pcap.extract_times(second_file))
    elif args.second_file.endswith('.csv'):
        second_times = np.array(process_csv.extract_times(second_file))
    else:
        second_times = np.array(process_txt.extract_times(second_file))

    if len(first_times) != len(second_times):
        print len(first_times), "in first trace"
        print len(second_times), "in second trace"
        print "Error: There are a different number of packets in each trace"
        sys.exit(1)

    # Now, go through each time and calculate the difference.
    # Plot that difference in a histogram.
    diffs = first_times - second_times
    # Convert to ns:
    diffs = diffs * (10 ** 9)
    # Convert to floats so they can be plotted.
    diffs = np.asarray(diffs, dtype='float')
    print "Plottiong ", len(diffs), "packets"
    print min(diffs), max(diffs)
    bins = graph_utils.get_linspace(min(diffs), max(diffs))
    plt.hist(diffs, cumulative=True, bins=bins, histtype='step', normed=True)
    plt.xlabel("Difference (ns)")
    plt.ylabel("CDF")
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    plt.tight_layout()
    filename = os.path.basename(first_file) + '_diff_' + \
        os.path.basename(second_file) + '.eps'
    plt.savefig(filename)
    print "Figure saved in ", filename


if __name__ == "__main__":
    main(sys.argv[1:])
