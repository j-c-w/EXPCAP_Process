import argparse
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import os
import process_txt
import process_pcap
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("first_file")
    parser.add_argument("second_file")

    args = parser.parse_args()

    first_file = args.first_file
    second_file = args.second_file

    if args.first_file.endswith('.pcap'):
        first_times = np.array(process_pcap.extract_times(first_file))
    else:
        first_times = np.array(process_txt.extract_times(first_file))

    if args.second_file.endswith('.pcap'):
        second_times = np.array(process_pcap.extract_times(second_file))
    else:
        second_times = np.array(process_txt.extract_times(second_file))


    if len(first_times) != len(second_times):
        print "Error: There are a different number of packets in each trace"
        sys.exit(1)

    # Now, go through each time and calculate the difference.
    # Plot that difference in a histogram.
    diffs = first_times - second_times
    # Convert to ns:
    diffs = diffs * (10 ** 9)
    print "Plottiong ", len(diffs), "packets"
    print diffs
    plt.hist(diffs, bins=60)
    plt.title("Difference Between arrival times")
    plt.xlabel("Difference (ns)")
    plt.ylabel("Frequency")
    plt.xlim([min(diffs), max(diffs)])
    plt.tight_layout()
    plt.savefig(os.path.basename(first_file) + '_diff_' + \
            os.path.basename(second_file) + '.eps')
