import argparse
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import os
import process_txt
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("first_file")
    parser.add_argument("second_file")

    args = parser.parse_args()

    first_file = args.first_file
    clear_first_file = False
    second_file = args.second_file
    clear_second_file = False

    if args.first_file.endswith('.pcap'):
        clear_first_file = True
        first_file = process_txt.create_txt_from_pcap(args.first_file)

    if args.second_file.endswith('.pcap'):
        clear_second_file = True
        second_file = process_txt.create_txt_from_pcap(args.second_file)

    first_times = np.array(process_txt.extract_times(first_file))
    second_times = np.array(process_txt.extract_times(second_file))

    if len(first_times) != len(second_times):
        print "Error: There are a different number of packets in each trace"
        sys.exit(1)

    # Now, go through each time and calculate the difference.
    # Plot that difference in a histogram.
    diffs = first_times - second_times
    print diffs
    plt.hist(diffs, bins=60)
    plt.title("Difference Between arrival times")
    plt.xlabel("Difference (ns)")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig(os.path.basename(first_file) + '_diff_' + \
            os.path.basename(second_file) + '.eps')

    if clear_first_file:
        os.remove(first_file)
    if clear_second_file:
        os.remove(second_file)
