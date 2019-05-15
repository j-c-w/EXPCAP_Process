import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import graph_utils
import numpy as np
import process_csv
import sys


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title')
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args(args)

    for pcap_file, label in args.input_files:
        if pcap_file.endswith('.csv'):
            flow_sizes = \
                process_csv.extract_flow_sizes(pcap_file)

        if len(flow_sizes) == 0:
            print "There were no TCP connections detected in ", pcap_file
            continue

        for i in range(len(flow_sizes)):
            flow_sizes[i] = flow_sizes[i]
        bins = np.append(np.linspace(min(flow_sizes), max(flow_sizes) + 0.00001, 1000), np.inf)
        plt.hist(flow_sizes, cumulative=True, bins=bins, histtype='step', normed=True, label=label)

    if args.title:
        plt.title(args.title)

    plt.figure(1)
    plt.xlabel("Flow Size (B)")
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_yax_max_one()
    graph_utils.set_integer_ticks()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_flow_sizes.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename


if __name__ == "__main__":
    main(sys.argv[1:])
