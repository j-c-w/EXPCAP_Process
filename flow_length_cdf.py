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
    plt.figure(1)
    plt.clf()
    plt.figure(2)
    plt.clf()

    for pcap_file, label in args.input_files:
        if pcap_file.endswith('.csv'):
            flow_lengths = \
                process_csv.extract_flow_lengths(pcap_file)

        if len(flow_lengths) == 0:
            print "There were no TCP connections detected in ", pcap_file
            continue

        for i in range(len(flow_lengths)):
            flow_lengths[i] = float(flow_lengths[i])
        min_lim = min(flow_lengths)
        max_lim = max(flow_lengths)
        small_diff = (min_lim + max_lim) / 1000.0
        bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), np.inf)
        plt.figure(1)
        plt.hist(flow_lengths, cumulative=True, bins=bins, histtype='step', normed=True, label=label)

        no_zero_values = graph_utils.no_zeroes(flow_lengths)
        if len(no_zero_values) > 0:
            min_lim = min(no_zero_values)
            max_lim = max(no_zero_values)
            logspace_bins = graph_utils.get_logspace(min_lim, max_lim)

            plt.figure(2)
            plt.hist(no_zero_values, cumulative=True, bins=logspace_bins, histtype='step', normed=True, label=label)
        else:
            print "Hard Warning!: Found no non-zero flow sizes"

    if args.title:
        plt.figure(1)
        plt.title(args.title)
        plt.figure(2)
        plt.title(args.title)

    label_count = len(args.input_files)
    graph_utils.latexify(bottom_label_rows=label_count / 2)

    plt.figure(1)
    plt.xlabel("Flow Completion Time (us)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_flow_lengths.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    plt.figure(2)
    plt.xlabel("Flow Completion Time (us)")
    plt.ylabel("CDF")
    graph_utils.set_log_x()
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_flow_lengths_log.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

if __name__ == "__main__":
    main(sys.argv[1:])
