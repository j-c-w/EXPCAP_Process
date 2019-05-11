import argparse
import graph_utils
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import process_csv

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title')
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    for pcap_file, label in args.input_files:
        if pcap_file.endswith('.csv'):
            flow_lengths = \
                process_csv.extract_flow_lengths(pcap_file)

        if len(flow_lengths) == 0:
            print "There were no TCP connections detected in ", pcap_file
            continue

        for i in range(len(flow_lengths)):
            flow_lengths[i] = float(flow_lengths[i])
        bins = np.append(np.linspace(min(flow_lengths), max(flow_lengths) + 0.00001, 1000), np.inf)
        plt.hist(flow_lengths, cumulative=True, bins=bins, histtype='step', normed=True, label=label)

    if args.title:
        plt.title(args.title)

    plt.figure(1)
    plt.xlabel("Flow Length (us)")
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_flow_lengths.eps'
    plt.savefig(filename, format='eps')
    print "Done! File is in ", filename
