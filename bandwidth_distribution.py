import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import graph_utils
import numpy as np
import process_csv

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

    for (pcap_file, label) in args.input_files:
        for (window_size, label_suffix) in args.window_sizes:
            if pcap_file.endswith('.csv'):
                x_values, usages = process_csv.extract_bandwidths(pcap_file, window_size, count=args.packets)
            # Recenter the xvalues around zero.
            zero_value = x_values[0][0]
            for i in range(len(x_values)):
                x_values[i] = x_values[i][0] - zero_value

            bins = np.append(np.linspace(min(bandwidths), max(bandwidths), 1000), np.inf)
            plt.hist(bandwidths, cumulative=True, normed=True, histtype='step', bins=bins, label=label)

    plt.xlabel("Bandwidth Used (Mbps)")
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    if len(args.input_files) * len(args.window_sizes) > 1:
        plt.legend()

    if args.title:
        plt.title(args.title)
    filename = args.output_name + '_bandwidth_cdf.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename
