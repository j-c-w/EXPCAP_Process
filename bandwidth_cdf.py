import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import graph_utils
import numpy as np
import process_csv
import graph_utils
import sys

def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--window-size', nargs=2, action='append', dest='window_size', help="How long to average over.  In ps.", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True, help="IP of the machine that the card is directory connected to")
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
    plt.figure(3)
    plt.clf()
    plt.figure(4)
    plt.clf()

    for pcap_file, label in args.input_files:
        for window_size, label_suffix in args.window_size:
            if pcap_file.endswith('.csv'):
                incoming_x_values, incoming_bandwidths = \
                        process_csv.extract_bandwidths(pcap_file, window_size,
                                                       to_ip=args.server_ip, count=args.packets)
                outgoing_x_values, outgoing_bandwidths = \
                    process_csv.extract_bandwidths(pcap_file, window_size,
                                                   from_ip=args.server_ip, count=args.packets)

            for i in range(len(incoming_bandwidths)):
                incoming_bandwidths[i] = float(incoming_bandwidths[i])

            min_lim = min(incoming_bandwidths)
            max_lim = max(incoming_bandwidths)
            small_diff = (min_lim + max_lim) / 10000.0
            bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), np.inf)
            print bins
            plt.figure(1)
            plt.hist(incoming_bandwidths, cumulative=True, bins=bins, histtype='step', normed=True, label=label + ' ' + label_suffix)

            no_zero_incoming_bandwidths = graph_utils.no_zeroes(incoming_bandwidths)
            if len(no_zero_incoming_bandwidths) > 0:
                min_lim = min(no_zero_incoming_bandwidths)
                max_lim = max(no_zero_incoming_bandwidths)
                logspace_bins = graph_utils.get_logspace(min_lim, max_lim)
                plt.figure(2)
                plt.hist(no_zero_incoming_bandwidths, cumulative=True, bins=logspace_bins, histtype='step', normed=True, label=label + ' ' + label_suffix)
            else:
                print "Error: No non-zero bandwidths found"

            for i in range(len(outgoing_bandwidths)):
                outgoing_bandwidths[i] = float(outgoing_bandwidths[i])
            min_lim = min(outgoing_bandwidths)
            max_lim = max(outgoing_bandwidths)
            small_diff = (min_lim + max_lim) / 10000.0
            bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), np.inf)
            plt.figure(3)
            plt.hist(outgoing_bandwidths, cumulative=True, bins=bins, histtype='step', normed=True, label=label + ' ' + label_suffix)

            no_zero_outgoing_bandwidths = graph_utils.no_zeroes(outgoing_bandwidths)
            if len(no_zero_outgoing_bandwidths) > 0:
                min_lim = min(no_zero_outgoing_bandwidths)
                max_lim = max(no_zero_outgoing_bandwidths)
                logspace_bins = graph_utils.get_logspace(min_lim, max_lim)
                plt.figure(4)
                plt.hist(no_zero_outgoing_bandwidths, cumulative=True, bins=logspace_bins, histtype='step', normed=True, label=label + ' ' + label_suffix)
            else:
                print "Error: No non-zero bandwidths found!"

    if args.title:
        plt.figure(1)
        plt.title('Client Traffic: ' + args.title)
        plt.figure(2)
        plt.title('Client Traffic: ' + args.title)
        plt.figure(3)
        plt.title('Server Traffic: ' + args.title)
        plt.figure(4)
        plt.title('Server Traffic: ' + args.title)

    label_count = len(args.input_files) * len(args.window_size)
    graph_utils.latexify(bottom_label_rows=label_count / 2)

    plt.figure(1)
    plt.xlabel("Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_incoming_bandwidth_cdf_window.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    plt.figure(2)
    plt.ylabel("CDF")
    plt.xlabel("Bandwidth (Mbps)")
    graph_utils.set_log_x()
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_incoming_bandwidth_cdf_window_log.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    plt.figure(3)
    plt.xlabel("Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_outgoing_bandwidth_cdf_window.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    plt.figure(4)
    plt.xlabel("Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_outgoing_bandwidth_cdf_window_log.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename


if __name__ == "__main__":
    main(sys.argv[1:])
