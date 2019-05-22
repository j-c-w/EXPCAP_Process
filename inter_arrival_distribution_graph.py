from decimal import *
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
    parser.add_argument('--server', dest='server_ip', help="The IP address of the server", required=False, default=None)
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title', required=False, default=None)
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
        if pcap_file.endswith('.csv'):
            timestamp_deltas_incoming = \
                process_csv.extract_deltas(pcap_file, to_ip=args.server_ip)
            timestamp_deltas_outgoing = \
                process_csv.extract_deltas(pcap_file, from_ip=args.server_ip)

        # Convert to ns before starting:
        for i in xrange(len(timestamp_deltas_incoming)):
            timestamp_deltas_incoming[i] = float(Decimal(1000000000.0) * timestamp_deltas_incoming[i])
        for i in xrange(len(timestamp_deltas_outgoing)):
            timestamp_deltas_outgoing[i] = float(Decimal(1000000000.0) * timestamp_deltas_outgoing[i])

        # Do the outgoing packets.
        range = [min(timestamp_deltas_outgoing),
                 max(timestamp_deltas_outgoing)]
        print "Range is ", range
        print "Median is ", np.median(timestamp_deltas_outgoing)
        print "Deviation is ", np.std(timestamp_deltas_outgoing)
        timestamp_deltas_outgoing = \
            np.asarray(timestamp_deltas_outgoing, dtype='float')

        plt.figure(1)
        min_lim = range[0]
        max_lim = range[1]
        small_diff = (min_lim + max_lim) / 10000.0
        bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), np.inf)
        plt.hist(timestamp_deltas_outgoing, bins=bins, cumulative=True,
                 histtype='step', normed=True, label=label)

        timestamp_deltas_outgoing_no_zero = graph_utils.no_zeroes(timestamp_deltas_outgoing)
        if len(timestamp_deltas_outgoing_no_zero) > 0:
            min_lim = min(timestamp_deltas_outgoing_no_zero)
            max_lim = max(timestamp_deltas_outgoing_no_zero)
            logspace_bins = graph_utils.get_logspace(min_lim, max_lim)
            plt.figure(2)
            plt.hist(timestamp_deltas_outgoing_no_zero, bins=logspace_bins, cumulative=True,
                     histtype='step', normed=True, label=label)

        # Do the incoming.
        range = [min(timestamp_deltas_incoming),
                 max(timestamp_deltas_incoming)]
        print "Incoming Range is ", range
        print "Incoming Median is ", np.median(timestamp_deltas_incoming)
        print "Incoming Deviation is ", np.std(timestamp_deltas_incoming)
        timestamp_deltas_incoming = \
            np.asarray(timestamp_deltas_incoming, dtype='float')

        min_lim = range[0]
        max_lim = range[1]
        small_diff = (min_lim + max_lim) / 10000.0
        bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), np.inf)

        plt.figure(3)
        plt.hist(timestamp_deltas_incoming, bins=bins,
                 cumulative=True, histtype='step', normed=True,
                 label=label)

        timestamp_deltas_incoming_no_zero = graph_utils.no_zeroes(timestamp_deltas_incoming)
        if len(timestamp_deltas_incoming_no_zero) > 0:
            min_lim = min(timestamp_deltas_incoming_no_zero)
            max_lim = max(timestamp_deltas_incoming_no_zero)

            plt.figure(4)
            plt.hist(timestamp_deltas_incoming, bins=logspace_bins,
                     cumulative=True, histtype='step', normed=True,
                     label=label)
        else:
            print "Error: found no incoming timestamp deltas with nonzero inter-arrival times"

    if args.title:
        plt.figure(1)
        plt.title("Server Traffic: " + args.title)
        plt.figure(2)
        plt.title("Server Traffic: " + args.title)
        plt.figure(3)
        plt.title("Client Traffic: " + args.title)
        plt.figure(4)
        plt.title("Client Traffic: " + args.title)

    label_count = len(args.input_files)
    graph_utils.latexify(bottom_label_rows=label_count / 2)

    plt.figure(1)
    plt.ylabel("CDF")
    plt.xlabel("Inter-arrival time (ns)")
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_outgoing_interarrival.eps'
    plt.savefig(filename)
    print "Done! File is in ", args.output_name + '_outgoing_interarrival'

    plt.figure(2)
    plt.ylabel("CDF")
    plt.xlabel("Inter-arrival time (ns)")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_outgoing_interarrival_log.eps'
    plt.savefig(filename)
    print "Done! File is in ", args.output_name + '_outgoing_interarrival'

    # Do the incoming packets.
    plt.figure(3)
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    plt.xlabel("Inter-arrival time (ns)")
    filename = args.output_name + '_incoming_interarrival.eps'
    plt.savefig(filename)
    print "Done! File is in ", args.output_name + '_incoming_interarrival'

    # Do the incoming packets.
    plt.figure(4)
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    plt.xlabel("Inter-arrival time (ns)")
    filename = args.output_name + '_incoming_interarrival_log.eps'
    plt.savefig(filename)
    print "Done! File is in ", args.output_name + '_incoming_interarrival'


if __name__ == "__main__":
    main(sys.argv[1:])
