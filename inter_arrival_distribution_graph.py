import graph_utils
from decimal import *
import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import process_csv

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', dest='server_ip', help="The IP address of the server", required=True)
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title', required=False, default=None)
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    for pcap_file, label in args.input_files:
        if pcap_file.endswith('.csv'):
            timestamp_deltas_incoming = \
                process_csv.extract_deltas(pcap_file, to_ip=args.server_ip)
            timestamp_deltas_outgoing = \
                process_csv.extract_deltas(pcap_file, from_ip=args.server_ip)

        # Convert to ns before starting:
        for i in range(len(timestamp_deltas_incoming)):
            timestamp_deltas_incoming[i] = float(Decimal(1000000000.0) * timestamp_deltas_incoming[i])
        for i in range(len(timestamp_deltas_outgoing)):
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
        bins = np.append(np.linspace(range[0], range[1], 1000), np.inf)
        plt.hist(timestamp_deltas_outgoing, bins=bins, cumulative=True,
                 histtype='step', normed=True, label=label)

        # Do the incoming.
        range = [min(timestamp_deltas_incoming),
                 max(timestamp_deltas_incoming)]
        print "Incoming Range is ", range
        print "Incoming Median is ", np.median(timestamp_deltas_incoming)
        print "Incoming Deviation is ", np.std(timestamp_deltas_incoming)
        timestamp_deltas_incoming = \
            np.asarray(timestamp_deltas_incoming, dtype='float')

        bins = np.append(np.linspace(range[0], range[1], 1000), np.inf)

        plt.figure(2)
        plt.hist(timestamp_deltas_incoming, bins=bins,
                 cumulative=True, histtype='step', normed=True,
                 label=label)

    if args.title:
        plt.figure(1)
        plt.title("Server Traffic: " + args.title)
        plt.figure(2)
        plt.title("Client Traffic: " + args.title)

    plt.figure(1)
    plt.ylabel("CDF")
    plt.xlabel("Inter-arrival time (ns)")
    graph_utils.legend_bottom_right()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    plt.savefig(args.output_name + '_outgoing_interarrival.eps', format='eps')
    print "Done! File is in ", args.output_name + '_outgoing_interarrival.eps'

    # Do the incoming packets.
    plt.figure(2)
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    plt.xlabel("Inter-arrival time (ns)")
    plt.savefig(args.output_name + '_incoming_interarrival.eps', format='eps')
    print "Done! File is in ", args.output_name + '_incoming_interarrival.eps'
