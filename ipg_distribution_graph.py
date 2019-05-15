from decimal import Decimal
import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import graph_utils
import numpy as np
import graph_utils
import process_csv
import sys


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True)
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

    pcap_files = args.input_files
    output_label = args.output_name

    for (pcap_file, label) in pcap_files:
        if pcap_file.endswith('.csv'):
            incoming_ipg_gaps = \
                process_csv.extract_ipgs(pcap_file, to_ip=args.server_ip)
            outgoing_ipg_gaps = \
                process_csv.extract_ipgs(pcap_file, from_ip=args.server_ip)

        range = [min(incoming_ipg_gaps), max(incoming_ipg_gaps)]
        print "Dealing with incoming IPG gaps"
        print "Range is ", range
        print "Median is ", np.median(incoming_ipg_gaps)
        print "Deviation is ", np.std(incoming_ipg_gaps)

        # Before we plot these, they need to be converted to normal
        # floats.  To do this, multiply by 10**9
        for i in xrange(len(incoming_ipg_gaps)):
            incoming_ipg_gaps[i] = float(Decimal(1000000000.0) * incoming_ipg_gaps[i])
        for i in xrange(len(outgoing_ipg_gaps)):
            outgoing_ipg_gaps[i] = float(Decimal(1000000000.0) * outgoing_ipg_gaps[i])

        # Remove anything greater than the 99th percentile to stop
        # if affecting the bins.
        i = 0
        nintyninth_percentile = np.percentile(incoming_ipg_gaps, 99)
        while i < len(incoming_ipg_gaps):
            if incoming_ipg_gaps[i] > nintyninth_percentile:
                del incoming_ipg_gaps[i]
            else:
                i += 1

        print nintyninth_percentile

        # Avoid issues witht the CDF line decreasing to zero after the data is
        # plotted.
        min_lim = min(incoming_ipg_gaps)
        max_lim = max(incoming_ipg_gaps)
        small_diff = (min_lim + max_lim) / 10000.0
        bins = np.linspace(min_lim, max_lim + small_diff, 1000)
        bins = np.append(bins, np.inf)

        plt.figure(1)
        plt.hist(incoming_ipg_gaps, bins=bins, cumulative=True,
                 histtype='step', normed=True, label=label)

        # Now do the outgoing.
        # Remove anything greater than the 99th percentile to stop
        # if affecting the bins.
        i = 0
        nintyninth_percentile = np.percentile(outgoing_ipg_gaps, 99)
        while i < len(outgoing_ipg_gaps):
            if outgoing_ipg_gaps[i] > nintyninth_percentile:
                del outgoing_ipg_gaps[i]
            else:
                i += 1

        print nintyninth_percentile

        # Avoid issues witht the CDF line decreasing to zero after the data
        # is plotted.
        min_lim = min(outgoing_ipg_gaps)
        max_lim = max(outgoing_ipg_gaps)
        small_diff = (min_lim + max_lim) / 10000.0
        bins = np.linspace(min_lim, max_lim + small_diff, 1000)
        bins = np.append(bins, np.inf)

        plt.figure(2)
        plt.hist(outgoing_ipg_gaps, bins=bins, cumulative=True,
                 histtype='step', normed=True, label=label)

    if args.title:
        plt.figure(1)
        plt.title('Client Traffic: ' + args.title)
        plt.figure(2)
        plt.title('Server Traffic: ' + args.title)

    plt.figure(1)
    plt.xlim([min(outgoing_ipg_gaps), nintyninth_percentile])
    plt.ylabel("CDF")
    plt.xlabel("IPG (ns)")
    graph_utils.legend_bottom_right()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = output_label + '_ipg_gaps_clients.eps'
    plt.savefig(filename)
    print "Done! File is in ", output_label + '_ipg_gaps_clients.eps'

    plt.figure(2)
    plt.xlim([min(outgoing_ipg_gaps), nintyninth_percentile])
    plt.ylabel("CDF")
    plt.xlabel("IPG (ns)")
    graph_utils.legend_bottom_right()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = output_label + '_ipg_gaps_server.eps'
    plt.savefig(filename)

    print "Done! File is in ", output_label + '_ipg_gaps_server.eps'


if __name__ == "__main__":
    main(sys.argv[1:])
