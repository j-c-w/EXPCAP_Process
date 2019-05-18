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
    plt.figure(3)
    plt.clf()
    plt.figure(4)
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

        # Now plot a log space version, with all times included.
        incoming_ipg_gas_no_zeroes = graph_utils.no_zeroes(incoming_ipg_gaps)
        if len(incoming_ipg_gas_no_zeroes) > 0:
            lim_min = min(incoming_ipg_gas_no_zeroes)
            lim_max = max(incoming_ipg_gas_no_zeroes)

            bins = graph_utils.get_logspace(lim_min, lim_max)
            plt.figure(2)
            plt.hist(incoming_ipg_gas_no_zeroes, bins=bins, cumulative=True,
                     histtype='step', normed=True, label=label)
        else:
            print "Error:: found only zero times on the incoming IPG gaps"

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

        plt.figure(3)
        plt.hist(outgoing_ipg_gaps, bins=bins, cumulative=True,
                 histtype='step', normed=True, label=label)

        # Now plot the logspace version.
        outgoing_ipg_gaps_no_zeroes = graph_utils.no_zeroes(outgoing_ipg_gaps)
        if len(outgoing_ipg_gaps_no_zeroes) > 0:
            min_lim = min(outgoing_ipg_gaps_no_zeroes)
            max_lim = max(outgoing_ipg_gaps_no_zeroes)

            bins = graph_utils.get_logspace(min_lim, max_lim)
            plt.figure(4)
            plt.hist(outgoing_ipg_gaps_no_zeroes, bins=bins,
                     cumulative=True,
                     histtype='step', normed=True, label=label)
        else:
            print "Error: No non-zero IPGs found in outgoing data"

    if args.title:
        plt.figure(1)
        plt.title('Client Traffic: ' + args.title)
        plt.figure(2)
        plt.title('Client Traffic: ' + args.title)
        plt.figure(3)
        plt.title('Server Traffic: ' + args.title)
        plt.figure(4)
        plt.title('Server Traffic: ' + args.title)

    plt.figure(1)
    plt.xlim([min(outgoing_ipg_gaps), nintyninth_percentile])
    plt.ylabel("CDF")
    plt.xlabel("IPG (ns)")
    graph_utils.set_legend_below()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = output_label + '_ipg_gaps_clients.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    plt.figure(2)
    plt.ylabel("CDF")
    plt.xlabel("IPG (ns)")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = output_label + '_ipg_gaps_clients_log.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    plt.figure(3)
    plt.xlim([min(outgoing_ipg_gaps), nintyninth_percentile])
    plt.ylabel("CDF")
    plt.xlabel("IPG (ns)")
    graph_utils.set_legend_below()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = output_label + '_ipg_gaps_server.eps'
    plt.savefig(filename)

    print "Done! File is in ", filename

    plt.figure(4)
    plt.ylabel("CDF")
    plt.xlabel("IPG (ns)")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = output_label + '_ipg_gaps_server_log.eps'
    plt.savefig(filename)

    print "Done! File is in ", filename


if __name__ == "__main__":
    main(sys.argv[1:])
