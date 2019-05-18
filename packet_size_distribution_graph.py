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
    parser.add_argument('--server', dest='server_ip', required=True, help="IP of the machine that the card is directory connected to")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title', required=False, default=None)

    args = parser.parse_args(args)

    plt.figure(1)
    plt.clf()
    plt.figure(2)
    plt.clf()
    plt.figure(3)
    plt.clf()
    plt.figure(4)
    plt.clf()
    plt.figure(5)
    plt.clf()
    plt.figure(6)
    plt.clf()

    for (pcap_file, label) in args.input_files:
        if pcap_file.endswith('.csv'):
            outgoing_packet_sizes = process_csv.extract_sizes(pcap_file, from_ip=args.server_ip)
            incoming_packet_sizes = process_csv.extract_sizes(pcap_file, to_ip=args.server_ip)
            both_packet_sizes = process_csv.extract_sizes(pcap_file)

        # Plot the server packet sizes.
        range = [min(outgoing_packet_sizes), max(outgoing_packet_sizes)]
        print "From the server, "
        print "Range is ", range
        print "Median is ", np.median(outgoing_packet_sizes)
        print "Deviation is ", np.std(outgoing_packet_sizes)
        outgoing_packet_sizes = np.asarray(outgoing_packet_sizes)
        min_lim = min(outgoing_packet_sizes)
        max_lim = max(outgoing_packet_sizes)
        small_diff = (min_lim + max_lim) / 10000.0
        bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), [np.inf])
        plt.figure(1)
        plt.hist(outgoing_packet_sizes, bins=bins, cumulative=True,
                 histtype='step', normed=True, label=label)

        # Plot the log version:
        log_bins = graph_utils.get_logspace(min_lim, max_lim)
        plt.figure(2)
        plt.hist(outgoing_packet_sizes, bins=log_bins, cumulative=True,
                 histtype='step', normed=True, label=label)


        # Plot the incoming packet sizes.
        range = [min(incoming_packet_sizes), max(incoming_packet_sizes)]
        print "Into the server, "
        print "Range is ", range
        print "Median is ", np.median(incoming_packet_sizes)
        print "Deviation is ", np.std(incoming_packet_sizes)
        incoming_packet_sizes = np.asarray(incoming_packet_sizes)
        min_lim = min(incoming_packet_sizes)
        max_lim = max(incoming_packet_sizes)
        small_diff = (min_lim + max_lim) / 10000.0
        bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), [np.inf])
        plt.figure(3)
        plt.hist(incoming_packet_sizes, bins=bins, cumulative=True,
                 histtype='step', normed=True, label=label)

        # Plot the log versions.
        log_bins = graph_utils.get_logspace(min_lim, max_lim)
        plt.figure(4)
        plt.hist(incoming_packet_sizes, bins=log_bins, cumulative=True,
                 histtype='step', normed=True, label=label)

        # Plot both packet sizes.
        range = [min(both_packet_sizes), max(both_packet_sizes)]
        print "Overall,"
        print "Range is ", range
        print "Median is ", np.median(both_packet_sizes)
        print "Deviation is ", np.std(both_packet_sizes)
        both_packet_sizes = np.asarray(both_packet_sizes)
        min_lim = min(both_packet_sizes)
        max_lim = max(both_packet_sizes)
        small_diff = (min_lim + max_lim) / 10000.0
        bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), [np.inf])

        plt.figure(5)
        plt.hist(both_packet_sizes, bins=bins, cumulative=True,
                 histtype='step', normed=True, label=label)

        # Plot the log versions.
        log_bins = graph_utils.get_logspace(min_lim, max_lim)
        plt.figure(6)
        plt.hist(both_packet_sizes, bins=log_bins, cumulative=True,
                 histtype='step', normed=True, label=label)

    if args.title:
        plt.figure(1)
        plt.title("From Server: " + args.title)
        plt.figure(2)
        plt.title("From Server: " + args.title)
        plt.figure(3)
        plt.title("From Clients: " + args.title)
        plt.figure(4)
        plt.title("From Clients: " + args.title)
        plt.figure(5)
        plt.title(args.title)
        plt.figure(6)
        plt.title(args.title)

    plt.figure(1)
    plt.ylabel("CDF")
    plt.xlabel("Sizes (B)")
    graph_utils.set_log_x()
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_outgoing_sizes.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    plt.figure(2)
    plt.ylabel("CDF")
    plt.xlabel("Sizes (B)")
    graph_utils.set_log_x()
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_outgoing_sizes_log.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    plt.figure(3)
    plt.ylabel("CDF")
    plt.xlabel("Sizes (B)")
    graph_utils.set_legend_below()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    graph_utils.set_integer_ticks()
    filename = args.output_name + '_incoming_sizes.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    plt.figure(4)
    plt.ylabel("CDF")
    plt.xlabel("Sizes (B)")
    graph_utils.set_log_x()
    graph_utils.set_legend_below()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = args.output_name + '_incoming_sizes_log.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    # Plot the packet sizes for both.
    plt.figure(5)
    plt.ylabel("CDF")
    plt.xlabel("Sizes (B)")
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    graph_utils.set_integer_ticks()
    filename = args.output_name + '_all_sizes.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename

    # Plot the packet sizes for both.
    plt.figure(6)
    plt.ylabel("CDF")
    plt.xlabel("Sizes (B)")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    graph_utils.set_integer_ticks()
    filename = args.output_name + '_all_sizes_log.eps'
    plt.savefig(filename)
    print "Done! File is in ", filename


if __name__ == "__main__":
    main(sys.argv[1:])
