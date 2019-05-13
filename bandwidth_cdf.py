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
    parser.add_argument('--window-size', nargs=2, action='append', dest='window_size', help="How long to average over.  In ps.", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True, help="IP of the machine that the card is directory connected to")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title')
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    for pcap_file, label in args.input_files:
        for window_size, label_suffix in args.window_size:
            if pcap_file.endswith('.csv'):
                incoming_x_values, incoming_bandwidths = \
                        process_csv.extract_bandwidths(pcap_file, window_size,
                                                       to_ip=args.server_ip)
                outgoing_x_values, outgoing_bandwidths = \
                    process_csv.extract_bandwidths(pcap_file, window_size,
                                                   from_ip=args.server_ip)

            for i in range(len(incoming_bandwidths)):
                incoming_bandwidths[i] = float(incoming_bandwidths[i])

            bins = np.append(np.linspace(min(incoming_bandwidths), max(incoming_bandwidths), 1000), np.inf)
            plt.figure(1)
            plt.hist(incoming_bandwidths, cumulative=True, bins=bins, histtype='step', normed=True, label=label + ' ' + label_suffix)

            for i in range(len(outgoing_bandwidths)):
                outgoing_bandwidths[i] = float(outgoing_bandwidths[i])
            bins = np.append(np.linspace(min(outgoing_bandwidths), max(outgoing_bandwidths), 1000), np.inf)
            plt.figure(2)
            plt.hist(outgoing_bandwidths, cumulative=True, bins=bins, histtype='step', normed=True, label=label + ' ' + label_suffix)

    if args.title:
        plt.figure(1)
        plt.title('Client Traffic: ' + args.title)
        plt.figure(2)
        plt.title('Server Traffic: ' + args.title)

    plt.figure(1)
    plt.xlabel("Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_incoming_bandwidth_cdf_window'
    plt.savefig(filename)
    print "Done! File is in ", filename
    plt.figure(2)
    plt.xlabel("Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + '_outgoing_bandwidth_cdf_window'
    plt.savefig(filename)
    print "Done! File is in ", filename
