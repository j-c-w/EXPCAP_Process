import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import process_csv
import graph_utils
import sys

def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--window-size', nargs=2, dest='window_size', action='append', help="How long to average over.  In ps. (Also needs a label)", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True, help="IP of the machine that the card is directory connected to")
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

    for (pcap_file, label) in args.input_files:
        for (window_size, label_suffix) in args.window_size:

            if pcap_file.endswith('.csv'):
                incoming_x_values, incoming_bandwidths = \
                        process_csv.extract_bandwidths(pcap_file, window_size,
                                                       to_ip=args.server_ip)
                outgoing_x_values, outgoing_bandwidths = \
                    process_csv.extract_bandwidths(pcap_file, window_size,
                                                   from_ip=args.server_ip)

            #  Handle the outgoing information first.
            # Recenter the xvalues around zero.
            zero_value = outgoing_x_values[0][0]
            for i in range(len(outgoing_x_values)):
                outgoing_x_values[i] = float(outgoing_x_values[i][0] - zero_value)

            #  Handle the incoming information next.
            # Recenter the xvalues around zero.
            zero_value = incoming_x_values[0][0]
            for i in range(len(incoming_x_values)):
                incoming_x_values[i] = float(incoming_x_values[i][0] - zero_value)

            if len(incoming_x_values) < 3000000:
                plt.figure(2)
                plt.plot(incoming_x_values, incoming_bandwidths, label=label + ' ' + label_suffix)
            else:
                print "Error: Skipping line ", label + ' ' + label_suffix, " because it has more than  3 million entries."

            if len(outgoing_x_values) < 3000000:
                plt.figure(1)
                plt.plot(outgoing_x_values, outgoing_bandwidths, label=label + ' ' + label_suffix)
            else:
                print "Error: Skipping line ", label + ' ' + label_suffix, " because it has more than  3 million entries."

    if args.title:
        plt.figure(1)
        plt.title('Server Traffic: ' + args.title)
        plt.figure(2)
        plt.title('Client Traffic: ' + args.title)

    label_count = len(args.input_files) * len(args.window_size)
    graph_utils.latexify(bottom_label_rows=label_count / 2)

    plt.figure(2)
    plt.xlabel("Time (s)")
    plt.ylabel("Bandwidth (Mbps)")
    graph_utils.set_ticks()
    graph_utils.set_non_negative_axes()
    graph_utils.set_legend_below()
    filename = args.output_name + '_incoming_bandwidth_windowed.eps'
    plt.savefig(filename, format='eps')
    print "Done! File is in ", filename

    plt.figure(1)
    plt.xlabel("Time (s)")
    plt.ylabel("Bandwidth (Mbps)")
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    graph_utils.set_legend_below()
    filename = args.output_name + '_outgoing_bandwidth_windowed.eps'

    plt.savefig(filename, format='eps')
    print "Done! File is in ", filename


if __name__ == "__main__":
    main(sys.argv[1:])
