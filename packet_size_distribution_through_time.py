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
    parser.add_argument('--window-size', nargs=2, dest='window_size', action='append', help="How long to average over.  In ps. (Also needs a label)", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True, help="IP of the machine that the card is directory connected to")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title', required=False, default=None)
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    server_graph = plt.figure(1)
    client_graph = plt.figure(2)
    all_graph = plt.figure(3)

    for pcap_file, label in args.input_files:
        for (window, window_label) in args.window_size:
            if pcap_file.endswith('.csv'):
                server_windows, server_packet_sizes = \
                    process_csv.extract_sizes_by_window(pcap_file, window, from_ip=args.server_ip)
                client_windows, client_packet_sizes = \
                    process_csv.extract_sizes_by_window(pcap_file, window, to_ip=args.server_ip)
                all_windows, all_packet_sizes = \
                    process_csv.extract_sizes_by_window(pcap_file, window)

            # Print the server graph
            median_sizes = [np.median(x) for x in server_packet_sizes]
            server_windows = [x[0] for x in server_windows]
            # Recenter the values around zero.
            for i in range(1, len(server_windows)):
                server_windows[i] = server_windows[i] - server_windows[0]
            server_windows[0] = 0.0
            plt.figure(1)
            plt.plot(server_windows, median_sizes, label=label + ' ' + window_label)

            # Print the client graph
            median_sizes = [np.median(x) for x in client_packet_sizes]
            client_windows = [x[0] for x in client_windows]
            # Recenter the values around zero.
            for i in range(1, len(client_windows)):
                client_windows[i] = client_windows[i] - client_windows[0]
            client_windows[0] = 0.0
            plt.figure(2)
            plt.plot(client_windows, median_sizes, label=label + ' ' + window_label)

            # Print the graph of everything else.
            median_sizes = [np.median(x) for x in all_packet_sizes]
            all_windows = [x[0] for x in all_windows]
            # Recenter the values around zero.
            for i in range(1, len(all_windows)):
                all_windows[i] = all_windows[i] - all_windows[0]
            all_windows[0] = 0.0
            plt.figure(3)
            plt.plot(all_windows, median_sizes, label=label + ' ' + window_label)

    if args.title:
        plt.figure(1)
        plt.title("Traffic from server: " + args.title)
        plt.figure(2)
        plt.title("Traffic to server: " + args.title)
        plt.figure(3)
        plt.title(args.title)

    # Output the server graph.
    plt.figure(1)
    plt.ylabel("Median Packet Size")
    plt.xlabel("Time (s)")
    plt.legend()
    graph_utils.set_ticks()
    graph_utils.set_non_negative_axes()
    plt.savefig(args.output_name + '_server_sizes_through_time.eps', format='eps')
    print "Done! File is in ", args.output_name + '_server_sizes_through_time.eps'

    # Output the client graph.
    plt.figure(2)
    plt.ylabel("Median Packet Size")
    plt.xlabel("Time (s)")
    plt.legend()
    graph_utils.set_ticks()
    graph_utils.set_non_negative_axes()
    plt.savefig(args.output_name + '_client_sizes_through_time.eps', format='eps')
    print "Done! File is in ", args.output_name + '_client_sizes_through_time.eps'

    # Output the overall graph.
    plt.figure(3)
    plt.ylabel("Median Packet Size")
    plt.xlabel("Time (s)")
    plt.legend()
    graph_utils.set_ticks()
    graph_utils.set_non_negative_axes()
    plt.savefig(args.output_name + '_all_times.eps', format='eps')
    print "Done! File is in ", args.output_name + '_all_times.eps'
