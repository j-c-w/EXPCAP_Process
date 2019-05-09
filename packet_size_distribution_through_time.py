import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import process_csv
import process_txt
import process_pcap
import expcap_metadata

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file')
    parser.add_argument('--window', type=int, dest='window', help="Window size (ps)", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True, help="IP of the machine that the card is directory connected to")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file
    window = args.window

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
    plt.plot(server_windows, median_sizes)
    plt.ylabel("Median Packet Size")
    plt.xlabel("Time (s)")
    plt.title("Median Packet Sizes through Time")
    plt.savefig(pcap_file + '_server_sizes_through_time.eps', format='eps')
    print "Done! File is in ", pcap_file + '_sizes_through_time.eps'

    # Print the client graph
    median_sizes = [np.median(x) for x in client_packet_sizes]
    client_windows = [x[0] for x in client_windows]
    plt.plot(client_windows, median_sizes)
    plt.title("Median Packet Sizes through Time")
    plt.ylabel("Median Packet Size")
    plt.xlabel("Time (s)")
    plt.savefig(pcap_file + '_client_sizes_through_time.eps', format='eps')
    print "Done! File is in ", pcap_file + '_sizes_through_time.eps'

    # Print the graph of everything else.
    median_sizes = [np.median(x) for x in all_packet_sizes]
    all_windows = [x[0] for x in all_windows]
    plt.plot(all_windows, median_sizes)
    plt.title("Median Packet Sizes through Time")
    plt.ylabel("Median Packet Size")
    plt.ylabel("Median Packet")
    plt.xlabel("Time (s)")
    plt.savefig(pcap_file + '_sizes_through_time.eps', format='eps')
    print "Done! File is in ", pcap_file + '_sizes_through_time.eps'
