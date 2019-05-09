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
    parser.add_argument('--window-size', type=int, dest='window_size', help="How long to average over.  In ps.", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True, help="IP of the machine that the card is directory connected to")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file
    window_size = args.window_size

    if pcap_file.endswith('.csv'):
        incoming_x_values, incoming_bandwidths = \
                process_csv.extract_bandwidths(pcap_file, window_size,
                                               to_ip=args.server_ip)
        outgoing_x_values, outgoing_bandwidths = \
            process_csv.extract_bandwidths(pcap_file, window_size,
                                           from_ip=args.server_ip)

    #  Handle the incoming information first.
    # Recenter the xvalues around zero.
    zero_value = incoming_x_values[0][0]
    for i in range(len(incoming_x_values)):
        incoming_x_values[i] = incoming_x_values[i][0] - zero_value

    plt.plot(incoming_x_values, incoming_bandwidths)
    plt.xlabel("Bandwidth (Mbps)")
    plt.title("Cumlative Distribution of Bandwidth Used")
    plt.ylabel("Fraction of Time")
    filename = pcap_file + '_incoming_bandwidth_cdf_window_' + str(window_size) + '.eps'
    plt.savefig(filename, format='eps')
    print "Done! File is in ", filename

    #  Handle the outgoing information first.
    # Recenter the xvalues around zero.
    zero_value = outgoing_x_values[0][0]
    for i in range(len(outgoing_x_values)):
        outgoing_x_values[i] = outgoing_x_values[i][0] - zero_value

    plt.plot(outgoing_x_values, outgoing_bandwidths)
    plt.xlabel("Bandwidth (Mbps)")
    plt.title("Cumlative Distribution of Bandwidth Used")
    plt.ylabel("Fraction of Time")
    filename = pcap_file + '_outgoing_bandwidth_cdf_window_' + str(window_size) + \
        '.eps'
    plt.savefig(filename, format='eps')
    print "Done! File is in ", filename
