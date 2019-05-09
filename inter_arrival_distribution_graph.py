import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import process_csv
import process_txt
import process_pcap

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file')
    parser.add_argument('--bins', type=int, dest='bins', help="Number of bins", default=1000)
    parser.add_argument('--server', dest='server_ip', help="The IP address of the server", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file

    if pcap_file.endswith('.csv'):
        timestamp_deltas_incoming = \
            process_csv.extract_deltas(pcap_file, to_ip=args.server_ip)
        timestamp_deltas_outgoing = \
            process_csv.extract_deltas(pcap_file, from_ip=args.server_ip)

    # Convert to ns before starting:
    for i in range(len(timestamp_deltas_incoming)):
        timestamp_deltas_incoming[i] = 1000000000.0 * timestamp_deltas_incoming[i]
    for i in range(len(timestamp_deltas_outgoing)):
        timestamp_deltas_outgoing[i] = 1000000000.0 * timestamp_deltas_outgoing[i]

    # Do the outgoing packets.
    range = [min(timestamp_deltas_outgoing), max(timestamp_deltas_outgoing)]
    print "Range is ", range
    print "Median is ", np.median(timestamp_deltas_outgoing)
    print "Deviation is ", np.std(timestamp_deltas_outgoing)
    timestamp_deltas_outgoing = np.asarray(timestamp_deltas_outgoing, dtype='float')

    plt.hist(timestamp_deltas_outgoing, bins=args.bins, cumlative=True,
             histype='step', normed=True)
    plt.ylabel("Number of Packets")
    plt.xlabel("Inter-arrival time (ns)")
    plt.savefig(pcap_file + '_outgoing_interarrival.eps', format='eps')
    print "Done! File is in ", pcap_file + '_outgoing_interarrival.eps'

    # Do the incoming packets.
    range = [min(timestamp_deltas_incoming), max(timestamp_deltas_incoming)]
    print "Incoming Range is ", range
    print "Incoming Median is ", np.median(timestamp_deltas_incoming)
    print "Incoming Deviation is ", np.std(timestamp_deltas_incoming)
    timestamp_deltas_incoming = np.asarray(timestamp_deltas_incoming, dtype='float')

    plt.hist(timestamp_deltas_incoming, bins=args.bins)
    plt.ylabel("Number of Packets")
    plt.xlabel("Inter-arrival time (ns)")
    plt.title("Cumlative Distribution of Inter-Packet Gaps")
    plt.savefig(pcap_file + '_incoming_interarrival.eps', format='eps')
    print "Done! File is in ", pcap_file + '_incoming_interarrival.eps'
