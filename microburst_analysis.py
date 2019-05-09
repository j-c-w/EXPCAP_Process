from decimal import *
import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import process_csv
import process_txt
import process_pcap
import expcap_metadata


def microburst_analyze(bursts, identifier, pcap_file):
    print identifier, " Number of bursts", len(bursts)
    bins = 1000
    if len(bursts) == 0:
        return

    # Print a CDF of the microburst length distribution:
    lengths = [len(x) for x in bursts]
    plt.clf()
    plt.hist(lengths, bins=bins, cumulative=True, histtype='step', normed=True)
    plt.xlabel("Burst Length (packets)")
    plt.ylabel("CDF")
    plt.title("Cumlative Frequency Distribution of Burst Lengths")
    plt.savefig(pcap_file + "burst_length_cdf_" + identifier + ".eps")

    # Plot a CDF of the bandwidth achieved in each microburst.
    bandwidths = []
    for burst in bursts:
        start_time = burst[0].wire_start_time
        end_time = burst[len(burst) - 1].wire_end_time

        total_time_in_use = Decimal(sum([packet.wire_length_time for packet in burst]))
        bandwidths.append(Decimal(10000.0) * (total_time_in_use / (end_time - start_time)))

    for i in range(len(bandwidths)):
        bandwidths[i] = float(bandwidths[i])
    print bandwidths

    plt.clf()
    plt.hist(bandwidths, bins=bins, cumulative=True, histtype='step', normed=True)
    plt.xlabel("Burst Bandwidth (Mbps)")
    plt.ylabel("CDF")
    plt.title("Cumlative Frequency Distribution of Burst Bandwidths")
    plt.savefig("burst_length_bandwidth_" + identifier + ".eps")



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file')
    parser.add_argument('--ipg-threshold', type=int, dest='ipg_threshold', help="How long between packets (ps) for sequential packets  to be counted in the same burst.", required=True)
    parser.add_argument('--packet-threshold', type=int, dest='packet_threshold', help="How many packets must arrive before  a bursst starts", required=True)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True, help="IP of the machine that the card is directory connected to")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file
    ipg_threshold = Decimal(args.ipg_threshold) / Decimal(1000000000000.0)

    if pcap_file.endswith('.csv'):
        incoming_bursts = \
                process_csv.find_bursts(pcap_file, ipg_threshold=ipg_threshold, packet_threshold=args.packet_threshold,
                                               to_ip=args.server_ip)
        outgoing_bursts  = \
            process_csv.find_bursts(pcap_file, ipg_threshold=ipg_threshold, packet_threshold=args.packet_threshold,
                                           from_ip=args.server_ip)

    #  Handle the incoming information first.
    microburst_analyze(incoming_bursts, str(ipg_threshold) + "_incoming", pcap_file)
    microburst_analyze(outgoing_bursts, str(ipg_threshold) + "_outgoing", pcap_file)
