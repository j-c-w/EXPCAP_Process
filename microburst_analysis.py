from decimal import *
import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import graph_utils
import numpy as np
import process_csv
import process_txt
import expcap_metadata


def microburst_analyze(bursts, identifier, pcap_file, label, id_base):
    print identifier, " Number of bursts", len(bursts)
    bins = 1000
    if len(bursts) == 0:
        return

    # Print a CDF of the microburst length distribution:
    lengths = [len(x) for x in bursts]
    bins = np.append(np.linspace(min(lengths), max(lengths), 1000), np.inf)
    plt.figure(1 + id_base)
    plt.hist(lengths, bins=bins, cumulative=True, histtype='step', normed=True, label=label)
    plt.savefig('test.eps')

    # Plot a CDF of the bandwidth achieved in each microburst.
    bandwidths = []
    for burst in bursts:
        start_time = burst[0].wire_start_time
        end_time = burst[len(burst) - 1].wire_end_time

        total_time_in_use = Decimal(sum([packet.wire_length_time for packet in burst]))
        bandwidths.append(Decimal(10000.0) * (total_time_in_use / (end_time - start_time)))

    for i in range(len(bandwidths)):
        bandwidths[i] = float(bandwidths[i])

    plt.figure(2 + id_base)
    bins = np.append(np.linspace(min(bandwidths), max(bandwidths), 1000), np.inf)
    plt.hist(bandwidths, bins=bins, cumulative=True, histtype='step', normed=True, label=label)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--thresholds', dest='thresholds', help="This should be a three-tuple.  The firs tiem should be how long between packets (ps) for sequential packets  to be counted in the same burst.  The second item should be how many packets must arrive before  a bursst starts.  The last item should be a label.", required=True, action='append', nargs=3)
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
        for allowed_ipg, burst_size, label_suffix in args.thresholds:
            ipg_threshold = Decimal(allowed_ipg) / Decimal(1000000000000.0)

            if pcap_file.endswith('.csv'):
                incoming_bursts = \
                        process_csv.find_bursts(pcap_file, ipg_threshold=ipg_threshold, packet_threshold=int(burst_size),
                                                       to_ip=args.server_ip)
                outgoing_bursts  = \
                    process_csv.find_bursts(pcap_file, ipg_threshold=ipg_threshold, packet_threshold=int(burst_size),
                                                   from_ip=args.server_ip)

            #  Handle the incoming information first.
            microburst_analyze(incoming_bursts, str(ipg_threshold) + "_incoming", pcap_file, label + ' ' + label_suffix, 0)
            microburst_analyze(outgoing_bursts, str(ipg_threshold) + "_outgoing", pcap_file, label + ' ' + label_suffix, 2)

    if args.title:
        plt.figure(1)
        plt.title('Client Traffic (Burst Lengths): ')
        plt.figure(2)
        plt.title('Client Traffic (Bandwidths): ')
        plt.figure(3)
        plt.title('Server Traffic (Burst Lengths): ')
        plt.figure(4)
        plt.title('Server Traffic (Bandwidths): ')

    plt.figure(1)
    plt.xlabel("Burst Length (packets)")
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_integer_ticks()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_length_cdf_incoming.eps"
    plt.savefig(filename)
    print "Output in ", args.output_name + "_burst_length_cdf_incoming.eps"

    plt.figure(2)
    plt.xlabel("Burst Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_bandwidth_cdf_incoming"
    plt.savefig(filename + '.eps')
    print "Output in ", args.output_name + "_burst_bandwidth_cdf_incoming.eps"

    plt.figure(3)
    plt.xlabel("Burst Length (packets)")
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_integer_ticks()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_length_bandwidth_outgoing.eps"
    plt.savefig(filename)
    print "Output in ", args.output_name + "_burst_length_bandwidth_outgoing.eps"

    plt.figure(4)
    plt.xlabel("Burst Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.legend_bottom_right()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_bandwidth_cdf_outgoing.eps"
    plt.savefig(filename)
    print "Output in ", args.output_name + "_burst_bandwidth_cdf_outgoing.eps"
