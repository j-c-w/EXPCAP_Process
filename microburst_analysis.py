from decimal import *
import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import graph_utils
import numpy as np
import process_csv
import sys

MICROBURST_DEBUG = False

def microburst_analyze(bursts, identifier, pcap_file, label, id_base):
    print identifier, " Number of bursts", len(bursts)
    bins = 1000
    if len(bursts) == 0:
        return

    # Print a CDF of the microburst length distribution:
    lengths = [len(x) for x in bursts]
    min_lim = min(lengths)
    max_lim = max(lengths)
    small_diff = (min_lim + max_lim) / 10000.0
    bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), np.inf)
    plt.figure(1 + id_base)
    plt.hist(lengths, bins=bins, cumulative=True, histtype='step', normed=True, label=label)

    # Do the same, but with a log scale:
    non_zero_lengths = graph_utils.no_zeroes(lengths)
    if len(non_zero_lengths) > 0:
        plt.figure(2 + id_base)
        min_lim = min(non_zero_lengths)
        max_lim = max(non_zero_lengths)

        bins = graph_utils.get_logspace(min_lim, max_lim)
        plt.hist(non_zero_lengths, bins=bins, cumulative=True, histtype='step', normed=True, label=label)


    # Plot a CDF of the bandwidth achieved in each microburst.
    bandwidths = []
    for burst in bursts:
        start_time = burst[0].wire_start_time()
        end_time = burst[len(burst) - 1].wire_end_time()
        total_time_in_use = Decimal(sum([packet.wire_length_time() for packet in burst]))
        bandwidths.append(Decimal(10000.0) * (total_time_in_use / (end_time - start_time)))
        if MICROBURST_DEBUG:
            for packet in burst:
                print "Packet time is ", packet.wire_start_time()
                print "Packet size is ", packet.length
                print "Packet end time is ", packet.wire_end_time()
            print "Time in use", total_time_in_use
            print "Total time is ", end_time - start_time
            print "Usage is ", bandwidths[-1]

    for i in range(len(bandwidths)):
        bandwidths[i] = float(bandwidths[i])

    plt.figure(3 + id_base)
    min_lim = min(bandwidths)
    max_lim = max(bandwidths)
    small_diff = (min_lim + max_lim) / 10000.0
    bins = np.append(np.linspace(min_lim, max_lim + small_diff, 1000), np.inf)
    plt.hist(bandwidths, bins=bins, cumulative=True, histtype='step', normed=True, label=label)

    # And do the logarithmic version.
    non_zero_bandwidths = graph_utils.no_zeroes(bandwidths)
    if len(non_zero_bandwidths) > 0:
        min_lim = min(non_zero_bandwidths)
        max_lim = max(non_zero_bandwidths)
        bins = graph_utils.get_logspace(min_lim, max_lim)
        plt.figure(4 + id_base)
        plt.hist(non_zero_bandwidths, bins=bins, cumulative=True, histtype='step', normed=True, label=label)
    else:
        print "There were non non-zero bandwidths!"



def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--thresholds', dest='thresholds', help="This should be a three-tuple.  The firs tiem should be how long between packets (ps) for sequential packets  to be counted in the same burst.  The second item should be how many packets must arrive before  a bursst starts.  The last item should be a label.", required=True, action='append', nargs=3)
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=False, default=None, help="IP of the machine that the card is directory connected to")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title')
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
    plt.figure(5)
    plt.clf()
    plt.figure(6)
    plt.clf()
    plt.figure(7)
    plt.clf()
    plt.figure(8)
    plt.clf()

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
            microburst_analyze(outgoing_bursts, str(ipg_threshold) + "_outgoing", pcap_file, label + ' ' + label_suffix, 4)

    if args.title:
        plt.figure(1)
        plt.title('Client Traffic (Burst Lengths): ')
        plt.figure(2)
        plt.title('Client Traffic (Burst Lengths): ')
        plt.figure(3)
        plt.title('Client Traffic (Bandwidths): ')
        plt.figure(4)
        plt.title('Client Traffic (Bandwidths): ')
        plt.figure(5)
        plt.title('Server Traffic (Burst Lengths): ')
        plt.figure(6)
        plt.title('Server Traffic (Burst Lengths): ')
        plt.figure(7)
        plt.title('Server Traffic (Bandwidths): ')
        plt.figure(8)
        plt.title('Server Traffic (Bandwidths): ')

    plt.figure(1)
    plt.xlabel("Burst Length (packets)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_integer_ticks()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_length_cdf_incoming.eps"
    plt.savefig(filename)
    print "Output in ", filename

    plt.figure(2)
    plt.xlabel("Burst Length (packets)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_integer_ticks()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_length_cdf_incoming_log.eps"
    plt.savefig(filename)
    print "Output in ", filename

    plt.figure(3)
    plt.xlabel("Burst Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_bandwidth_cdf_incoming.eps"
    plt.savefig(filename)
    print "Output in ", filename

    plt.figure(4)
    plt.xlabel("Burst Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_bandwidth_cdf_incoming_log.eps"
    plt.savefig(filename)
    print "Output in ", filename

    plt.figure(5)
    plt.xlabel("Burst Length (packets)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_integer_ticks()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_length_bandwidth_outgoing.eps"
    plt.savefig(filename)
    print "Output in ", filename

    plt.figure(6)
    plt.xlabel("Burst Length (packets)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_yax_max_one()
    graph_utils.set_non_negative_axes()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_length_bandwidth_outgoing_log.eps"
    plt.savefig(filename)
    print "Output in ", filename

    plt.figure(7)
    plt.xlabel("Burst Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_bandwidth_cdf_outgoing.eps"
    plt.savefig(filename)
    print "Output in ", filename

    plt.figure(8)
    plt.xlabel("Burst Bandwidth (Mbps)")
    plt.ylabel("CDF")
    graph_utils.set_legend_below()
    graph_utils.set_log_x()
    graph_utils.set_non_negative_axes()
    graph_utils.set_yax_max_one()
    graph_utils.set_ticks()
    filename = args.output_name + "_burst_bandwidth_cdf_outgoing_log.eps"
    plt.savefig(filename)
    print "Output in ", filename


if __name__ == "__main__":
    main(sys.argv[1:])
