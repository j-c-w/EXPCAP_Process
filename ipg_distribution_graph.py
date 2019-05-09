from decimal import Decimal
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
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    parser.add_argument('--server', dest='server_ip', required=True)
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file

    if pcap_file.endswith('.csv'):
        outgoing_ipg_gaps = process_csv.extract_ipgs(pcap_file, from_ip=args.server_ip)
        incoming_ipg_gaps = process_csv.extract_ipgs(pcap_file, to_ip=args.server_ip)

    range = [min(outgoing_ipg_gaps), max(outgoing_ipg_gaps)]
    print "Range is ", range
    print "Median is ", np.median(outgoing_ipg_gaps)
    print "Deviation is ", np.std(outgoing_ipg_gaps)

    # Before we plot these, they need to be converted to normal
    # floats.  To do this, multiply by 10**6
    for i in xrange(len(outgoing_ipg_gaps)):
        outgoing_ipg_gaps[i] = float(Decimal(1000000.0) * outgoing_ipg_gaps[i])
        print outgoing_ipg_gaps[i]

    # Remove anything greater than the 99th percentile to stop
    # if affecting the bins.
    i = 0
    nintyninth_percentile = np.percentile(outgoing_ipg_gaps, 99)
    while i < len(outgoing_ipg_gaps):
        if outgoing_ipg_gaps[i] > nintyninth_percentile:
            del outgoing_ipg_gaps[i]
        else:
            i += 1

    print nintyninth_percentile
    bins = 100
    plt.hist(outgoing_ipg_gaps, bins=bins, cumulative=True, histtype='step', normed=True)
    plt.xlim([min(outgoing_ipg_gaps), nintyninth_percentile])
    plt.ylabel("Fraction of Packets")
    plt.xlabel("IPG (ps)")
    plt.title("Cumlative Frequency Distribution of Inter-Packet Gaps")
    plt.savefig(pcap_file + '_outgoing_ipg_gaps.eps', format='eps')
    print "Done! File is in ", pcap_file + '_outgoing_ipg_gaps.eps'

    # Also do the incoming packets.
    range = [min(incoming_ipg_gaps), max(incoming_ipg_gaps)]
    print "Range is ", range
    print "Median is ", np.median(incoming_ipg_gaps)
    print "Deviation is ", np.std(incoming_ipg_gaps)

    # Before we plot these, they need to be converted to normal
    # floats.  To do this, multiply by 10**6
    for i in xrange(len(incoming_ipg_gaps)):
        incoming_ipg_gaps[i] = float(Decimal(1000000.0) * incoming_ipg_gaps[i])
        print incoming_ipg_gaps[i]

    # Remove anything greater than the 99th percentile to stop
    # if affecting the bins.
    i = 0
    nintyninth_percentile = np.percentile(incoming_ipg_gaps, 99)
    while i < len(incoming_ipg_gaps):
        if incoming_ipg_gaps[i] > nintyninth_percentile:
            del incoming_ipg_gaps[i]
        else:
            i += 1

    print nintyninth_percentile
    bins = 100
    plt.hist(incoming_ipg_gaps, bins=bins, cumulative=True, histtype='step', normed=True)
    plt.xlim([min(incoming_ipg_gaps), nintyninth_percentile])
    plt.ylabel("Fraction of Packets")
    plt.xlabel("IPG (ps)")
    plt.title("Cumlative Frequency Distribution of Inter-Packet Gaps")
    plt.savefig(pcap_file + '_incoming_ipg_gaps.eps', format='eps')
    print "Done! File is in ", pcap_file + '_incoming_ipg_gaps.eps'
