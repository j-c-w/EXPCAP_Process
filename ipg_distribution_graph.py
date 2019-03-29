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
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")

    args = parser.parse_args()

    pcap_file = args.input_file

    if pcap_file.endswith('.csv'):
        ipg_gaps = process_csv.extract_ipgs(pcap_file)

    range = [min(ipg_gaps), max(ipg_gaps)]
    print "Range is ", range
    print "Median is ", np.median(ipg_gaps)
    print "Deviation is ", np.std(ipg_gaps)

    # Before we plot these, they need to be converted to normal
    # floats.  To do this, multiply by 10**6
    for i in xrange(len(ipg_gaps)):
        ipg_gaps[i] = float(Decimal(1000000.0) * ipg_gaps[i])
        print ipg_gaps[i]

    # Remove anything greater than the 99th percentile to stop
    # if affecting the bins.
    i = 0
    nintyninth_percentile = np.percentile(ipg_gaps, 99)
    while i < len(ipg_gaps):
        if ipg_gaps[i] > nintyninth_percentile:
            del ipg_gaps[i]
        else:
            i += 1

    print nintyninth_percentile
    bins = 100
    plt.hist(ipg_gaps, bins=bins, cumulative=True, histtype='step', normed=True)
    plt.xlim([min(ipg_gaps), nintyninth_percentile])
    plt.ylabel("Fraction of Packets")
    plt.xlabel("IPG (ps)")
    plt.savefig(pcap_file + '_ipg_gaps.eps', format='eps')
    print "Done! File is in ", pcap_file + '_ipg_gaps.eps'
