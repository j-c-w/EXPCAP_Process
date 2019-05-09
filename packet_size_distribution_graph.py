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
    parser.add_argument('--input-file', dest='input_files', nargs=2, action='append', required=True, help="csv file to plot.  Needs a label as a second argument.")
    parser.add_argument('--keep-temps', dest='keep_temps', default=False, action='store_true', help="Keep temp files")
    # This is to avoid issues with tcpdump hanging.
    parser.add_argument('--packets', type=int, required=False,
            default=None, dest='packets',
            help="Number of packets to process from a pcap file")
    parser.add_argument('--output-name', dest='output_name', required=True)
    parser.add_argument('--title', dest='title', required=False, default=None)

    args = parser.parse_args()

    for (pcap_file, label) in args.input_files:
        if pcap_file.endswith('.csv'):
            packet_sizes = process_csv.extract_sizes(pcap_file)

        range = [min(packet_sizes), max(packet_sizes)]
        print "Range is ", range
        print "Median is ", np.median(packet_sizes)
        print "Deviation is ", np.std(packet_sizes)
        packet_sizes = np.asarray(packet_sizes)

        bins = np.append(np.linspace(min(packet_sizes), max(packet_sizes), 1000), np.inf)
        plt.hist(packet_sizes, bins=bins, cumulative=True, histtype='step', normed=True, label=label)

    if args.title:
        plt.title(args.title)

    plt.ylabel("Fraction of Packets")
    plt.xlabel("Sizes (B)")
    plt.savefig(args.output_name + '_sizes.eps', format='eps')
    print "Done! File is in ", args.output_name + '_sizes.eps'
