import argparse
import numpy as np
import process_csv
import process_txt
import process_pcap
import sys

def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('file')

    args = parser.parse_args(args)
    file = args.file

    if file.endswith('.pcap'):
        times = process_pcap.extract_deltas(file)
    elif file.endswith('.csv'):
        times = process_csv.extract_deltas(file)
    else:
        times = process_txt.extract_deltas(file)

    print "Mean delta: ", np.mean(times), ", Median delta: ", np.median(times),
    print ", deviation: ", np.std(times)


if __name__ == "__main__":
    main(sys.argv[1:])
