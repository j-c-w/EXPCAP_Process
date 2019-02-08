import argparse
import numpy as np
import os
import process_txt

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('file')

    args = parser.parse_args()
    file = args.file

    delete_when_done = False
    if file.endswith('.pcap'):
        process_txt.create_txt_from_pcap(file)
        file = file + '.txt'
        delete_when_done = True

    times = process_txt.extract_deltas(file)

    print "Mean delta: ", np.mean(times), ", Median delta: ", np.median(times),
    print ", deviation: ", np.std(times)

    if delete_when_done:
        os.remove(file)
