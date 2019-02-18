import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import os
import process_csv
import process_txt
import process_pcap
import subprocess

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('input_file')
    parser.add_argument('--packets', type=int,
                        help='Number of packets to process',
                        required=False, dest='packets',
                        default=None)

    args = parser.parse_args()

    input_file = args.input_file
    if input_file.endswith('.pcap'):
        arrival_times = process_pcap.extract_times(input_file)
    elif input_file.endswith('.csv'):
        arrival_times = process_csv.extract_times(input_file)
    else:
        arrival_times = process_txt.extract_times(input_file)
    x_values = range(0, len(arrival_times))

    last_time = 0
    for index in range(len(arrival_times)):
        time = arrival_times[index]
        if time < last_time:
            print "have time ", time, "at line ", index
        last_time = time

    plt.plot(x_values, arrival_times)
    plt.title("Arrival time")
    plt.xlabel("Packet number")
    plt.ylabel("Absolute Arrival Time")
    plt.savefig(input_file + '_arrival_times.eps', format='eps')
