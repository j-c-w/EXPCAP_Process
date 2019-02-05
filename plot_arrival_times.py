import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import os
import process_txt
import subprocess

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('input_file')
    parser.add_argument('--packets', type=int,
                        help='Number of packets to process',
                        required=False, dest='packets',
                        default=None)

    args = parser.parse_args()

    temp_file_generated = False
    input_file = args.input_file
    if input_file.endswith('.pcap'):
        input_file = process_txt.create_txt_from_pcap(input_file)
        temp_file_generate = True

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
