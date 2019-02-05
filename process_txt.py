from statistics import mean, median
import subprocess
import sys
# this package is available in python >= 3.4

input_file_name = "/home/murali/Code/process_pcap_traces/pcap_txt.txt"

# tcpdump -tt -r client_05_1.cap -c 100 > pcap_txt.txt
# use that command to extract txt output from pcap file
# -tt is for unix timestamp
# -c is upper limit on number of packets to read


def myfunction():
    list_of_timestamp_deltas = extract_deltas(input_file_name)
    avg_ipg = mean(list_of_timestamp_deltas)
    median_ipg = median(list_of_timestamp_deltas)

    print('ipg: average is %s and median is %s ' % (avg_ipg, median_ipg))


def create_txt_from_pcap(pcap_file, number_of_packets=None):
    command = ['./field_from_pcap.sh', pcap_file, pcap_file + '.txt', '',
               '-tt']
    if number_of_packets:
        command += ['-c', number_of_packets]
    result = subprocess.call(command)
    if result != 0:
        print "Error extracting TXT file"
        sys.exit(1)

    pcap_file = pcap_file + '.txt'
    return pcap_file


def float_from_timestamp(timestamp, decimal_figs=9):
    int_part = timestamp.split(".")[0]
    float_part = timestamp.split(".")[1]

    if len(float_part) < decimal_figs:
        float_part = ("0" * (decimal_figs - len(float_part))) + float_part
    if decimal_figs < len(float_part):
        print "Expecting to find ", decimal_figs, "figures"
        print "But found ", len(float_part), "figures"
        sys.exit(1)

    return float(int_part + "." + float_part)


def extract_deltas(file):
    list_of_timestamps = extract_times(file)
    list_of_timestamp_deltas = []

    first_timestamp = True
    current_timestamp = 0
    prev_timestamp = 0
    for timestamp in list_of_timestamps:
        if first_timestamp:
            current_timestamp = timestamp
            first_timestamp = False
        else:
            prev_timestamp = current_timestamp
            current_timestamp = timestamp
            difference = current_timestamp - prev_timestamp
            list_of_timestamp_deltas.append(difference)

    return list_of_timestamp_deltas


def extract_times(file):
    list_of_timestamps = []
    with open(file) as f:
        for line in f:
            list_of_timestamps.append(
                    float_from_timestamp(line.split(' ', 1)[0]))

    return list_of_timestamps


if __name__ == "__main__":
    myfunction()
