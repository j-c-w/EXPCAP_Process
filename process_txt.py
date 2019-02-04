from statistics import mean, median
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


def extract_deltas(file):
    list_of_timestamps = []
    list_of_timestamp_deltas = []

    with open(file) as f:
        for line in f:
            list_of_timestamps.append(line.split(' ', 1)[0])

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
            difference = float(current_timestamp) - float(prev_timestamp)
            list_of_timestamp_deltas.append(difference)

    return list_of_timestamp_deltas



if __name__ == "__main__":
    myfunction()
