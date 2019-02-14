import dpkt

def extract_times(file):
    times = []
    with open(file) as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            times.append(ts)

    return times


def extract_detlas(file):
    times = extract_times(file)

    last_time = times[0]
    deltas = []
    for time in times[1:]:
        deltas.append(time - last_time)
        last_time = time

    return deltas
