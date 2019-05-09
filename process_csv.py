from decimal import *
from expcap_metadata import ExpcapPacket
import numpy as np
import os
import sys

# This is a little hack to make loading repeatedly from the same file faster.
last_loaded = None
last_loaded_from = None

def ip_to_hex(ip):
    if len(ip.split('.')) != 4:
        print "Input should be a typical IP address"
        sys.exit(1)

    def extend(string):
        if len(string) < 2:
            string = "0" + string
        return string

    hex_no = ""
    for number in ip.split('.'):
        hex_no += extend(hex(int(number))[2:])

    return hex_no


def windows_list_to_string(windows):
    return ','.join([str(w_start) + '_' + str(w_end)
                     for (w_start, w_end) in windows]) + '\n'


def windows_list_from_string(windows_string):
    windows = []

    for item in windows_string.split(','):
        win_start, win_end = item.split('_')
        windows.append((Decimal(win_start), Decimal(win_end)))

    return windows


def generate_cache_name(input_file, name, to_ip, from_ip, count, window_size=None):
    name = input_file + name

    if to_ip:
        name = name + '_to_ip_' + to_ip
    if from_ip:
        name = name + '_from_ip_' + from_ip
    if count:
        name = name + '_packets_' + count
    if window_size:
        name = name + '_window_size_' + window_size

    return name + '.cache'


def extract_expcap_metadatas(filename, count=None, to_ip=None, from_ip=None):
    global last_loaded
    global last_loaded_from

    if filename == last_loaded_from:
        # Clone the last loaded list and send it back if this is the same
        # file as before.
        metadata = last_loaded[:]
    else:
        with open(filename) as f:
            if count:
                lines = f.readlines()[1:count]
            else:
                lines = f.readlines()[1:]

            metadata = []
            for line in lines:
                expcap_packet = ExpcapPacket(line)
                if expcap_packet.padding_packet or not expcap_packet.fully_processed_ip:
                    print "Not adding packet"
                    continue
                metadata.append(expcap_packet)

        metadata.sort(key=lambda x: x.start_time)
        last_loaded = metadata[:]
        last_loaded_from = filename

    if to_ip:
        index = 0
        hex_ip = ip_to_hex(to_ip)
        while index < len(metadata):
            if metadata[index].dst_addr != hex_ip:
                del metadata[index]
            else:
                index += 1

    if from_ip:
        index = 0
        hex_ip = ip_to_hex(from_ip)
        while index < len(metadata):
            if metadata[index].src_addr != hex_ip:
                del metadata[index]
            else:
                index += 1

    print "Using ", len(metadata), "packets"
    return metadata


def extract_sizes(filename, count=None, to_ip=None, from_ip=None):
    cache_name = generate_cache_name(filename, '_sizes_list', to_ip, from_ip, count)
    if os.path.exists(cache_name):
        with open(cache_name) as f:
            sizes = f.readlines()[0].split(',')
            return [int(size) for size in sizes]

    metadatas = extract_expcap_metadatas(filename, count, to_ip=to_ip,
                                         from_ip=from_ip)
    sizes = []
    for expcap_packet in metadatas:
        sizes.append(expcap_packet.length)

    with open(cache_name, 'w') as f:
        f.write(','.join([str(size) for size in sizes]))
    return sizes



""" This finds bursts by finding packet_threshold number
of packets that are all at most ipg_threshold (in ps)
apart.

It returns a list of lists of packet bursts.

We don't try to cache bursts.  They are usually used for further
processing anyway.  This function returns the whole
packet at each stage.
"""
def find_bursts(filename, count=None, ipg_threshold=20000, packet_threshold=20, to_ip=None, from_ip=None):
    metadatas = extract_expcap_metadatas(filename, count=count, to_ip=to_ip, from_ip=from_ip)

    time = metadatas[0].wire_start_time
    burst_count = 0
    current_burst = []
    bursts = []
    for packet in metadatas[1:]:
        next_time = packet.wire_start_time

        if next_time - time < ipg_threshold:
            burst_count += 1
            current_burst.append(packet)
        else:
            burst_count = 0
            if len(current_burst) > packet_threshold:
                bursts.append(current_burst)
                current_burst = []
        time = next_time
    
    if len(current_burst) > packet_threshold:
        bursts.append(current_burst)

    return bursts


def extract_ipgs(filename, count=None, to_ip=None, from_ip=None):
    cache_name = generate_cache_name(filename, '_ipgs', to_ip, from_ip, count)
    if os.path.exists(cache_name):
        with open(cache_name) as f:
            return [Decimal(x) for x in (f.readlines()[0].split(','))]
    metadatas = extract_expcap_metadatas(filename, count=count, to_ip=to_ip, from_ip=from_ip)
    ipgs = []
    if len(metadatas) < 2:
        return []
    last_end = metadatas[0].wire_end_time

    for expcap_packet in metadatas[1:]:
        ipgs.append(expcap_packet.wire_end_time - last_end)
        last_end = expcap_packet.wire_end_time

    with open(cache_name, 'w') as f:
        f.write(','.join([str(ipg) for ipg in ipgs]))

    return ipgs


def extract_times(filename, column=7, count=None, to_ip=None, from_ip=None):
    times = []

    cache_name = generate_cache_name(filename, '_times', to_ip, from_ip, count)
    if os.path.exists(cache_name):
        with open(cache_name) as f:
            return [Decimal(x) for x in (f.readlines()[0].split(','))]

    expcap_metadatas = \
        extract_expcap_metadatas(filename, count=count, to_ip=to_ip, from_ip=from_ip)

    for expcap in expcap_metadatas:
        times.append(expcap.wire_start_time)

    with open(cache_name, 'w') as f:
        f.write(','.join([str(time) for time in times]))

    return times


"""
This function takes a filename that represents a CSV file.  The CSV file
should contain Expcap formatted packets.  TBH it could be extended to work
with any capture format that can present the same interface that's present
in expcap metadata.

It returns a pair.  The first element of the pair is a list
of windows.  The second element of the pair is a list of tupes.
The first element of each tuple is what fraction of
each packet it within the window.  The second element
of each tuple is the packet.

There is no cache for these because there is usually some
post-processing anyway.  A cache would have every file
in the trace in it and so would be too big.
"""
def extract_windows(filename, window_size, count=None, to_ip=None, from_ip=None):
    # Note that window_size is in pico seconds, so convert to seconds
    window_size = Decimal(window_size) / Decimal(1000000000000)
    expcap_metadatas = extract_expcap_metadatas(filename, count=count, to_ip=to_ip, from_ip=from_ip)
    debug = False
    packet_groups = []
    windows = []
    
    # First, get the start and end time.  Note that the
    # packets are sorted by arrival time.
    start_time = expcap_metadatas[0].wire_start_time
    end_time = expcap_metadatas[len(expcap_metadatas) - 1].wire_end_time

    # Find the number of iterations we need in the loop.
    iterations = int((end_time - start_time) / window_size)
    if debug:
        print iterations
    # Also, we need to keep the number of windows accurate, so throw away
    # any slice of time that doesn't fit exactly.
    rounding_error = (start_time - end_time) - (Decimal(iterations) * window_size)
    end_time = end_time - rounding_error

    # Keep track of the first relevant packet for each
    # time interval.
    packet_start_index = 0
    for index in range(iterations):
        window_start = start_time + Decimal(index) * window_size
        window_end = window_start + window_size
        # Get all the packets in this range:
        packet_end_index = packet_start_index
        while packet_end_index < len(expcap_metadatas) and \
                expcap_metadatas[packet_end_index].wire_end_time < window_end:
            packet_end_index += 1

        # If we've gone past the end, teh last packet is clearly just
        # the last one in the list.
        if packet_end_index == len(expcap_metadatas):
            packet_end_index -= 1

        # Now, compute how much of the window is filled with
        # packets.  There are edge cases at the start
        # and end.

        packets_in_window = []
        if expcap_metadatas[packet_start_index].wire_end_time < window_start:
            # The packet is entirely before the start of the window.
            pass
        elif expcap_metadatas[packet_start_index].wire_start_time < window_start:
            # The packet starts before the window, so chop that off.
            fraction_in_window = (window_start - expcap_metadatas[packet_start_index].wire_start_time) / expcap_metadatas[packet_start_index].wire_length_time
            packets_in_window.append((fraction_in_window,
                                      expcap_metadatas[packet_start_index]))
            if debug:
                print "wire end time first packet"
        else:
            packets_in_window.append((Decimal(1.0), expcap_metadatas[packet_start_index]))
            if debug:
                print "wire length time first packet"

        # Loop over all but the last packet, which we don't want to include
        # in the calculation because it may be chopped out of the region.
        for index in range(packet_start_index + 1, packet_end_index):
            # These packets will be entirely in the window, so
            # they fraction 1.0 in the window
            packets_in_window.append((Decimal(1.0), expcap_metadatas[index]))

        # The last packet might only be partially in the window.
        if expcap_metadatas[packet_end_index].wire_start_time >  window_end:
            # The packet is entirely outside the window.
            pass
        elif expcap_metadatas[packet_end_index].wire_end_time > window_end:
            if debug:
                print "wire start time last packet"
            fraction_in_window = (expcap_metadatas[packet_end_index].wire_end_time - window_end) / expcap_metadatas[packet_end_index].wire_length_time
            packets_in_window.append((fraction_in_window, expcap_metadatas[packet_end_index]))
        else:
            if debug:
                print "Wire length time last packet"
            packets_in_window.append((Decimal(1.0), expcap_metadatas[packet_end_index]))

        # Make the rate calculation here:
        packet_groups.append(packets_in_window)
        windows.append((window_start, window_end))

        # For the next iteration, the starting packet is the same as the last
        # one on this iteration.
        packet_start_index = packet_end_index

    return (windows, packet_groups)


def extract_bandwidths(filename, window_size, count=None, to_ip=None, from_ip=None):
    cache_name = generate_cache_name(filename, '_bandwidths', to_ip, from_ip, count, window_size=str(window_size))
    if os.path.exists(cache_name):
        with open(cache_name) as f:
            lines = f.readlines()
            windows = windows_list_from_string(lines[0])
            usages = [Decimal(x) for x in (lines[1].split(','))]

            return (windows, usages)

    (windows, packets) = extract_windows(filename, window_size, count=count,
                                         to_ip=to_ip, from_ip=from_ip)

    usages = []
    # For each window, go through and sum the total
    # fraction of time the window is in use.
    for i in range(len(windows)):
        (window_start, window_end) = windows[i]
        total_window_time = window_end - window_start
        time_used = Decimal(0.0)
        for (fraction, packet) in packets[i]:
            time_used += fraction * packet.wire_length_time

        usages.append(time_used / total_window_time)

    with open(cache_name, 'w') as f:
        f.write(windows_list_to_string(windows))
        f.write(','.join([str(usage) for usage in usages]))

    return (windows, usages)


def extract_sizes_by_window(filename, window_size, count=None, to_ip=None,
        from_ip=None):
    cache_name = generate_cache_name(filename, '_sizes_by_window', to_ip, from_ip, count, window_size=window_size)
    if os.path.exists(cache_name):
        with open(cache_name) as f:
            lines = f.readlines()
            windows = windows_list_from_string(lines[0])
            sizes = lines[1].split(',')
            for i in range(len(sizes)):
                sizes[i] = [int(x) for x in sizes[i].split('_')]
            return windows, sizes

    (windows, packets) = extract_windows(filename, window_size, count=count,
            to_ip=to_ip, from_ip=from_ip)

    sizes = []
    for packet_window in packets:
        window_sizes = []
        for (fraction_in_window, packet) in packet_window:
            window_sizes.append(packet.length)

        sizes.append(window_sizes)

    with open(cache_name, 'w') as f:
        f.write(windows_list_to_string(windows))
        f.write(','.join(['_'.join([str(x) for x in size_list]) for size_list in sizes]))

    return windows, sizes


def extract_deltas(filename, column=7, to_ip=None, from_ip=None):
    cache_name = generate_cache_name(filename, '_deltas', to_ip, from_ip, None)
    if os.path.exists(cache_name):
        with open(cache_name) as f:
            return [Decimal(delta) for delta in f.readlines()[0].split(',')]

    times = extract_times(filename, column, to_ip=to_ip, from_ip=from_ip)

    diffs = []
    last_time = times[0]
    for time in times[1:]:
        diffs.append(time - last_time)
        last_time = time

    with open(cache_name, 'w') as f:
        f.write(','.join([str(diff) for diff in diffs]))

    return diffs
