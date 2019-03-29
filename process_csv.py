from decimal import *
from expcap_metadata import ExpcapPacket
import numpy as np


def extract_expcap_metadatas(filename, count=None):
    with open(filename) as f:
        if count:
            lines = f.readlines()[1:count]
        else:
            lines = f.readlines()[1:]

        metadata = []
        for line in lines:
            expcap_packet = ExpcapPacket(line)
            if expcap_packet.padding_packet or not expcap_packet.fully_processed_ip:
                continue
            metadata.append(expcap_packet)

    metadata.sort(key=lambda x: x.start_time)
    return metadata


def extract_sizes(filename, count=None):
    metadatas = extract_expcap_metadatas(filename, count)
    sizes = []
    for expcap_packet in metadatas:
        sizes.append(expcap_packet.length)

    return sizes


def extract_ipgs(filename, count=None):
    metadatas = extract_expcap_metadatas(filename, count=count)
    ipgs = []
    if len(metadatas) < 2:
        return []
    last_end = metadatas[0].wire_end_time

    for expcap_packet in metadatas[1:]:
        ipgs.append(expcap_packet.wire_end_time - last_end)
        last_end = expcap_packet.wire_end_time

    return ipgs


def extract_times(filename, column=7, count=None):
    times = []
    with open(filename) as f:
        # Skip the first line, which likely includes headers
        if count:
            lines = f.readlines()[1:count]
        else:
            lines = f.readlines()[1:]
        last_time = -1.0
        for line in lines:
            time = line.split(",")[column]
            # There is a bug in the HPT setup which
            # means that invalid packets sometimes
            # appear.
            if time != last_time:
                times.append(Decimal(time))
            last_time = time
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
"""
def extract_windows(filename, window_size, count=None):
    # Note that window_size is in pico seconds, so convert to seconds
    window_size = Decimal(window_size) / Decimal(1000000000000)
    expcap_metadatas = extract_expcap_metadatas(filename, count)
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


def extract_bandwidths(filename, window_size, count=None):
    (windows, packets) = extract_windows(filename, window_size, count=count)

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

    return (windows, usages)


def extract_sizes_by_window(filename, window_size, count=None):
    (windows, packets) = extract_windows(filename, window_size, count=count)

    sizes = []
    for packet_window in packets:
        window_sizes = []
        for (fraction_in_window, packet) in packet_window:
            window_sizes.append(packet.length)

        sizes.append(window_sizes)

    return windows, sizes


def extract_deltas(filename, column=7):
    times = extract_times(filename, column)

    diffs = []
    last_time = times[0]
    for time in times[1:]:
        diffs.append(time - last_time)
        last_time = time

    return diffs
