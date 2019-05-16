from decimal import *
import time
from expcap_metadata import ExpcapPacket
import numpy as np
import os
import re
import sys
import pickle
import glob
import flock
import threading

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


def generate_cache_name(input_file, name, to_ip, from_ip, count, window_size=None, packet_threshold=None, ipg_threshold=None):
    name = input_file + name

    if to_ip:
        name = name + '_to_ip_' + to_ip
    if from_ip:
        name = name + '_from_ip_' + from_ip
    if count:
        name = name + '_packets_' + str(count)
    if packet_threshold:
        name = name + '_packet_threshold_' + str(packet_threshold)
    if ipg_threshold:
        name = name + '_ipg_threshold_' + str(ipg_threshold)
    if window_size:
        name = name + '_window_size_' + window_size

    return name + '.cache'


def get_caches_we_can_build_from(input_file, name, to_ip, from_ip, count, window_size):
    biggest_match_found = None
    biggest_file_found = None
    glob_name = generate_cache_name(input_file, name, to_ip, from_ip, count, window_size="*")

    files = glob.glob(glob_name)

    for file in files:
        # Get the window size first:
        window_index = file.index('window_size_')
        assert window_index != -1
        last_part = file[window_index + len('window_size_'):]
        # Chop from the number to the end:
        size = int(re.split('_|\.', last_part)[0])

        if int(window_size) % size == 0:
            print "Found a file that will build to make the cache we want!"
            if not biggest_match_found or size > biggest_match_found:
                biggest_match_found = size
                biggest_file_found = file

    return biggest_file_found, biggest_match_found


def tcp_flow_identifier(packet):
    # Note that this needs to identify /flows/ so things
    # need to be in the same order independent of whether
    # this is going to or from the server.
    data = [packet.src_addr, packet.dst_addr, packet.src_port, packet.dst_port]

    return '_'.join(sorted(data))


metadatas_lock = threading.Lock()

def extract_expcap_metadatas(filename, count=None, to_ip=None, from_ip=None):
    global last_loaded
    global last_loaded_from
    global metadatas_lock

    if filename == last_loaded_from:
        # Clone the last loaded list and send it back if this is the same
        # file as before.
        metadata = last_loaded[:]
    else:
        metadatas_lock.acquire()
        try:
            with open(filename) as f:
                if count:
                    lines = f.readlines()[1:count]
                else:
                    lines = f.readlines()[1:]

                metadata = []
                start_time = time.time()
                for line in lines:
                    expcap_packet = ExpcapPacket(line)
                    if expcap_packet.padding_packet or not expcap_packet.fully_processed_ip:
                        print "Extracted: ", len(metadata), "so far"
                        current_time = time.time()
                        print "Rate is ", len(metadata) / (current_time - start_time), "pps"
                        continue
                    metadata.append(expcap_packet)

            metadata.sort(key=lambda x: x.start_time)
            last_loaded = metadata[:]
            last_loaded_from = filename
        finally:
            metadatas_lock.release()

    deleted_count = 0
    if to_ip:
        hex_ip = ip_to_hex(to_ip)
        for index in xrange(len(metadata)):
            if metadata[index].dst_addr != hex_ip:
                deleted_count += 1
                metadata[index] = None

    if from_ip:
        hex_ip = ip_to_hex(from_ip)
        for index in xrange(len(metadata)):
            if metadata[index].src_addr != hex_ip:
                deleted_count += 1
                metadata[index] = None

    all_data = [None] * (len(metadata) - deleted_count)
    index = 0
    for data in metadata:
        if data:
            all_data[index] = data
            index += 1

    print "Using ", len(all_data), "packets"
    return all_data


def extract_sizes(filename, count=None, to_ip=None, from_ip=None):
    cache_name = generate_cache_name(filename, '_sizes_list', to_ip, from_ip, count)
    if os.path.exists(cache_name):
        print "Hit a cache extracting packet sizes!"
        with open(cache_name) as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
                sizes = f.readlines()[0].split(',')
                return [int(size) for size in sizes]

    metadatas = extract_expcap_metadatas(filename, count, to_ip=to_ip,
                                         from_ip=from_ip)
    sizes = []
    for expcap_packet in metadatas:
        sizes.append(expcap_packet.length)

    with open(cache_name, 'w') as f:
        with flock.Flock(f, flock.LOCK_EX) as lock:
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
    cache_name = generate_cache_name(filename, '_bursts', to_ip, from_ip, count, ipg_threshold=ipg_threshold, packet_threshold=packet_threshold)
    if os.path.exists(cache_name):
        print "Found a cache!  Going to use it!"
        with open(cache_name) as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
                bursts = pickle.load(f)
                return bursts

    metadatas = extract_expcap_metadatas(filename, count=count, to_ip=to_ip, from_ip=from_ip)

    if len(metadatas) == 0:
        return []

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

    total_bursts = sum([len(burst) for burst in bursts])
    # I think we're storing about 100 bytes of info per packet.
    # Arbitrarily, let's try to keep the pickle size below
    # 300 MB.
    # So, that means we need less than 3 million total packets
    # to be able to save this to the disk.
    if total_bursts < 3000000:
        with open(cache_name, 'w') as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
                pickle.dump(bursts, f)
    else:
        print "WARNING: Burst too big, not caching."

    return bursts


def extract_ipgs(filename, count=None, to_ip=None, from_ip=None):
    cache_name = generate_cache_name(filename, '_ipgs', to_ip, from_ip, count)
    if os.path.exists(cache_name):
        print "Hit a cache extracting IPGs!"
        with open(cache_name) as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
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
        with flock.Flock(f, flock.LOCK_EX) as lock:
            f.write(','.join([str(ipg) for ipg in ipgs]))

    return ipgs


def extract_times(filename, column=7, count=None, to_ip=None, from_ip=None):
    times = []

    cache_name = generate_cache_name(filename, '_times', to_ip, from_ip, count)
    if os.path.exists(cache_name):
        print "Hit a cache extracting arrival times!"
        with open(cache_name) as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
                return [Decimal(x) for x in (f.readlines()[0].split(','))]

    expcap_metadatas = \
        extract_expcap_metadatas(filename, count=count, to_ip=to_ip, from_ip=from_ip)

    for expcap in expcap_metadatas:
        times.append(expcap.wire_start_time)

    with open(cache_name, 'w') as f:
        with flock.Flock(f, flock.LOCK_EX) as lock:
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
    if int(window_size) < 70000:
        print "Window size less than 70,000 ps not supported"
        sys.exit(1)

    window_size = Decimal(window_size) / Decimal(1000000000000)
    expcap_metadatas = extract_expcap_metadatas(filename, count=count, to_ip=to_ip, from_ip=from_ip)
    debug = False
    packet_groups = []
    windows = []

    if len(expcap_metadatas) == 0:
        print "Error: No expcap metadatas found for file ", filename
        print "With restrictions: to ip:", to_ip
        print "from_ip:", from_ip
        return []
    
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
    one = Decimal(1.0)
    for index in xrange(iterations):
        window_start = start_time + Decimal(index) * window_size
        window_end = window_start + window_size
        # Check if there are no packets in this window
        # and skip the hard work if so:
        if expcap_metadatas[packet_start_index].wire_start_time > window_end:
            packet_groups.append([])
            windows.append((window_start, window_end))
            if debug:
                print "Empty window! Skipping... Until it's not empty!"
            continue
        # Get all the packets in this range:
        packet_end_index = packet_start_index
        while packet_end_index < len(expcap_metadatas) and \
                expcap_metadatas[packet_end_index].wire_end_time < window_end:
            packet_end_index += 1

        if debug:
            print "Packet Start index is", packet_start_index
            print "Packet end index is ", packet_end_index
        # If we've gone past the end, teh last packet is clearly just
        # the last one in the list.
        if packet_end_index == len(expcap_metadatas):
            packet_end_index -= 1

        # Now, compute how much of the window is filled with
        # packets.  There are edge cases at the start
        # and end.

        packets_in_window = []
        if packet_start_index == packet_end_index:
            start_packet = expcap_metadatas[packet_start_index]
            if start_packet.wire_start_time < window_start and start_packet.wire_end_time > window_end:
                # The packet is not entirely  in the window but is sticking out both sides.  Deal with that here:
                window_size = window_end - window_start
                fraction_in_window = window_size / expcap_metadatas[packet_start_index].wire_length_time
                packet_groups.append([(fraction_in_window, start_packet)])
            elif start_packet.wire_end_time < window_end and \
                    start_packet.wire_start_time > window_start:
                # Add the packet entirely:
                packet_groups.append([(one, start_packet)])
            elif start_packet.wire_start_time < window_start:
                fraction_in_window = (start_packet.wire_end_time - window_start) / start_packet.wire_length_time
                packet_groups.append([(fraction_in_window, start_packet)])
            elif start_packet.wire_end_time > window_end:
                fraction_in_window = (window_end - start_packet.wire_start_time) / start_packet.wire_length_time
                packet_groups.append([(fraction_in_window, start_packet)])
            else:
                assert packet.wire_end_time < window_start or packet.wire_start_time > window_end
                # The packet is entirely outside the window.
                packet_groups.append([])

            # We need to not do the logic below or the packet will be added more times.
            # Note that we should not increment becase it sticks out the end of the window.
            windows.append((window_start, window_end))

            # We don't have to set the packet end index because it is already correct.
            continue

        if expcap_metadatas[packet_start_index].wire_end_time < window_start:
            # The packet is entirely before the start of the window.
            pass
        elif expcap_metadatas[packet_start_index].wire_start_time < window_start:
            # The packet starts before the window, so chop that off.
            fraction_in_window = (expcap_metadatas[packet_start_index].wire_end_time - window_start) / expcap_metadatas[packet_start_index].wire_length_time
            packets_in_window.append((fraction_in_window,
                                      expcap_metadatas[packet_start_index]))
            if debug:
                print "Wire start time for first packet before start of window"
                print "Fraction in window ", fraction_in_window
        else:
            packets_in_window.append((one, expcap_metadatas[packet_start_index]))
            if debug:
                print "First packet entirely in the window"
                print "(Start time is", expcap_metadatas[packet_start_index].wire_start_time, ")"
                print "Window start time is ", window_start

        if debug:
            print "Added partial packet  at index", packet_start_index
        # Loop over all but the last packet, which we don't want to include
        # in the calculation because it may be chopped out of the region.
        for index in xrange(packet_start_index + 1, packet_end_index):
            # These packets will be entirely in the window, so
            # they fraction 1.0 in the window
            if debug:
                print "Added all of indexes", index
            packets_in_window.append((one, expcap_metadatas[index]))

        if debug:
            print "Adding partial packet at index", packet_end_index
        # The last packet might only be partially in the window.
        if expcap_metadatas[packet_end_index].wire_start_time >  window_end:
            # The packet is entirely outside the window.
            pass
        elif expcap_metadatas[packet_end_index].wire_end_time > window_end:
            if debug:
                print "Packet sticks out of window end."
            fraction_in_window = (window_end - expcap_metadatas[packet_end_index].wire_start_time) / expcap_metadatas[packet_end_index].wire_length_time
            packets_in_window.append((fraction_in_window, expcap_metadatas[packet_end_index]))
            if debug:
                print "Fraction in the window is", fraction_in_window
        else:
            if debug:
                print "Wire length time last packet"
            packets_in_window.append((one, expcap_metadatas[packet_end_index]))

        if debug:
            print "Added packets with hashes:", 
            for (fraction, packet) in packets_in_window:
                print hash(packet),
            print ""
        # Make the rate calculation here:
        packet_groups.append(packets_in_window)
        windows.append((window_start, window_end))

        # For the next iteration, the starting packet is the same as the last
        # one on this iteration.
        packet_start_index = packet_end_index

    return (windows, packet_groups)


def extract_bandwidths(filename, window_size, max_mbps=10000, count=None, to_ip=None, from_ip=None):
    windows, utilizations = extract_utilizations(filename, window_size, count=count, to_ip=to_ip, from_ip=from_ip)

    max_mbps = Decimal(max_mbps)
    for i in xrange(len(utilizations)):
        utilizations[i] = max_mbps * utilizations[i]

    return windows, utilizations


def extract_utilizations(filename, window_size, count=None, to_ip=None, from_ip=None):
    cache_name = generate_cache_name(filename, '_bandwidths', to_ip, from_ip, count, window_size=str(window_size))
    if os.path.exists(cache_name):
        print "Hit a cache extracting utilizations!"
        with open(cache_name) as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
                lines = f.readlines()
                windows = windows_list_from_string(lines[0])
                usages = [Decimal(x) for x in (lines[1].split(','))]

                return (windows, usages)
    else:
        # Try to see if there are any multiple window size files
        # that we can build the right one from.
        other_name, other_size = get_caches_we_can_build_from(filename, '_bandwidths', to_ip, from_ip, count, window_size)
        if other_name != None:
            print "We are able to build the graph using a different cache file!"
            combination_factor = (int(window_size) / other_size)
            print "The combination factor is ", combination_factor
            with open(other_name) as f:
                with flock.Flock(f, flock.LOCK_EX) as lock:
                    bigger_windows = []
                    bigger_utilizations = []

                    lines = f.readlines()
                    windows = windows_list_from_string(lines[0])
                    utilizations = [Decimal(x) for x in lines[1].split(',')]

                    for base_index in range(0, len(windows) / combination_factor, combination_factor):
                        window_start, _ = windows[base_index]
                        _, window_end = windows[base_index + combination_factor - 1]

                        # Now, go through and build up the appropriate windows:
                        new_utilizations = []
                        for index in range(base_index, base_index + combination_factor):
                            # We want to weight the contribution to the
                            # utilization in the new window by the length of
                            # the window.
                            sub_window_start, sub_window_end = windows[index]
                            new_fraction = (sub_window_end - sub_window_start) / (window_end - window_start)
                            new_utilizations.append(utilizations[index] * new_fraction)

                        bigger_utilizations.append(sum(new_utilizations))
                        bigger_windows.append((window_start, window_end))
            # Before we return, werite the new utiliations out to disk.
            save_utilizations_in_cache(cache_name, bigger_windows, bigger_utilizations)
            return bigger_windows, bigger_utilizations

    (windows, packets) = extract_windows(filename, window_size, count=count,
                                         to_ip=to_ip, from_ip=from_ip)

    usages = []
    debug = False
    # For each window, go through and sum the total
    # fraction of time the window is in use.
    for i in xrange(len(windows)):
        (window_start, window_end) = windows[i]
        total_window_time = window_end - window_start
        time_used = Decimal(0.0)
        for (fraction, packet) in packets[i]:
            print fraction
            print packet.wire_length_time
            print hash(packet)
            time_used += fraction * packet.wire_length_time

        utilization = time_used / total_window_time
        usages.append(utilization)
        if debug:
            print "Window size is ", total_window_time
            print "Utilization is ", utilization
            print "Number of packets in the window is ", len(packets[i])
            if utilization > 1:
                print "Greater than one usage: see last ", len(packets[i]), "utilizations"

    save_utilizations_in_cache(cache_name, windows, usages)
    return (windows, usages)


def save_utilizations_in_cache(cache_name, windows, usages):
    with open(cache_name, 'w') as f:
        with flock.Flock(f, flock.LOCK_EX) as lock:
            f.write(windows_list_to_string(windows))
            f.write(','.join([str(usage) for usage in usages]))


def extract_sizes_by_window(filename, window_size, count=None, to_ip=None,
        from_ip=None):
    cache_name = generate_cache_name(filename, '_sizes_by_window', to_ip, from_ip, count, window_size=window_size)
    if os.path.exists(cache_name):
        print "Hit a cache extracting sizes by window!"
        with open(cache_name) as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
                lines = f.readlines()
                windows = windows_list_from_string(lines[0])
                sizes = lines[1].split(',')
                for i in xrange(len(sizes)):
                    sizes[i] = [int(x) for x in sizes[i].split('_')]
                return windows, sizes
    else:
        # Try to see if there are any multiple window size files
        # that we can build the right one from.
        other_name, other_size = get_caches_we_can_build_from(filename, '_sizes_by_window', to_ip, from_ip, count, window_size)
        if other_name != None:
            print "We are able to build the graph using a different cache file!"
            combination_factor = (int(window_size) / other_size)
            print "The combination factor is ", combination_factor
            with open(other_name) as f:
                with flock.Flock(f, flock.LOCK_EX) as lock:
                    bigger_windows = []
                    bigger_sizes = []

                    lines = f.readlines()
                    windows = windows_list_from_string(lines[0])
                    sizes = lines[1].split(',')

                    for base_index in range(0, len(sizes) / combination_factor, combination_factor):
                        window_start, _ = windows[base_index]
                        _, window_end = windows[base_index + combination_factor - 1]
                        this_window_sizes = []
                        for index in range(0, combination_factor):
                            sub_window_sizes = [int(x) for x in sizes[base_index + index].split('_')]
                            this_window_sizes += sub_window_sizes
                        bigger_sizes.append(this_window_sizes)
                        bigger_windows.append((window_start, window_end))
            return bigger_windows, bigger_sizes


    (windows, packets) = extract_windows(filename, window_size, count=count,
            to_ip=to_ip, from_ip=from_ip)

    sizes = []
    for packet_window in packets:
        window_sizes = []
        for (fraction_in_window, packet) in packet_window:
            window_sizes.append(packet.length)

        sizes.append(window_sizes)

    with open(cache_name, 'w') as f:
        with flock.Flock(f, flock.LOCK_EX) as lock:
            f.write(windows_list_to_string(windows))
            f.write(','.join(['_'.join([str(x) for x in size_list]) for size_list in sizes]))

    return windows, sizes


def extract_deltas(filename, column=7, to_ip=None, from_ip=None):
    cache_name = generate_cache_name(filename, '_deltas', to_ip, from_ip, None)
    if os.path.exists(cache_name):
        print "Hit a cache extracting deltas!"
        with open(cache_name) as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
                return [Decimal(delta) for delta in f.readlines()[0].split(',')]

    times = extract_times(filename, column, to_ip=to_ip, from_ip=from_ip)
    if len(times) == 0:
        return []

    diffs = []
    last_time = times[0]
    for pkt_time in times[1:]:
        diffs.append(pkt_time - last_time)
        last_time = pkt_time

    with open(cache_name, 'w') as f:
        with flock.Flock(f, flock.LOCK_EX) as lock:
            f.write(','.join([str(diff) for diff in diffs]))

    return diffs


def extract_flow_lengths(filename):
    cache_name = generate_cache_name(filename, '_flow_lengths', None, None, None)

    if os.path.exists(cache_name):
        print "Hit a cache extracting flow lengths!"
        with open(cache_name) as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
                data = f.readlines()[0]
                if data == '':
                    return []
                lengths = [Decimal(x) for x in data.split(',')]
                return lengths

    # Get all the TCP packets, then look for SYNs and FINs.
    metadatas = extract_expcap_metadatas(filename)

    flows = {}
    flow_count = 0
    flow_lengths = []
    for packet in metadatas:
        if packet.is_ip and packet.is_tcp and packet.is_tcp_syn:
            identifier = tcp_flow_identifier(packet)
            flows[identifier] = packet.wire_start_time
            flow_count += 1

        if packet.is_ip and packet.is_tcp and (packet.is_tcp_fin or packet.is_tcp_rst):
            identifier = tcp_flow_identifier(packet)
            if identifier in flows:
                flow_lengths.append(packet.wire_end_time - flows[identifier])
                # Remove that flow, we don't want to count
                # everything twice.  We'll only delete it on
                # the first FIN, but that's OK.
                del flows[identifier]
            else:
                print "Warning! Found a FIN/RST for a flow we didn't see a SYN for!"

    if len(flows) > 0:
        print "Warning: Saw ", len(flows), " SYNs for flows that weren't closed"
    with open(cache_name, 'w') as f:
        with flock.Flock(f, flock.LOCK_EX) as lock:
            f.write(','.join([str(length) for length in flow_lengths]))

    print "Flow count is ", flow_count
    return flow_lengths


def extract_flow_sizes(filename):
    cache_name = generate_cache_name(filename, '_flow_sizes', None, None, None)

    if os.path.exists(cache_name):
        print "Hit a cache extracting flow sizes!"
        with open(cache_name) as f:
            with flock.Flock(f, flock.LOCK_EX) as lock:
                data = f.readlines()[0]
                if data == '':
                    return []
                lengths = [int(x) for x in data.split(',')]
                return lengths

    # Get all the TCP packets, then look for SYNs and FINs.
    metadatas = extract_expcap_metadatas(filename)

    flows = {}
    flow_count = 0
    flow_sizes = []
    for packet in metadatas:
        if packet.is_ip and packet.is_tcp and packet.is_tcp_syn:
            # print "Starting flow for ", packet.packet_data
            identifier = tcp_flow_identifier(packet)
            print "Flow ID is ", identifier
            # print "Start time is", packet.wire_start_time
            flows[identifier] = packet.tcp_data_length
            flow_count += 1
        elif packet.is_ip and packet.is_tcp and (packet.is_tcp_fin or packet.is_tcp_rst):
            identifier = tcp_flow_identifier(packet)
            if identifier in flows:
                flow_sizes.append(packet.tcp_data_length + flows[identifier])
                # Remove that flow, we don't want to count
                # everything twice.  We'll only delete it on
                # the first FIN, but that's OK.
                del flows[identifier]
            else:
                print "Warning! Found a FIN/RST for a flow we didn't see a SYN for!"
        elif packet.is_tcp:
            identifier = tcp_flow_identifier(packet)
            if identifier in flows:
                flows[identifier] += packet.tcp_data_length
            else:
                print "Saw a TCP packet for a flow we didn't SYN to!"

    if len(flows) > 0:
        print "Warning: Saw ", len(flows), " SYNs for flows that weren't closed"

    with open(cache_name, 'w') as f:
        with flock.Flock(f, flock.LOCK_EX) as lock:
            f.write(','.join([str(length) for length in flow_sizes]))

    print "Flow count is ", flow_count
    return flow_sizes
