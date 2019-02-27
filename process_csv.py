from decimal import *

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


def extract_deltas(filename, column=7):
    times = extract_times(filename, column)

    diffs = []
    last_time = times[0]
    for time in times[1:]:
        diffs.append(time - last_time)
        last_time = time

    return diffs
