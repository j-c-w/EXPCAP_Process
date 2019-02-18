

def extract_timestamp(filename, column=7):
    times = []
    with open(filename) as f:
        # Skip the first line, which likely includes headers
        for line in f.readlines()[1:]:
            time = float(line.split(",")[column])
            times.append(time)
    return times


def extract_deltas(filename, column=7):
    times = extract_timestamp(filename, column)

    diffs = []
    last_time = times[0]
    for time in times[1:]:
        diffs.append(time - last_time)

    return diffs
