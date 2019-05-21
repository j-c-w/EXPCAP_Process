import argparse
import threading
import shlex
import bandwidth_cdf
import bandwidth_through_time
import flow_length_cdf
import flow_size_cdf
import inter_arrival_distribution_graph
import ipg_distribution_graph
import microburst_analysis
import packet_size_distribution_graph
import packet_size_distribution_through_time

entry_semaphore = None
entered = 0


def draw_graph(name, commands):
    global entry_semaphore
    global entered
    entry_semaphore.acquire()
    entered += 1
    print "A thread has acquired the global semaphore and is starting work."
    print "(Using ", name, ")"
    print entered
    print "Entered is ", entered

    try:
        if name == "bandwidth_cdf.py":
            bandwidth_cdf.main(commands)
        elif name == "bandwidth_through_time.py":
            bandwidth_through_time.main(commands)
        elif name == "flow_length_cdf.py":
            flow_length_cdf.main(commands)
        elif name == "flow_size_cdf.py":
            flow_size_cdf.main(commands)
        elif name == "inter_arrival_distribution_graph.py":
            inter_arrival_distribution_graph.main(commands)
        elif name == "ipg_distribution_graph.py":
            ipg_distribution_graph.main(commands)
        elif name == "microburst_analysis.py":
            microburst_analysis.main(commands)
        elif name == "packet_size_distribution_graph.py":
            packet_size_distribution_graph.main(commands)
        elif name == "packet_size_distribution_through_time.py":
            packet_size_distribution_through_time.main(commands)
        else:
            print "Error: Unkown filename", name
    finally:
        print "Entered is ", entered
        entered -= 1
        entry_semaphore.release()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--parallelism', dest='parallelism',
                        default=1, required=False)
    parser.add_argument('--dry-run', dest='dry_run',
                        default=False, action='store_true')
    parser.add_argument('config_file')

    args = parser.parse_args()

    entry_semaphore = threading.Semaphore(args.parallelism)
    commands = []

    with open(args.config_file) as f:
        # Get all the lines.  Lines starting with a '#' are comments.

        for line in f.readlines():
            if not line.startswith('#'):
                # The first CSV value is the plotting command.
                command = line.split(',')[1]

                # Splits the string using command line
                # separators.
                command_parts = shlex.split(command)
                # The zeroeth element is just 'python'.
                # The next element if the name of the file we need.
                graph_name = command_parts[1]
                command_parts = command_parts[2:]
                commands.append((graph_name, command_parts))

    if args.dry_run:
        print commands
    else:
        threads = []
        for (name, command) in commands:
            threads.append(threading.Thread(target=draw_graph, args=[name, command]))
        for thread in threads:
            thread.start()
        print "All threads started!"

        for thread in threads:
            thread.join()
        print "All done!"
