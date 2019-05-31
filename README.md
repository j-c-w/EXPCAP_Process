# process\_pcap\_traces

This directory contains scripts to process and graph csv files produced by the expcap to CSV converter found here: https://github.com/exablaze-oss/exact-capture

The infrastructure here uses a config file format that is a CSV file.  It is documented in 'config\_files/TEMPLATE'.  This repository contains several tools to help process large pcap traces.  The help manage the extraction of large compressed traces, ./draw\_graphs\_from\_expcap.sh can be used.  Despite the confusing name, this will extract compressed expcap files from one location onto a disk that is large enough to hold them.

The script 'draw\_graphs\_from\_config\_file.py' takes these config files as input.  All graphs are automatically drawn with linear and log scales.  Graphs  will take a very long time to draw the first time around.  The infrastructure automatically caches intermediate results which gives orders of magnitude speedup when replotting.

I advise that you start small: plot individual graphs of everything to generate the cache files trying to plot graphs that simultaneously use many traces.  *You will need a lot of RAM if you are using big traces.* (Processing requires approximately 500 bytes of memory per packet)

To understand the available command line options, use 'python graph\_script.py -h':
Arguments that take two options are generally of the form: <value> <name for a labe\l on that graph>
(Some examples are --window-size 1000000 "1 us window" or --input-file run\_with\_x\_machines "x machines")

Graphing scripts are:
	arrival\_time\_difference\_plot.py: Plot the difference in arrival times between two capture files.  This is only useful when comparing clock synchronizations or similar.
	bandwidth\_cdf.py:  Plot a CDF of the bandwidth throughout an application run.
	bandwidth\_through\_time.py: Plot the bandwidth with time as an x-axis (note that matplotlib limits us to 3 million or so points so the window size must be sufficienlty large)
	flow\_length\_cdf.py: Plot a CDF of the TCP flow completion times.
	flow\_size\_cdf.py: Plot a CDF of the TCP flow sizes
	inter\_arrival\_distribution\_graph.py: Plot a CDF of 
	of inter-arrival distributions.
	interarrival\_statistics.py: Print interarrival statistics
	ipg\_distribution\_graph.py: Draw a CDF of the IPG distribution.
	microburst\_analysis.py: Determine the length of and bandwidth consumption during each mircoburst using specified parameters. (see -h for the parameters)

	packet\_size\_distribution\_graph.py: Plot a CDF of the packet sizes.
	packet\_size\_distribution\_through\_time.py: Plot a graph of the median packet size throughout the benchmark.
	plot\_arrival\_times.py: Plot the arrival times vs the  incoming packet number.  This shows how the benchmark 'progresses' towards completion in terms of network usage.
