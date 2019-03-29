#!/bin/bash

set -eu
if [[ $# -ne 3 || ! -f $1 || ! -d $2 ]]; then
	echo "Usage: $0 <expcap file> <decode location> <unique name>"
	echo "The unique name is a name to copy to, and will also be"
	echo "used as an identifier for the graphs."
	exit 1
fi
unique_name=$3

if [[ $unique_name == *.expcap.bzip2 ]]; then
	echo "Unique  name should not be a 'file' per say."
	exit 1
fi

# First, copy the expcap file to the decode location:
cp $1 $2/${unique_name}.expcap.bz2
# Then extract it:
bunzip2 -f $2/${unique_name}.expcap.bz2

# Then extract it:
# Put this in a different folder so the graphs can also be put
# in that folder and avoid cluttering the top level stuff.
mkdir -p $2/$unique_name
/root/jcw78/scripts/hpt_setup/exanic-exact/exact-capture-1.0RC/bin/exact-pcap-parse -i $2/${unique_name}.expcap -c $2/$unique_name/${unique_name}.csv -n 2000 -f expcap || true

csv=$2/$unique_name/${unique_name}.csv
# Now, run each of the analyses.
# Bandwidth on 10us scale
python bandwidth_through_time.py $csv --window 10000000 &
python packet_size_distribution_through_time.py --window 10000000 &
# Bandwidth on 1ms scale
python bandwidth_through_time.py $csv --window 1000000000 &
python packet_size_distribution_through_time.py --window 1000000000 &

python packet_size_distribution_graph.py $csv &
python ipg_distribution_graph.py $csv &
wait

# Finally, remove everything that is left, which is the expcap file and the CSV file.
rm -f $2/$unique_name/${unique_name}.csv
rm -f $2/$unique_name/${unique_name}.expcap
