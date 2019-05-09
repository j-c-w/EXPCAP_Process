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

# We also want to extract it into a PCAP file so the tcptrace tool
# can use it.
/root/jcw78/scripts/hpt_setup/exanic-exact/exact-capture-1.0RC/bin/exact-pcap-extract -i $2/${unique_name}.expcap -w $2/$unique_name/${unique_name} -a

csv=$2/$unique_name/${unique_name}.csv
pcap=$2/$unique_name/${unique_name}_0.pcap

# Now, run each of the analyses.
# Bandwidth on 10us scale
python bandwidth_through_time.py $csv --server 192.168.0.7 --window 10000000 &
python packet_size_distribution_through_time.py $csv --server 192.168.0.7 --window 10000000 &
python bandwidth_cdf.py $csv --server 192.168.0.7 --window 10000000 &

# Bandwidth on 1ms scale
python bandwidth_through_time.py $csv --server 192.168.0.7 --window 1000000000 &
python packet_size_distribution_through_time.py --server 192.168.0.7 --window 1000000000 &
python bandwidth_cdf.py $csv --server 192.168.0.7 --window 1000000000 &

# Do the microbursts on several scales
python microburst_analysis.py --server 192.168.0.7 --ipg-threshold 10000000 --packet-threshold 4 $csv
python microburst_analysis.py --server 192.168.0.7 --ipg-threshold 10000000 --packet-threshold 16 $csv
python microburst_analysis.py --server 192.168.0.7 --ipg-threshold 100000000 --packet-threshold 1024 $csv
python microburst_analysis.py --server 192.168.0.7 --ipg-threshold 1000000 --packet-threshold 4 $csv
python microburst_analysis.py --server 192.168.0.7 --ipg-threshold 100000 --packet-threshold 2 $csv

python packet_size_distribution_graph.py --server 192.168.0.7 $csv &
python ipg_distribution_graph.py --server 192.168.0.7 $csv &
(cd $(dirname $pcap); tcptrace -G $(basename $pcap)) &
wait

# Finally, remove everything that is left, which is the expcap file and the CSV file.
rm -f $2/$unique_name/${unique_name}.csv
rm -f $2/$unique_name/${unique_name}.expcap
tm -f $2/$unique_name/${unique_name}.pcap
