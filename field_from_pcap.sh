#!/bin/bash

set -eu

if [[ $# -lt 3 ]] || [[ ! -f "$1" ]]; then
	echo "Usage $0 <pcap file> <output file> <name(s) of field(s) to extract> [options passed onto tcpdump]"
	echo "The field may be any valid grep expression.  If"
	echo "all matches will be included in the output"
	echo "'' matches everything"
fi

in_file="$1"
out_file="$2"
grep_cmd="$3"
shift 3

# This is a scipt that converts a pcap file into a text file
# with only the relevant lines.
if [[ $grep_cmd == "" ]]; then
	echo "No grep command: not filtering"
	tcpdump -r "$in_file" "$@" > "$out_file"
else
	echo "Filtering on $grep_cmd"
	tcpdump -r "$in_file" "$@" | grep -e "$grep_cmd" > "$out_file"
fi
echo "Done extracting!"
