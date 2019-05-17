#!/bin/bash

if [[ $# -ne 2 ]]; then
	echo "Usage: $0 <benchmark name> <parallelism>"
	exit 1
fi

parallel -j $2 python draw_graphs_from_config_file.py config_files/draw_${1}_{} ">" draw_${1}_{}_out ::: $(seq -s ' ' 2 7)
