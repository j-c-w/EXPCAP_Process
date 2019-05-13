#!/bin/bash
set -eu

if [[ $# -ne 4 ]]; then
	echo "Usage: $0 <draw directory> <capture directory> <benchmark name> <number of machines>"
	exit 1
fi

draw_directory=$1
capture_directory=$2
name=$3
number_machines=$4

config_file=draw_${name}_$number_machines
cp TEMPLATE $config_file

sed -i "s/APP_NAME/$name/g" $config_file 
sed -i "s/NUMBER_MACHINES/$number_machines/g" $config_file
sed -i "s|DRAW_DIRECTORY|$draw_directory|g" $config_file
sed -i "s|APPS_CAPTURE_DIRECTORY|$capture_directory|g" $config_file

echo "New config file is in $config_file!"
