#!/bin/zsh

set -eu

echo "Usage: $0 <original location> <temp location> [--extract-all] [--delete-cache] [--plot-only AWK search string] [--copy file] [--copy file] ..."
echo "--extract-all extracts all files.  --copy should be given a list of particular benchmarks (in the format of 'benchmark label'.  All items in this list have their caches cleared and are re-extracted.)"
echo "The first time you call this script, you will need to pass --extract all"
echo "--delete-cache: delete cached files when we are done.  Good for running on small disks."
echo "--dry-run: Just print the files we are going to extract and the commands we would run."
l=""
read "l?<Enter to continue>"

declare -a copy_files
declare -a extract_all
declare -a delete_cache
declare -a plot_only
declare -a dry_run

zparseopts -D -E -copy+=copy_files -extract-all=extract_all -delete-cache=delete_cache -plot-only=plot_only -dry-run=dry_run

typeset -a files_to_extract

for arg in ${copy_files[@]}; do
	if [[ $arg != "--copy" ]]; then
		files_to_extract+="$arg"
	fi
done

function decompress() {
	local src=$1
	local dst=$2
	cp $src $dst.bz2

	# The unzip will take the .bz2 off the end.  It will delete the zipped
	# file.
	bunzip2 $dst.expcap.bz2

	# Get the CSV file out.
	/root/jcw78/scripts/hpt/extract_csv.sh $dst.expcap $dst

	# Delete the expcap file.
	rm $dst.expcap
}

function cleanup() {
	local tmp_location_file=$1

	if [[ ${#delete_cache} == 0 ]]; then
		echo "Removing files: $tmp_location_file"
		if [[ ${#dry_run} == 0 ]]; then
			rm -f $tmp_location_file
		fi
	else
		echo "Removing files: "
		ls $tmp_location_file*.cache
		if [[ ${#dry_run} == 0 ]]; then
			rm -f $tmp_location_file*.cache
		fi
	fi

	if [[ ${#dry_run} == 0 ]]; then
		echo "Files deleted!"
	fi
}

function decompress_files() {
	local -a files_to_decompress
	while [[ $# -gt 0 ]]; do
		if [[ ${#extract_all} != 0 ]] || [[ "${files_to_extract[@]}" == *"$1"* ]]; then
			files_to_decompress+="$1"
			files_to_decompress+="$2"
		fi
		shift 2
	done

	echo "Decompressing ${files_to_decompress[@]}"

	# Copy and extract every file to the target folder
	if [[ ${#dry_run} -ne 0 ]] && [[ ${#files_to_decompress} -gt 0 ]]; then
		parallel -j 8 decompress {1} {2} ::: ${files_to_decompress[@]}
	fi
}


# The idea here is that many of the graphing commands may actually
# share files.  We keep track of all the files.

typeset -a graph_commands
while read p; do
	graph_commands+=("$p")
done < graphs

for graph_command in "${graph_commands[@]}"; do
	if [[ "$graph_command" == '#'* ]]; then
		continue
	fi
	echo $graph_command
	# Get the commands and the files list.
	name="$(echo "$graph_command" | cut -d',' -f1)"
	comm="$(echo "$graph_command" | cut -d',' -f2)"
	files=($(echo "$graph_command" | cut -d',' -f3))
	echo ${files[@]}

	if [[ ${#files} -gt 0 ]]; then
		decompress_files ${files[@]}
	else
		echo "There are no files to extract!"
	fi

	# Now, run the command to draw the graph
	if [[ ${#dry_run} == 0 ]]; then
		eval "$comm"
	else
		echo "Running '$comm'"
	fi

	for file in ${files[@]}; do
		# We don't want  to delete the original EXPCAP files!
		if [[ $file == *.csv ]]; then
			cleanup $file
		fi
	done
done
