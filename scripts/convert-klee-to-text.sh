#!/bin/bash

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Function to display usage information
usage() {
  echo "Usage: $0 -d <input_directory> -o <output_directory>"
  echo "Options:"
  echo "  -d  Directory to search for .ktest files"
  echo "  -o  Output directory to store new files"
  echo "  -h  Show this help message"
}

# Initialize variables
input_dir="${DIR}"
output_dir="ktest-text"

# Parse command line options
while getopts "d:o:h" opt; do
  case $opt in
    d)
      input_dir=$OPTARG
      ;;
    o)
      output_dir=$OPTARG
      ;;
    h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

# Check if all parameters are specified
if [ -z "$input_dir" ]; then
  usage
  exit 1
fi

# Create output directory if it doesn't exist
if [ ! -d "$output_dir" ]; then
  mkdir -p "$output_dir"
fi

# Find and sort all the .ktest files
ktest_files=$(find "$input_dir"/ -name "*.ktest" | sort)

# Loop through each .ktest file
for ktest_file in $ktest_files; do
  ktest_name=$(basename "$ktest_file")
  echo "Processing $ktest_file..."
  ktest-tool ${ktest_file} > ${output_dir}/${ktest_name%.ktest}.txt
done

