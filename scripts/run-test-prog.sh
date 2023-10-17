#!/bin/bash

# Function to display usage information
usage() {
  echo "Usage: $0 -d <input_directory> -o <output_directory> -b <binary>"
  echo "Options:"
  echo "  -d  Directory to search for .ktest files"
  echo "  -o  Output directory to store new files"
  echo "  -b  Binary file to execute"
  echo "  -h  Show this help message"
}

# Initialize variables
input_dir=""
output_dir=""
binary=""

# Parse command line options
while getopts "d:o:b:h" opt; do
  case $opt in
    d)
      input_dir=$OPTARG
      ;;
    o)
      output_dir=$OPTARG
      ;;
    b)
      binary=$OPTARG
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
if [ -z "$input_dir" ] || [ -z "$output_dir" ] || [ -z "$binary" ]; then
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
  echo "Processing $ktest_file..."
  KTEST_FILE=$ktest_file $binary -d "$output_dir"
done
