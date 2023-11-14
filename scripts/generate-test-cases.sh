#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Function to display usage information
usage() {
  echo "Usage: $0 -d <input_directory> -o <output_directory> -b <binary>"
  echo "Options:"
  echo "  -d  Directory of the application to test"
  echo "  -o  Output directory to store generated test cases"
  echo "  -b  Name of binary file to execute"
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
if [ -z "$input_dir" ] || [ -z "$output_dir" ]; then
  usage
  exit 1
fi

rm -rf "$output_dir"
# Create output directory if it doesn't exist
if [ ! -d "$output_dir" ]; then
  mkdir -p "$output_dir"
fi

pushd .
echo -e "${COLOR_GREEN}Moving inside the input directory: ${input_dir}${COLOR_OFF}"
cd "${input_dir}"

echo -e "${COLOR_GREEN}Generating test cases with KLEE${COLOR_OFF}"
make build-tests

echo -e "${COLOR_GREEN}Compiling test application${COLOR_OFF}"
make build-replay-tests

# check if $binary is specified
if [ -z "$binary" ]; then
  # search for a file that ends with .bin
  binary=$(find . -name "*.bin" | head -n 1)
fi

echo -e "${COLOR_GREEN}Moving generated test cases to output directory: ${output_dir}${COLOR_OFF}"
rm -rf "${output_dir}/ktest-files" > /dev/null 2>&1
mkdir -p "${output_dir}/ktest-files"
mv klee-last/*.ktest "${output_dir}/ktest-files"

echo -e "${COLOR_GREEN}Running application with symbolic inputs to get map values${COLOR_OFF}"

# Find and sort all the .ktest files
ktest_files=$(find "${output_dir}/ktest-files/" -name "*.ktest" | sort)

rm -rf "${output_dir}/map-tmp-results" > /dev/null 2>&1
mkdir -p "${output_dir}/map-tmp-results"
# Loop through each .ktest file
for ktest_file in $ktest_files; do
  echo "Processing $ktest_file..."
  KTEST_FILE=$ktest_file ./$binary -d "$output_dir/map-tmp-results"
done

echo -e "${COLOR_GREEN}Consolidate extracted map values${COLOR_OFF}"
rm -rf "${output_dir}/map-results" > /dev/null 2>&1
mkdir -p "${output_dir}/map-results"
python3 "${DIR}/consolidate-test-cases.py" -v "${output_dir}/ktest-files/" -k "${output_dir}/map-tmp-results" -o "${output_dir}/map-results"

rm -rf "${output_dir}/map-tmp-results" > /dev/null 2>&1

popd