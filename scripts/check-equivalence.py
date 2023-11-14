#!/usr/bin/env python3

import sys
import os
import argparse
import json
from jycm.jycm import YouchamaJsonDiffer


def main():
    # Use argparse to parse command line arguments
    parser = argparse.ArgumentParser(description='Check equivalence of two BPF programs')

    parser.add_argument('prog1', metavar='PROG_A_FOLDER', type=str, help='path to folder of first BPF program')
    parser.add_argument('prog2', metavar='PROG_B_FOLDER', type=str, help='path to folder of second BPF program')
    parser.add_argument('-b', '--equivalence-bin', type=str, help='path to equivalence check binary')

    args = parser.parse_args()

    # Check if the directory paths are valid
    if not os.path.isdir(args.prog1):
        print('Error: Invalid path to first BPF program')
        sys.exit(1)

    if not os.path.isdir(args.prog2):
        print('Error: Invalid path to second BPF program')
        sys.exit(1)

    # Check if the equivalence binary path is valid
    if not os.path.isfile(args.equivalence_bin):
        print('Error: Invalid path to equivalence check binary')
        sys.exit(1)

    # Search inside prog1 dir for a file with the .bpf.o extension
    prog1_file = None
    for file in os.listdir(args.prog1):
        if file.endswith('.bpf.o'):
            prog1_file = file
            break
    
    # Search inside prog2 dir for a file with the .bpf.o extension
    prog2_file = None
    for file in os.listdir(args.prog2):
        if file.endswith('.bpf.o'):
            prog2_file = file
            break

    if prog1_file is None:
        print('Error: No .bpf.o file found in first BPF program directory')
        sys.exit(1)

    if prog2_file is None:
        print('Error: No .bpf.o file found in second BPF program directory')
        sys.exit(1)

    # I am not going to run the first program with its own test cases, and generate the output
    # then, I will run the second program with the test cases of the first program, and compare the outputs
    # I will do the same thing for the second program
    # If the outputs are the same, then the programs are equivalent
    # If the outputs are different, then the programs are not equivalent
    prog1_test1_folder = f"{sys.path[0]}/prog1_test1"

    # Create dst_folder if it does not exist
    if not os.path.isdir(prog1_test1_folder):
        os.makedirs(prog1_test1_folder)

    cmd_str = f"{args.equivalence_bin} -b {args.prog1}/{prog1_file} -i {args.prog1}/ktest-files/ -m {args.prog1}/map-results/ -d {prog1_test1_folder}"
    os.system(cmd_str)

    # Run the second program with the test cases of the first program
    prog2_test1_folder = f"{sys.path[0]}/prog2_test1"

    # Create dst_folder if it does not exist
    if not os.path.isdir(prog2_test1_folder):
        os.makedirs(prog2_test1_folder)

    cmd_str = f"{args.equivalence_bin} -b {args.prog2}/{prog2_file} -i {args.prog1}/ktest-files/ -m {args.prog1}/map-results/ -d {prog2_test1_folder}"
    os.system(cmd_str)

    # Compare the outputs of the two programs
    # Get the list of files in the first program's output folder, every entry should have the absolute path
    prog1_test1_files = os.listdir(prog1_test1_folder)

    # Get the list of files in the second program's output folder
    prog2_test1_files = os.listdir(prog2_test1_folder)

    # Check if the two lists are the same
    if len(prog1_test1_files) != len(prog2_test1_files):
        print('The list of files in the two output folders are not the same')
        sys.exit(0)

    # Sort the two lists
    prog1_test1_files.sort()
    prog2_test1_files.sort()

    # for every file I want to append the absolute path to the file name
    for i in range(len(prog1_test1_files)):
        prog1_test1_files[i] = f"{prog1_test1_folder}/{prog1_test1_files[i]}"

    # for every file I want to append the absolute path to the file name
    for i in range(len(prog2_test1_files)):
        prog2_test1_files[i] = f"{prog2_test1_folder}/{prog2_test1_files[i]}"

    equivalent = True
    # Compare the two lists
    for i in range(len(prog1_test1_files)):
        if not compare_json_files(prog1_test1_files[i], prog2_test1_files[i]):
            equivalent = False
            print(f"Test case {prog1_test1_files[i]} is not equivalent to test case {prog2_test1_files[i]}")
            # sys.exit(0)

    if not equivalent:
        print('The two programs are not equivalent')
        sys.exit(0)
        

    prog1_test2_folder = f"{sys.path[0]}/prog1_test2"

    # Create dst_folder if it does not exist
    if not os.path.isdir(prog1_test2_folder):
        os.makedirs(prog1_test2_folder)

    cmd_str = f"{args.equivalence_bin} -b {args.prog1}/{prog1_file} -i {args.prog2}/ktest-files/ -m {args.prog2}/map-results/ -d {prog1_test2_folder}"
    os.system(cmd_str)

    # Run the second program with the test cases of the first program
    prog2_test2_folder = f"{sys.path[0]}/prog2_test2"

    # Create dst_folder if it does not exist
    if not os.path.isdir(prog2_test2_folder):
        os.makedirs(prog2_test2_folder)

    cmd_str = f"{args.equivalence_bin} -b {args.prog2}/{prog2_file} -i {args.prog2}/ktest-files/ -m {args.prog2}/map-results/ -d {prog2_test2_folder}"
    os.system(cmd_str)

    # Compare the outputs of the two programs
    # Get the list of files in the first program's output folder, every entry should have the absolute path
    prog1_test2_files = os.listdir(prog1_test2_folder)

    # Get the list of files in the second program's output folder
    prog2_test2_files = os.listdir(prog2_test2_folder)

    # Check if the two lists are the same
    if len(prog1_test2_folder) != len(prog2_test2_folder):
        print('The list of files in the two output folders are not the same')
        sys.exit(0)

    # Sort the two lists
    prog1_test2_files.sort()
    prog2_test2_folder.sort()

    # for every file I want to append the absolute path to the file name
    for i in range(len(prog1_test2_files)):
        prog1_test2_files[i] = f"{prog1_test2_folder}/{prog1_test2_files[i]}"

    # for every file I want to append the absolute path to the file name
    for i in range(len(prog2_test2_files)):
        prog2_test2_files[i] = f"{prog2_test2_folder}/{prog2_test2_files[i]}"

    equivalent = True
    # Compare the two lists
    for i in range(len(prog1_test2_files)):
        if not compare_json_files(prog1_test2_files[i], prog2_test2_files[i]):
            equivalent = False
            print(f"Test case {prog1_test2_files[i]} is not equivalent to test case {prog2_test2_files[i]}")
            # sys.exit(0)

    if not equivalent:
        print('The two programs are not equivalent')
    else:
        print('The two programs are equivalent')
    
    return 0

def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj

def compare_json_files(file1, file2):
    with open(file1, 'r') as f1:
        json1 = json.load(f1)

    with open(file2, 'r') as f2:
        json2 = json.load(f2)

    ycm = YouchamaJsonDiffer(json1, json2)
    return ycm.diff()

if __name__ == '__main__':
    main()