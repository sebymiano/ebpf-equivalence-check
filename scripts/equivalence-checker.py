#!/usr/bin/env python3

import sys
import os
import argparse
import json
from jycm.jycm import YouchamaJsonDiffer
import docker
import subprocess
import tarfile
from tqdm import tqdm
import re

import logging

GENERATE_TEST_CASE_SCRIPT="generate-test-cases.sh"

PIX_FOLDER="/pix"

class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    cyan = "\x1b[36;20m"
    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: cyan + format + reset,
        logging.INFO: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
    
def create_tar_archive(source_dir, archive_name):
    with tarfile.open(archive_name, "w") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))
    
def generate_test_cases(prog_dir, container_output_dir, local_output_dir):
    volume_mapping = {
        sys.path[0]: {
            'bind': f'{PIX_FOLDER}/scripts',
            'mode': 'rw'
        },
    }
    # Start a detached container
    container = docker_client.containers.run(docker_image, "tail -f /dev/null", detach=True, volumes=volume_mapping)

    archive_name = "progA.tar"
    create_tar_archive(prog_dir, archive_name)

    prog_dir_basename = os.path.basename(os.path.normpath(prog_dir))

    # Before copying the archive to the container, I need to create the directory inside the container
    # container.exec_run(f"mkdir -p {os.path.join('/pix/ebpf-nfs', prog_dir_basename)}")

    # Copy the archive to the container and then extract it
    with open(archive_name, 'rb') as archive:
        logger.debug(f"Copying {archive_name} to container")
        container.put_archive(f"{PIX_FOLDER}/ebpf-nfs", archive.read())

    os.remove(archive_name)

    try:
        cmd = f"{os.path.join(f'{PIX_FOLDER}/scripts/', GENERATE_TEST_CASE_SCRIPT)} -d {os.path.join(f'{PIX_FOLDER}/ebpf-nfs/', prog_dir_basename)} -o {os.path.join(f'{PIX_FOLDER}', container_output_dir)}"
        logger.info(f"Running {cmd}")
        logger.info("This will take a while... (it depends on the size of the program)")

        # Start the exec instance
        exec_instance = docker_client.api.exec_create(container.id, cmd, stdout=True, stderr=True)

        # Start the exec and get a socket-like object for the output
        output_stream = docker_client.api.exec_start(exec_instance, detach=False, stream=True)
        
        # Initialize the progress bar
        progress_bar = tqdm(desc="Generated test cases", unit=" tests")

        # Process the output stream
        for chunk in output_stream:
            output = chunk.decode('utf-8')
            # Extract the test number
            match = re.search(r'Added test number: (\d+)', output)
            if match:
                # Update the progress bar to the latest test number
                latest_test_number = int(match.group(1))
                progress_bar.n = latest_test_number
                progress_bar.refresh()

        # Close the progress bar
        progress_bar.close()

        # response = container.exec_run(cmd, stdout=True, stderr=True)

        # if response.exit_code != 0:
        #     logger.error(f"Failed to generate test cases: {response.output.decode()}")
        #     sys.exit(1)

        logger.info("Test cases for program generated")

        # Let's retrieve the result from the container
        logger.debug("Retrieving result from container")
        stream, _ = container.get_archive(os.path.join(f'{PIX_FOLDER}', container_output_dir))

        with open(f"{container_output_dir}.tar", 'wb') as out_file:
            for chunk in stream:
                out_file.write(chunk)
        
        # Extract the tar archive
        with tarfile.open(f"{container_output_dir}.tar", 'r') as tar:
            tar.extractall(path=local_output_dir)

        os.remove(f"{container_output_dir}.tar")  # Clean up the tar file

        generated_files = os.listdir(os.path.join(local_output_dir, container_output_dir, "ktest-files"))

        if len(generated_files) == 0:
            logger.error("No test cases generated")
            logger.debug(f"Cmd returned :\n{response.output.decode()}")
            sys.exit(1)

    finally:
        # Stop and remove the container
        container.stop()
        container.remove()

def compare_json_files(file1, file2):
    with open(file1, 'r') as f1:
        json1 = json.load(f1)

    with open(file2, 'r') as f2:
        json2 = json.load(f2)

    ycm = YouchamaJsonDiffer(json1, json2)
    return ycm.diff()

def check_equivalence(progA_output_dir, progA_file, progB_output_dir, progB_file, equivalence_bin, output_dir):
    # I am not going to run the first program with its own test cases, and generate the output
    # then, I will run the second program with the test cases of the first program, and compare the outputs
    # I will do the same thing for the second program
    # If the outputs are the same, then the programs are equivalent
    # If the outputs are different, then the programs are not equivalent
    equivalent = True
    progA_testA_folder = os.path.join(output_dir, "progA_testA")

    # Create dst_folder if it does not exist
    if not os.path.isdir(progA_testA_folder):
        os.makedirs(progA_testA_folder)

    cmd_str = f"{equivalence_bin} -b {os.path.join(progA_output_dir, progA_file)} -i {os.path.join(progA_output_dir, 'ktest-files')} -m {os.path.join(progA_output_dir, 'map-results')} -d {progA_testA_folder}"
    os.system(cmd_str)

    # Run the second program with the test cases of the first program
    progB_testA_folder = os.path.join(output_dir, "progB_testA")

    # Create dst_folder if it does not exist
    if not os.path.isdir(progB_testA_folder):
        os.makedirs(progB_testA_folder)

    cmd_str = f"{equivalence_bin} -b {os.path.join(progB_output_dir, progB_file)} -i {os.path.join(progA_output_dir, 'ktest-files')} -m {os.path.join(progA_output_dir, 'map-results')} -d {progB_testA_folder}"
    os.system(cmd_str)

    # Compare the outputs of the two programs
    # Get the list of files in the first program's output folder, every entry should have the absolute path
    progA_testA_files = os.listdir(progA_testA_folder)

    # Get the list of files in the second program's output folder
    progB_testA_files = os.listdir(progB_testA_folder)

    # Check if the two lists are the same
    if len(progA_testA_files) != len(progB_testA_files):
        logger.error('The list of files in the two output folders are not the same')
        return False

    # Sort the two lists
    progA_testA_files.sort()
    progB_testA_files.sort()

    # for every file I want to append the absolute path to the file name
    for i in range(len(progA_testA_files)):
        progA_testA_files[i] = os.path.join(progA_testA_folder, progA_testA_files[i])

    # for every file I want to append the absolute path to the file name
    for i in range(len(progB_testA_files)):
        progB_testA_files[i] = os.path.join(progB_testA_folder, progB_testA_files[i])

    # Compare the two lists
    for i in range(len(progA_testA_files)):
        if not compare_json_files(progA_testA_files[i], progB_testA_files[i]):
            equivalent = False
            logger.debug(f"Test case {progA_testA_files[i]} is not equivalent to test case {progB_testA_files[i]}")
        
    progA_testB_folder = os.path.join(output_dir, "progA_testB")

    # Create dst_folder if it does not exist
    if not os.path.isdir(progA_testB_folder):
        os.makedirs(progA_testB_folder)

    cmd_str = f"{equivalence_bin} -b {os.path.join(progA_output_dir, progA_file)} -i {os.path.join(progB_output_dir, 'ktest-files')} -m {os.path.join(progB_output_dir, 'map-results')} -d {progA_testB_folder}"
    os.system(cmd_str)

    # Run the second program with the test cases of the first program
    progB_testB_folder = os.path.join(output_dir, "progB_testB")

    # Create dst_folder if it does not exist
    if not os.path.isdir(progB_testB_folder):
        os.makedirs(progB_testB_folder)

    cmd_str = f"{equivalence_bin} -b {os.path.join(progB_output_dir, progB_file)} -i {os.path.join(progB_output_dir, 'ktest-files')} -m {os.path.join(progB_output_dir, 'map-results')} -d {progB_testB_folder}"
    os.system(cmd_str)

    # Compare the outputs of the two programs
    # Get the list of files in the first program's output folder, every entry should have the absolute path
    progA_testB_files = os.listdir(progA_testB_folder)

    # Get the list of files in the second program's output folder
    progB_testB_files = os.listdir(progB_testB_folder)

    # Check if the two lists are the same
    if len(progA_testB_folder) != len(progB_testB_folder):
        logger.error('The list of files in the two output folders are not the same')
        return False

    # Sort the two lists
    progA_testB_files.sort()
    progB_testB_files.sort()

    # for every file I want to append the absolute path to the file name
    for i in range(len(progA_testB_files)):
        progA_testB_files[i] = os.path.join(progA_testB_folder, progA_testB_files[i])

    # for every file I want to append the absolute path to the file name
    for i in range(len(progB_testB_files)):
        progB_testB_files[i] = os.path.join(progB_testB_folder, progB_testB_files[i])

    # Compare the two lists
    for i in range(len(progA_testB_files)):
        if not compare_json_files(progA_testB_files[i], progB_testB_files[i]):
            equivalent = False
            logger.debug(f"Test case {progA_testB_files[i]} is not equivalent to test case {progB_testB_files[i]}")

    return equivalent

    
def main(progA, progB, equivalence_bin, output_dir):
    logger.debug('Starting equivalence check')

    progA_output_dir = "progA_test_cases"
    progB_output_dir = "progB_test_cases"

    generate_test_cases(progA, progA_output_dir, output_dir)
    generate_test_cases(progB, progB_output_dir, output_dir)

    logger.info(f"Compiling original program A in {progA}")
    # Now that the test cases are generated, I need to compile the original program
    cmd = f"cd {progA} && make build-original"
    result = subprocess.run(cmd, shell=True, capture_output=True)

    if result.returncode != 0:
        logger.error(f"Failed to compile original program: {result.stderr.decode()}")
        sys.exit(1)

    # Search for a file with the .bpf.o extension inside progA
    progA_file = None
    for file in os.listdir(progA):
        if file.endswith('.bpf.o'):
            progA_file = file
            break
    
    if progA_file is None:
        logger.error('No .bpf.o file found in first BPF program directory')
        sys.exit(1)

    # Copy file inside the progA_output_dir
    with open(f"{os.path.join(progA, progA_file)}", 'rb') as progA_file_obj:
        with open(f"{os.path.join(output_dir, progA_output_dir, progA_file)}", 'wb') as progA_output_file_obj:
            progA_output_file_obj.write(progA_file_obj.read())
    
    logger.info(f"Compiling original program B in {progB}")
    # Compile the original program for progB
    cmd = f"cd {progB} && make build-original"
    result = subprocess.run(cmd, shell=True, capture_output=True)

    if result.returncode != 0:
        logger.error(f"Failed to compile original program: {result.stderr.decode()}")
        sys.exit(1)
    
    # Search for a file with the .bpf.o extension inside progB
    progB_file = None
    for file in os.listdir(progB):
        if file.endswith('.bpf.o'):
            progB_file = file
            break
    
    if progB_file is None:
        logger.error('No .bpf.o file found in second BPF program directory')
        sys.exit(1)
    
    # Copy file inside the progB_output_dir    
    with open(f"{os.path.join(progB, progB_file)}", 'rb') as progB_file_obj:
        with open(f"{os.path.join(output_dir, progB_output_dir, progB_file)}", 'wb') as progB_output_file_obj:
            progB_output_file_obj.write(progB_file_obj.read())

    # Run the equivalence check binary
    logger.info("Running equivalence check binary")

    equivalence = check_equivalence(os.path.join(output_dir, progA_output_dir), progA_file, os.path.join(output_dir, progB_output_dir), progB_file, equivalence_bin, output_dir)
    
    if equivalence:
        logger.info("The two programs are equivalent")
    else:
        logger.error("The two programs are not equivalent")

if __name__ == '__main__':
    logger = logging.getLogger("Equivalence Checker")
    logger.setLevel(logging.DEBUG)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    ch.setFormatter(CustomFormatter())

    logger.addHandler(ch)

    # Use argparse to parse command line arguments
    parser = argparse.ArgumentParser(description='Check equivalence of two BPF programs', formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('progA', metavar='PROG_A_FOLDER', type=str, help='path to folder of first BPF program')
    parser.add_argument('progB', metavar='PROG_B_FOLDER', type=str, help='path to folder of second BPF program')
    parser.add_argument('--docker-image', type=str, required=False, default="sebymiano/pix-klee:latest", help='name of the docker image to use')
    parser.add_argument('-b', '--equivalence-bin', type=str, default="equivalence_check", help='path to equivalence check binary')
    parser.add_argument('-o', '--output-dir', type=str, default="output", help='path to output directory')
    args = parser.parse_args()

    docker_image = args.docker_image

    # Check if the directory paths are valid
    if not os.path.isdir(args.progA):
        logger.error('Invalid path to first BPF program')
        sys.exit(1)
    else:
        args.progA = os.path.abspath(args.progA)

    if not os.path.isdir(args.progB):
        logger.error('Invalid path to second BPF program')
        sys.exit(1)
    else:
        args.progB = os.path.abspath(args.progB)

    # Run the equivalence check binary to see if it works using the subprocess module
    logger.info("Running equivalence check binary")
    try:
        subprocess.run([args.equivalence_bin, "--help"], capture_output=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.error(f"Equivalence check binary ({args.equivalence_bin}) is not available")
        sys.exit(1)    

    # Let's now check if the docker container is available
    logger.info("Initializing docker client")
    docker_client = docker.from_env()

    response = docker_client.containers.run(docker_image, "echo hello world", remove=True)
    if response.decode("utf-8") != "hello world\n":
        logger.error("Docker container is not available")
        sys.exit(1)

    # Check if the output directory exists
    if os.path.isdir(args.output_dir):
        logger.warning(f"Output directory {args.output_dir} already exists, it will be overwritten")
        # remove it
        os.system(f"rm -rf {args.output_dir}")
    else:
        os.makedirs(args.output_dir)

    main(args.progA, args.progB, args.equivalence_bin, args.output_dir)