#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===-- ktest-tool --------------------------------------------------------===##
# 
#                      The KLEE Symbolic Virtual Machine
# 
#  This file is distributed under the University of Illinois Open Source
#  License. See LICENSE.TXT for details.
# 
# ===----------------------------------------------------------------------===##

import binascii
import io
import string
import struct
import sys
import os

import json
import re
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from textwrap import dedent

version_no=4

pattern_val_in_map = re.compile(r'val_(\d+)_in_([\w]+)')
pattern_val = re.compile(r'val_(\d+)_(\w+)')
pattern_key = re.compile(r'key_(\d+)_(\w+)')

class KTestError(Exception):
    pass


class KTest:
    valid_chars = string.digits + string.ascii_letters + string.punctuation + ' '

    @staticmethod
    def fromfile(path):
        try:
            f = open(path, 'rb')
        except IOError:
            print('ERROR: file %s not found' % path)
            sys.exit(1)

        hdr = f.read(5)
        if len(hdr) != 5 or (hdr != b'KTEST' and hdr != b'BOUT\n'):
            raise KTestError('unrecognized file')
        version, = struct.unpack('>i', f.read(4))
        if version > version_no:
            raise KTestError('unrecognized version')
        numArgs, = struct.unpack('>i', f.read(4))
        args = []
        for i in range(numArgs):
            size, = struct.unpack('>i', f.read(4))
            args.append(str(f.read(size).decode(encoding='ascii')))

        if version >= 2:
            symArgvs, = struct.unpack('>i', f.read(4))
            symArgvLen, = struct.unpack('>i', f.read(4))
        else:
            symArgvs = 0
            symArgvLen = 0

        numObjects, = struct.unpack('>i', f.read(4))
        objects = []
        for i in range(numObjects):
            size, = struct.unpack('>i', f.read(4))
            name = f.read(size).decode('utf-8')
            size, = struct.unpack('>i', f.read(4))
            bytes = f.read(size)
            objects.append((name, bytes))

        havocs = []
        if version >= 4:
            numHavocs, = struct.unpack('>i', f.read(4))
            for i in range(numHavocs):
                size, = struct.unpack('>i', f.read(4))
                name = f.read(size)
                size, = struct.unpack('>i', f.read(4))
                bytes = f.read(size)
                mask_size = int((size + 31)/32*4)
                mask = f.read(mask_size)
                havocs.append( (name,bytes,mask) )
        # Create an instance
        b = KTest(version, path, args, symArgvs, symArgvLen, objects,havocs)
        return b

    def __init__(self, version, path, args, symArgvs, symArgvLen, objects,havocs):
        self.version = version
        self.path = path
        self.symArgvs = symArgvs
        self.symArgvLen = symArgvLen
        self.args = args
        self.objects = objects
        self.havocs = havocs

    def __format__(self, format_spec):
        sio = io.StringIO()
        width = str(len(str(max(1, len(self.objects) - 1))))

        # print ktest info
        print('ktest file : %r' % self.path, file=sio)
        print('args       : %r' % self.args, file=sio)
        print('num objects: %r' % len(self.objects), file=sio)

        # format strings
        fmt = dict()
        fmt['name'] = "object {0:" + width + "d}: name: '{1}'"
        fmt['size'] = "object {0:" + width + "d}: size: {1}"
        fmt['int' ] = "object {0:" + width + "d}: int : {1}"
        fmt['uint'] = "object {0:" + width + "d}: uint: {1}"
        fmt['data'] = "object {0:" + width + "d}: data: {1}"
        fmt['hex' ] = "object {0:" + width + "d}: hex : 0x{1}"
        fmt['text'] = "object {0:" + width + "d}: text: {1}"

        fmt['havoc_name' ] = "havoc {0:" + width + "d}: name: '{1}'"
        fmt['havoc_size' ] = "havoc {0:" + width + "d}: size: {1}"
        fmt['havoc_mask' ] = "havoc {0:" + width + "d}: mask : {1}"
        fmt['havoc_int'  ] = "havoc {0:" + width + "d}: int : {1}"
        fmt['havoc_uint' ] = "havoc {0:" + width + "d}: uint: {1}"
        
        def p(key, arg): print(fmt[key].format(i, arg), file=sio)

        # print objects
        for i, (name, data) in enumerate(self.objects):
            blob = data.rstrip(b'\x00') if format_spec.endswith('trimzeros') else data
            txt = ''.join(c if c in self.valid_chars else '.' for c in blob.decode('ascii', errors='replace').replace('�', '.'))
            size = len(data)

            p('name', name)
            p('size', size)
            p('data', blob)
            p('hex', binascii.hexlify(blob).decode('ascii'))
            for n, m in [(1, 'b'), (2, 'h'), (4, 'i'), (8, 'q')]:
                if size == n:
                    p('int', struct.unpack(m, data)[0])
                    p('uint', struct.unpack(m.upper(), data)[0])
                    break
            p('text', txt)

        # print havocs
        for i,(name, data, mask) in enumerate(self.havocs):
            blob = data.rstrip(b'\x00') if format_spec.endswith('trimzeros') else data
            size = len(data)
            p('havoc_name',name)
            p('havoc_size',size)
            p('havoc_mask',mask)
            for n, m in [(1, 'b'), (2, 'h'), (4, 'i'), (8, 'q')]:
                if size == n:
                    p('havoc_int', struct.unpack(m, data)[0])
                    p('havoc_uint', struct.unpack(m.upper(), data)[0])
                    break
                
        return sio.getvalue()

    def extract(self, object_names, trim_zeros):
        for name, data in self.objects:
            if name not in object_names:
                continue

            f = open(self.path + '.' + name, 'wb')
            blob = data.rstrip(b'\x00') if trim_zeros else data
            f.write(blob)
            f.close()

def main():
    ap = ArgumentParser(prog='consolidate-test-cases', formatter_class=RawDescriptionHelpFormatter, description="Program to consolidate test cases into a single file.")
    ap.add_argument('-v', '--values-dir', type=str, help='Directory with the values files (.ktest)')
    ap.add_argument('-k', '--keys-dir', type=str, help='Directory with the keys files (.json)')
    ap.add_argument('-o', '--output-dir', type=str, help='Output directory')
    args = ap.parse_args()

    # Scan for all the files in the values directory with the .ktest extension
    values_files = []
    for root, dirs, files in os.walk(args.values_dir):
        for file in files:
            if file.endswith(".ktest"):
                # append the file to the list with the absolute path
                values_files.append(os.path.abspath(os.path.join(root, file)))
    
    # Scan for all the files in the keys directory with the .json extension
    keys_files = []
    for root, dirs, files in os.walk(args.keys_dir):
        for file in files:
            if file.endswith(".json"):
                keys_files.append(os.path.abspath(os.path.join(root, file)))


    # Sort the values_files array by the name of the file
    values_files.sort(key=lambda f: int(''.join(filter(str.isdigit, f))))

    # Create the output directory if it does not exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    # Consolidate the test cases
    for file in values_files:
        map_results_dict = dict()
        # Get the name of the file without the extension
        file_name = os.path.splitext(os.path.basename(file))[0]
        
        # Find the corresponding keys file
        keys_file = [x for x in keys_files if file_name in x]

        if len(keys_file) != 1:
            print(f"ERROR: There should be exactly one keys file for each values file {len(keys_file)} != 1")
            sys.exit(1)
        key_file = keys_file[0]
        
        ktest = KTest.fromfile(file)
        ktest.extract(list(), False)

        # Parse json file from key_file
        with open(key_file) as json_file:
            key_data = json.load(json_file)

        # For every object in the ktest file we need to find the ones related to the maps
        # They all start with val_<lookup>_<map_name>        

        for name, data in ktest.objects:
            match_val_in_map = pattern_val_in_map.match(name)

            if match_val_in_map:
                lookup = match_val_in_map.group(1)
                map_name = match_val_in_map.group(2)

                # Create the map in the results dict if it does not exist
                if map_name not in map_results_dict:
                    map_results_dict[map_name] = dict()

                # Create the lookup in the results dict if it does not exist
                if lookup not in map_results_dict[map_name]:
                    map_results_dict[map_name][lookup] = dict()

                # Check if the format is the one we expect
                if len(data) != 4:
                    print(f"ERROR: Unexpected format for {name}")
                    sys.exit(1)

                data_int = struct.unpack('I', data)[0]

                if data_int == 0:
                    map_results_dict[map_name][lookup]['hasValue'] = False
                else:
                    map_results_dict[map_name][lookup]['hasValue'] = True

                continue

            match_val = pattern_val.match(name)

            if match_val:
                lookup = match_val.group(1)
                map_name = match_val.group(2)

                key_pattern = f'key_{lookup}_{map_name}'

                # Find the key in the key_data
                if key_pattern not in key_data:
                    print(f"ERROR: Key {key_pattern} not found in {key_file}")
                    sys.exit(1)
                
                key_val = key_data[key_pattern]

                # Create the map in the results dict if it does not exist
                if map_name not in map_results_dict:
                    map_results_dict[map_name] = dict()

                # Create the lookup in the results dict if it does not exist
                if lookup not in map_results_dict[map_name]:
                    map_results_dict[map_name][lookup] = dict()

                bin_key = bytes.fromhex(key_val[2:])

                map_results_dict[map_name][lookup]['key'] = binascii.hexlify(bin_key).decode('ascii')
                map_results_dict[map_name][lookup]['key_size'] = len(bin_key)
                map_results_dict[map_name][lookup]['value'] = binascii.hexlify(data).decode('ascii')
                map_results_dict[map_name][lookup]['value_size'] = len(data)

        # Create the output file
        output_file = os.path.join(args.output_dir, f'{file_name}.json')

        with open(output_file, 'w') as outfile:
            json.dump(map_results_dict, outfile, indent=4)

        print(f"INFO: Map results stored in {output_file}")
        

if __name__ == '__main__':
    main()