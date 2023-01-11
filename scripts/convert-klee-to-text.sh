#!/bin/bash

OUTDIR="ktest-text"
mkdir -p ${OUTDIR}

for filename in ./test*.ktest; do
  ktest-tool ${filename} > ${OUTDIR}/${filename%.*}.txt
done

