#!/bin/sh

ARCH=amd64
LLVM=11
UBUNTU=18.04
OS=linux


if [ $# -ne 2 ]; then 
	echo -e "Invalid Arguments!\nUsage: \n\t$0 <inputbinary> <outputbc>"
	exit 1
fi

INPUT=$1
OUTPUT=$2

docker run --rm -it --entrypoint=mcsema-disass --ipc=host -v "$(pwd)":/mcsema/local mcsema:llvm${LLVM}-ubuntu${UBUNTU}-${ARCH} --disassembler /opt/ghidra/support/analyzeHeadless --arch ${ARCH} --os ${OS} --log_file /mcsema/local/mcsema_disass.log --output /mcsema/local/disass.cfg --binary /mcsema/local/${INPUT} \
&& docker run --rm -it --ipc=host -v "$(pwd)":/mcsema/local mcsema:llvm${LLVM}-ubuntu${UBUNTU}-${ARCH} --output /mcsema/local/${OUTPUT} --arch ${ARCH} --os ${OS} --cfg /mcsema/local/disass.cfg
