#!/usr/bin/bash

progname="vulnerable_program"
new_func="new_func.bin"

if [[ ! -x /usr/bin/nasm ]]; then
	echo "nasm assembler is required for building the example"
	exit 1
fi

gcc example_vulnerable_program.c -o ${progname}
nasm -f elf64 example_new_func.asm

text_offset="0x$(readelf -S example_new_func.o | grep '\B\.text' | awk '{print $6}')"
text_len="0x$(readelf -S example_new_func.o | grep '\B\.text' -A1 | grep X | awk '{print $1}')"

xxd -s ${text_offset} -l ${text_len} -o -${text_offset} example_new_func.o | xxd -r > ${new_func}

echo "Vulnerable program: ${progname}"
echo "new_func: ${new_func}"
