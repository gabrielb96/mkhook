#!/usr/bin/bash

progname="vulnerable_program"
shellcode="shellcode.bin"

if [[ ! -x /usr/bin/nasm ]]; then
	echo "nasm assembler is required to build the shellcode"
	exit 1
fi

gcc example_vulnerable_program.c -o ${progname}
nasm -f elf64 example_shellcode.asm

text_offset="0x$(readelf -S example_shellcode.o | grep '\B\.text' | awk '{print $6}')"
text_len="0x$(readelf -S example_shellcode.o | grep '\B\.text' -A1 | grep X | awk '{print $1}')"

xxd -s ${text_offset} -l ${text_len} -o -${text_offset} example_shellcode.o | xxd -r > ${shellcode}

echo "Vulnerable program: ${progname}"
echo "Shellcode: ${shellcode}"
