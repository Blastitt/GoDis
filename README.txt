GoDis
	GoDis is a linear sweep disassembler written in Go.
	The disassembler does not use any third party libraries.
	It can be compiled for any architecture supported by
	Go, as outline below. GoDis can be run as follows:

	$ godis.exe -i <binary file>


Build
	Install Go version 1.17.1
	Navigate to the src/disassembler directory.
	$ go build -o godis.exe disassembler


Notes
	According to the Intel specification, some of the supported
	instructions are only legal for a limited subset of addressing
	modes. If an instruction is found to have an illegal addressing
	mode, it is still disassembled, and a comment is included about
	the violation of the law, for later review by an x86 magistrate.

	Some opcodes require an opcode extension located in the next byte
	parsed as a MODR/M in order to determine the specific instruction.
	If the extension found in the REG section of the byte parsed as a
	MODR/M is not supported for that opcode, the opcode is listed as
	unknown with a "db <byte>" instruction, and the MODR/M is unread,
	to be parsed as the beginning of the next instruction.