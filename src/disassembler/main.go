package main

import (
	"bytes"
	"disassembler/datatypes"
	"disassembler/operations"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

// Global maps
var Instructions = make(map[int]*datatypes.Instruction)

// Command line argument
var infile string

func init() {

	flag.StringVar(&infile, "i", "", "File to disassemble.")
	flag.Parse()
}

func main() {
	// Parse instructions from file
	if infile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var f *os.File
	var data = new(bytes.Buffer)
	var err error

	if f, err = os.Open(infile); err != nil {
		log.Fatalf("Error opening file: %s", err)
	}

	if err = ReadAll(data, f); err != nil {
		log.Fatalf("Error reading file: %s", err)
	}

	Parse_Instructions(data)

	// Print out each instruction
	Print_Instructions()
}

func Parse_Instructions(data *bytes.Buffer) error {
	var opcode *operations.OpCode
	var prefix *datatypes.Prefix
	var opcode_literal byte

	var err error

	var offset int = 0

	for {

		// Grab the instruction from the master map if it exists, or create a new one.
		instruction := &datatypes.Instruction{}
		if inst, exists := Instructions[offset]; exists {
			instruction = inst
		}

		// Consume the next opcode from the input.
		opcode, prefix, opcode_literal, err = operations.GetNext(data)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}

			// Handle unknown OpCode
			instruction.Offset = offset
			instruction.Mnemonic = err.Error()
			instruction.Literal = append(instruction.Literal, opcode_literal)
			Instructions[offset] = instruction
			offset += 1
			continue
		}

		// Start building the instruction
		instruction.Offset = offset
		instruction.Pre = prefix
		instruction.Op = opcode_literal

		if prefix != nil {
			instruction.Literal = append(instruction.Literal, prefix.Literal)
		}
		instruction.Literal = append(instruction.Literal, opcode_literal)

		if err = opcode.Encode(data, instruction); err != nil {
			// This should basically never happen.
			fmt.Printf("Error encoding: %s\n", err)
		}

		// Add labels to other instructions if instruction has an offset as an operand.
		var other_offset int
		var is_offset bool

		if instruction.Operands, other_offset, is_offset, err = opcode.Encoder.StringifyOperands(instruction); err != nil {
			// This also shouldn't really happen.
			fmt.Printf("Error stringifying: %s\n", err)
		}
		if is_offset {
			other_instruction := &datatypes.Instruction{
				Offset: other_offset,
			}
			if other_inst, exists := Instructions[other_offset]; exists {
				other_instruction = other_inst
			}
			other_instruction.Label = instruction.Operands
			Instructions[other_offset] = other_instruction
		}

		// Save the instruction to the master map
		Instructions[offset] = instruction

		// Update the offset for the next instruction
		offset += len(instruction.Literal)

	}

	return err
}

func Print_Instructions() {

	// Sort the Instructions map by offset.
	offsets := make([]int, len(Instructions))

	for i := range Instructions {
		offsets = append(offsets, i)
	}

	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

	// Keep track of what we've printed already, and print 3 columns
	// for each Instruction, in order.
	visited := make(map[int]bool)

	t := new(tabwriter.Writer)
	t.Init(os.Stdout, 8, 8, 0, '\t', 0)
	defer t.Flush()

	for _, offset := range offsets {
		instruction := Instructions[offset]

		if len(instruction.Literal) == 0 || visited[offset] {
			continue
		}

		if instruction.Label != "" {
			fmt.Fprintf(t, "%s:\t\t\t\n", instruction.Label)
		}

		ofst := fmt.Sprintf("%08x:", instruction.Offset)

		var literal string
		for _, byte_literal := range instruction.Literal {
			literal += fmt.Sprintf("%02x ", byte_literal)
		}

		var asm string

		if instruction.Pre != nil && instruction.Pre.Mnemonic != "" {
			asm = instruction.Pre.Mnemonic + " "
		}

		if strings.Contains(instruction.Mnemonic, "%s") {
			asm += fmt.Sprintf(instruction.Mnemonic, instruction.Operands)
		} else {
			asm += instruction.Mnemonic + " " + instruction.Operands
		}

		// Check for illegal addressing modes.
		comment := ""

		if (instruction.Mnemonic != "") &&
			(instruction.Mnemonic == operations.OpCodesExt[0xAE][7].Mnemonic || instruction.Mnemonic == operations.OpCodes[0x8D].Mnemonic) &&
			(instruction.Modrm != nil && instruction.Modrm.Mod == datatypes.AM_DIRECT) {
			comment = "; Illegal addressing mode."
		}

		fmt.Fprintf(t, "%s\t%s\t%s\t%s\n", ofst, literal, asm, comment)

		visited[offset] = true

	}

}

func ReadAll(b *bytes.Buffer, f *os.File) error {
	defer f.Close()
	_, err := io.Copy(b, f)
	return err
}
