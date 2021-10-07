package datatypes

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Instruction, with Displacement and Immediate stored as little-endian byte arrays.
type Instruction struct {
	Literal      []byte
	Offset       int
	Label        string
	Pre          *Prefix
	Mnemonic     string
	Op           byte
	Modrm        *ModRm
	Displacement []byte
	Immediate    []byte
	DispSize     int
	ImmSize      int
	Operands     string
}

// Prefix Bytes
type Prefix struct {
	Literal  byte
	Mnemonic string
}

// MODRM Byte
type ModRm struct {
	Literal byte
	Mod     AddressMode
	Reg     Register
	RM      Register
}

// SIB Byte
// type SIB struct {
// 	Literal byte
// 	Scale   int
// 	Index   Register
// 	Base    Register
// }

// MODRM Address Modes
type AddressMode byte

const (
	AM_REG          = AddressMode(byte(0))
	AM_BYTE_OFFSET  = AddressMode(byte(1))
	AM_DWORD_OFFSET = AddressMode(byte(2))
	AM_DIRECT       = AddressMode(byte(3))
)

// X86 Registers
type Register int

const (
	REG_EAX = Register(0)
	REG_ECX = Register(1)
	REG_EDX = Register(2)
	REG_EBX = Register(3)
	REG_ESP = Register(4)
	REG_EBP = Register(5)
	REG_ESI = Register(6)
	REG_EDI = Register(7)
)

var Registers = make(map[Register]string)

func init() {
	Registers[REG_EAX] = "eax"
	Registers[REG_ECX] = "ecx"
	Registers[REG_EDX] = "edx"
	Registers[REG_EBX] = "ebx"
	Registers[REG_ESP] = "esp"
	Registers[REG_EBP] = "ebp"
	Registers[REG_ESI] = "esi"
	Registers[REG_EDI] = "edi"
}

func ParseModRM(modrm byte) *ModRm {
	mod := AddressMode(modrm >> 6 & 3)
	reg := Register(int((modrm >> 3) & 7))
	rm := Register(int(modrm & 7))

	return &ModRm{
		Literal: modrm,
		Mod:     mod,
		Reg:     reg,
		RM:      rm,
	}
}

func ParseDisplacement(modrm *ModRm, data *bytes.Buffer, size int) ([]byte, error) {
	var err error
	var displacement []byte
	var disp byte

	if modrm != nil {
		switch modrm.Mod {

		case AM_REG:
			if modrm.RM == REG_EBP {
				if displacement = data.Next(4); len(displacement) != 4 {
					return displacement, io.ErrUnexpectedEOF
				} else {
					return displacement, nil
				}
			}
			return nil, nil

		case AM_BYTE_OFFSET:
			if disp, err = data.ReadByte(); err != nil {
				return nil, io.ErrUnexpectedEOF
			} else {
				return []byte{disp}, nil
			}

		case AM_DWORD_OFFSET:
			if displacement = data.Next(4); len(displacement) != 4 {
				return displacement, io.ErrUnexpectedEOF
			} else {
				return displacement, nil
			}

		case AM_DIRECT:
			return nil, nil

		default:
			return nil, fmt.Errorf("Bad Address Mode.")
		}
	}

	// No MODRM. Displacement is part of opcode, either 1 or 4 bytes.
	if displacement = data.Next(size); len(displacement) != size {
		return displacement, io.ErrUnexpectedEOF
	} else {
		return displacement, nil
	}
}

func ParseImmediate(data *bytes.Buffer, size int) ([]byte, error) {
	var err error
	var immediate []byte

	if immediate = data.Next(size); len(immediate) != size {
		err = io.ErrUnexpectedEOF
	}
	return immediate, err
}

// Stringify the RM part of MODRM, depending on the Addressing Mode.
func StringifyRM(modrm *ModRm, disp []byte) string {
	if modrm != nil {
		rm := Registers[modrm.RM]

		switch modrm.Mod {

		case AM_REG:
			if modrm.RM == REG_EBP {
				return fmt.Sprintf("[ %s ]", StringifyIntegerBytes(disp))
			}
			return fmt.Sprintf("[ %s ]", rm)

		case AM_BYTE_OFFSET, AM_DWORD_OFFSET:
			return fmt.Sprintf("[ %s+%s ]", rm, StringifyIntegerBytes(disp))

		case AM_DIRECT:
			return rm

		default:
			return ""
		}
	}
	return ""
}

// Convert a little-endian byte slice to the signed integer it represents.
func BytesToIntSigned(intbytes []byte) (int, error) {
	switch len(intbytes) {
	case 1:
		return int(int8(intbytes[0])), nil
	case 2:
		return int(int16(binary.LittleEndian.Uint16(intbytes))), nil
	case 4:
		return int(int32(binary.LittleEndian.Uint32(intbytes))), nil
	default:
		return 0, fmt.Errorf("Invalid byte slice length for integer conversion: %d", len(intbytes))
	}
}

// Convert a little-endian byte slice to the integer it represents without two's complementing.
func BytesToInt(intbytes []byte) (int, error) {
	switch len(intbytes) {
	case 1:
		return int(intbytes[0]), nil
	case 2:
		return int(binary.LittleEndian.Uint16(intbytes)), nil
	case 4:
		return int(binary.LittleEndian.Uint32(intbytes)), nil
	default:
		return 0, fmt.Errorf("Invalid byte slice length for integer conversion: %d", len(intbytes))
	}
}

// Stringify an integer as hex with zero-padding.
func StringifyInteger(integer int) string {
	return fmt.Sprintf("0x%08x", integer)
}

// Convert a little-endian byte slice representing an integer into a hex string.
func StringifyIntegerBytes(intbytes []byte) string {
	var integer int
	var err error

	if integer, err = BytesToInt(intbytes); err != nil {
		return ""
	}

	return fmt.Sprintf("0x%08x", integer)
}
