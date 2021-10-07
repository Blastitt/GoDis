package operations

import (
	"bytes"
	"disassembler/datatypes"
	"disassembler/encoders"
	"errors"
	"fmt"
	"io"
)

// OpCode
type OpCode struct {
	Literal      byte
	Mnemonic     string
	Encoder      encoders.Encoder
	ModrmReq     bool
	ExtensionReq bool
	PrefixReq    bool
	Extension    int
	DispSize     int
	ImmSize      int
}

var (
	Vex, Repne *datatypes.Prefix

	Prefixes = make(map[byte]*datatypes.Prefix)

	OpCodes         = make(map[byte]*OpCode)
	OpCodesExt      = make(map[byte]map[int]*OpCode)
	OpCodesPrefixed = make(map[byte]*OpCode)

	Op81 = make(map[int]*OpCode)
	OpFF = make(map[int]*OpCode)
	OpAE = make(map[int]*OpCode)
	OpF7 = make(map[int]*OpCode)
	OpC7 = make(map[int]*OpCode)
	Op8F = make(map[int]*OpCode)
	OpD1 = make(map[int]*OpCode)

	allOps []*OpCode

	ONF = errors.New("ONF") // Op Not Found
)

func init() {

	Vex = &datatypes.Prefix{
		Literal:  0x0F,
		Mnemonic: "",
	}

	Repne = &datatypes.Prefix{
		Literal:  0xF2,
		Mnemonic: "repne",
	}

	Prefixes[0x0F] = Vex
	Prefixes[0xF2] = Repne

	OpCodesExt[0x81] = Op81
	OpCodesExt[0xFF] = OpFF
	OpCodesExt[0xAE] = OpAE
	OpCodesExt[0xF7] = OpF7
	OpCodesExt[0xC7] = OpC7
	OpCodesExt[0x8F] = Op8F
	OpCodesExt[0xD1] = OpD1

	allOps = []*OpCode{

		// ADD
		{
			Literal:      0x05,
			Mnemonic:     "add eax,",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x81,
			Mnemonic:     "add",
			Encoder:      encoders.MI{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    0,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x01,
			Mnemonic:     "add",
			Encoder:      encoders.MR{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x03,
			Mnemonic:     "add",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// AND
		{
			Literal:      0x25,
			Mnemonic:     "and eax,",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x81,
			Mnemonic:     "and",
			Encoder:      encoders.MI{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    4,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x21,
			Mnemonic:     "and",
			Encoder:      encoders.MR{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x23,
			Mnemonic:     "and",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// CALL
		{
			Literal:      0xE8,
			Mnemonic:     "call",
			Encoder:      encoders.D{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     4,
			ImmSize:      0,
		},
		{
			Literal:      0xFF,
			Mnemonic:     "call",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    2,
			DispSize:     0,
			ImmSize:      0,
		},

		// CLFLUSH
		{
			Literal:      0xAE,
			Mnemonic:     "clflush",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			PrefixReq:    true,
			Extension:    7,
			DispSize:     0,
			ImmSize:      0,
		},

		// CMP
		{
			Literal:      0x3D,
			Mnemonic:     "cmp eax,",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x81,
			Mnemonic:     "cmp",
			Encoder:      encoders.MI{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    7,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x39,
			Mnemonic:     "cmp",
			Encoder:      encoders.MR{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x3B,
			Mnemonic:     "cmp",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// DEC
		{
			Literal:      0xFF,
			Mnemonic:     "dec",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    1,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x48,
			Mnemonic:     "dec",
			Encoder:      encoders.O{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// IDIV
		{
			Literal:      0xF7,
			Mnemonic:     "idiv",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    7,
			DispSize:     0,
			ImmSize:      0,
		},

		// IMUL
		{
			Literal:      0xF7,
			Mnemonic:     "imul",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    5,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0xAF,
			Mnemonic:     "imul",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			PrefixReq:    true,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x69,
			Mnemonic:     "imul",
			Encoder:      encoders.RMI{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},

		// INC
		{
			Literal:      0xFF,
			Mnemonic:     "inc",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    0,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x40,
			Mnemonic:     "inc",
			Encoder:      encoders.O{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// JMP
		{
			Literal:      0xEB,
			Mnemonic:     "jmp",
			Encoder:      encoders.D{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     1,
			ImmSize:      0,
		},
		{
			Literal:      0xE9,
			Mnemonic:     "jmp",
			Encoder:      encoders.D{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     4,
			ImmSize:      0,
		},
		{
			Literal:      0xFF,
			Mnemonic:     "jmp",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    4,
			DispSize:     0,
			ImmSize:      0,
		},

		// JZ
		{
			Literal:      0x74,
			Mnemonic:     "jz",
			Encoder:      encoders.D{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     1,
			ImmSize:      0,
		},
		{
			Literal:      0x84,
			Mnemonic:     "jz",
			Encoder:      encoders.D{},
			ModrmReq:     false,
			ExtensionReq: false,
			PrefixReq:    true,
			DispSize:     4,
			ImmSize:      0,
		},

		// JNZ
		{
			Literal:      0x75,
			Mnemonic:     "jnz",
			Encoder:      encoders.D{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     1,
			ImmSize:      0,
		},
		{
			Literal:      0x85,
			Mnemonic:     "jnz",
			Encoder:      encoders.D{},
			ModrmReq:     false,
			ExtensionReq: false,
			PrefixReq:    true,
			DispSize:     4,
			ImmSize:      0,
		},

		// LEA
		{
			Literal:      0x8D,
			Mnemonic:     "lea",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// MOV
		{
			Literal:      0xB8,
			Mnemonic:     "mov",
			Encoder:      encoders.OI{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0xC7,
			Mnemonic:     "mov",
			Encoder:      encoders.MI{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    0,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x89,
			Mnemonic:     "mov",
			Encoder:      encoders.MR{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x8B,
			Mnemonic:     "mov",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// MOVSD
		{
			Literal:      0xA5,
			Mnemonic:     "movsd",
			Encoder:      encoders.NP{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// MUL
		{
			Literal:      0xF7,
			Mnemonic:     "mul",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    4,
			DispSize:     0,
			ImmSize:      0,
		},

		// NEG
		{
			Literal:      0xF7,
			Mnemonic:     "neg",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    3,
			DispSize:     0,
			ImmSize:      0,
		},

		// NOP
		{
			Literal:      0x90,
			Mnemonic:     "nop",
			Encoder:      encoders.NP{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// NOT
		{
			Literal:      0xF7,
			Mnemonic:     "not",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    2,
			DispSize:     0,
			ImmSize:      0,
		},

		// OR
		{
			Literal:      0x0D,
			Mnemonic:     "or eax,",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x81,
			Mnemonic:     "or",
			Encoder:      encoders.MI{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    1,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x09,
			Mnemonic:     "or",
			Encoder:      encoders.MR{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x0B,
			Mnemonic:     "or",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// OUT
		{
			Literal:      0xE7,
			Mnemonic:     "out %s, eax",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      1,
		},

		// POP
		{
			Literal:      0x8F,
			Mnemonic:     "pop",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    0,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x58,
			Mnemonic:     "pop",
			Encoder:      encoders.O{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// PUSH
		{
			Literal:      0xFF,
			Mnemonic:     "push",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    6,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x50,
			Mnemonic:     "push",
			Encoder:      encoders.O{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x68,
			Mnemonic:     "push",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},

		// CMPSD
		{
			Literal:      0xA7,
			Mnemonic:     "cmpsd",
			Encoder:      encoders.NP{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// RETF
		// if you didn't scroll past this you get extra credit.
		{
			Literal:      0xCB,
			Mnemonic:     "retf",
			Encoder:      encoders.NP{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0xCA,
			Mnemonic:     "retf",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      2,
		},
		{
			Literal:      0xC3,
			Mnemonic:     "retn",
			Encoder:      encoders.NP{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0xC2,
			Mnemonic:     "retn",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      2,
		},

		// SAL, SAR, SHR
		{
			Literal:      0xD1,
			Mnemonic:     "sal %s, 1",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    4,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0xD1,
			Mnemonic:     "sar %s, 1",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    7,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0xD1,
			Mnemonic:     "shr %s, 1",
			Encoder:      encoders.M{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    5,
			DispSize:     0,
			ImmSize:      0,
		},

		// SBB
		{
			Literal:      0x1D,
			Mnemonic:     "sbb eax,",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x81,
			Mnemonic:     "sbb",
			Encoder:      encoders.MI{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    3,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x19,
			Mnemonic:     "sbb",
			Encoder:      encoders.MR{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x1B,
			Mnemonic:     "sbb",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// SUB
		{
			Literal:      0x2D,
			Mnemonic:     "sub eax,",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x81,
			Mnemonic:     "sub",
			Encoder:      encoders.MI{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    5,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x29,
			Mnemonic:     "sub",
			Encoder:      encoders.MR{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x2B,
			Mnemonic:     "sub",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// TEST
		{
			Literal:      0xA9,
			Mnemonic:     "test eax,",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0xF7,
			Mnemonic:     "test",
			Encoder:      encoders.MI{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    0,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x85,
			Mnemonic:     "test",
			Encoder:      encoders.MR{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},

		// XOR
		{
			Literal:      0x35,
			Mnemonic:     "xor eax,",
			Encoder:      encoders.I{},
			ModrmReq:     false,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x81,
			Mnemonic:     "xor",
			Encoder:      encoders.MI{},
			ModrmReq:     true,
			ExtensionReq: true,
			Extension:    6,
			DispSize:     0,
			ImmSize:      4,
		},
		{
			Literal:      0x31,
			Mnemonic:     "xor",
			Encoder:      encoders.MR{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
		{
			Literal:      0x33,
			Mnemonic:     "xor",
			Encoder:      encoders.RM{},
			ModrmReq:     true,
			ExtensionReq: false,
			DispSize:     0,
			ImmSize:      0,
		},
	}

	// Populate the Ops maps.
	for _, op := range allOps {
		if op.ExtensionReq {
			OpCodesExt[op.Literal][op.Extension] = op
		} else if op.PrefixReq {
			OpCodesPrefixed[op.Literal] = op
		} else {
			if op.Encoder.Encoding() == "O" || op.Encoder.Encoding() == "OI" {
				for i := int(op.Literal); i < int(op.Literal)+7; i++ {
					OpCodes[byte(i)] = op
				}
			} else {
				OpCodes[op.Literal] = op
			}
		}
	}

}

func (o *OpCode) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	var err error
	inst.Mnemonic = o.Mnemonic
	inst.DispSize = o.DispSize
	inst.ImmSize = o.ImmSize
	err = o.Encoder.Encode(data, inst)
	return err
}

// Parses the next operation from the data buffer and returns the OpCode and Prefix byte.
func GetNext(data *bytes.Buffer) (*OpCode, *datatypes.Prefix, byte, error) {
	var err error
	var next byte

	if next, err = data.ReadByte(); err != nil {
		return nil, nil, 0x00, io.EOF
	}

	prefix, exists := Prefixes[next]
	if exists {
		var code byte
		if code, err = data.ReadByte(); err != nil {
			return nil, prefix, 0x00, io.ErrUnexpectedEOF
		}

		switch prefix {
		case Vex:
			if opcode, ok := OpCodesPrefixed[code]; ok {
				return opcode, prefix, code, nil
			} else if code == 0xAE { // CLFLUSH is a chimera.
				op, err := GetExtendedOpcode(code, data)
				return op, prefix, code, err
			} else {
				data.UnreadByte()
				return nil, prefix, 0x00, fmt.Errorf("db %02x", prefix.Literal)
			}
		case Repne:
			if opcode, ok := OpCodes[code]; ok {
				return opcode, prefix, code, nil
			} else {
				return nil, prefix, code, fmt.Errorf("db %02x", code)
			}
		default:
			data.UnreadByte()
			return nil, prefix, 0x00, fmt.Errorf("db %02x", prefix.Literal)
		}
	} else {
		opcode, err := GetExtendedOpcode(next, data)

		if err != ONF {
			return opcode, nil, next, err
		}

		if opcode, ok := OpCodes[next]; ok {
			return opcode, nil, next, nil
		} else {
			return nil, nil, next, fmt.Errorf("db %02x", next)
		}

	}
}

func GetExtendedOpcode(opcode byte, data *bytes.Buffer) (*OpCode, error) {
	if opcode_map, ok := OpCodesExt[opcode]; ok {
		var modrm_byte byte
		var err error
		if modrm_byte, err = data.ReadByte(); err != nil {
			return nil, io.ErrUnexpectedEOF
		}

		modrm := datatypes.ParseModRM(modrm_byte)

		if code, ok := opcode_map[int(modrm.Reg)]; ok {
			data.UnreadByte()
			return code, nil
		} else {
			// Bad extension, treat like unknown opcode
			data.UnreadByte()
			return nil, fmt.Errorf("db %02x", opcode)
		}
	} else {
		return nil, ONF
	}
}
