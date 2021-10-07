package encoders

import (
	"bytes"
	"disassembler/datatypes"
	"fmt"
	"io"
)

// Instruction Encodings
type Encoder interface {
	Encode(*bytes.Buffer, *datatypes.Instruction) error
	StringifyOperands(*datatypes.Instruction) (string, int, bool, error)
	Encoding() string
}

type M struct{}
type MI struct{}
type MR struct{}
type RM struct{}
type RMI struct{}
type NP struct{}
type O struct{}
type I struct{}
type OI struct{}
type D struct{}

// ====================================================================================================================
// 															Encoders
// ====================================================================================================================

// Consume the MODRM byte and the Displacement, depending on its Addressing Mode.
func (e M) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	var err error
	var next byte

	if next, err = data.ReadByte(); err != nil {
		return io.ErrUnexpectedEOF
	}

	inst.Modrm = datatypes.ParseModRM(next)
	inst.Literal = append(inst.Literal, inst.Modrm.Literal)
	inst.Displacement, err = datatypes.ParseDisplacement(inst.Modrm, data, 0)
	inst.Literal = append(inst.Literal, inst.Displacement...)
	return err
}

// Consume the MODRM byte and the Displacement, depending on its Addressing Mode,
// and consume a 32-bit Immediate.
// Same as RMI.
func (e MI) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	var err error
	m := M{}
	if err = m.Encode(data, inst); err != nil {
		return err
	}

	inst.Immediate, err = datatypes.ParseImmediate(data, 4)
	inst.Literal = append(inst.Literal, inst.Immediate...)

	return err
}

// Consume the MODRM byte and the Displacement, depending on its Addressing Mode.
// Same as M and RM.
func (e MR) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	m := M{}
	return m.Encode(data, inst)
}

// Consume the MODRM byte and the Displacement, depending on its Addressing Mode.
// Same as M and MR.
func (e RM) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	m := M{}
	return m.Encode(data, inst)
}

// Consume the MODRM byte and the Displacement, depending on its Addressing Mode,
// and consume a 32-bit Immediate.
// Same as MI
func (e RMI) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	mi := MI{}
	return mi.Encode(data, inst)
}

// No operands, so consume nothing!
func (e NP) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	return nil
}

// Register is encoded in the opcode itself. Nothing to consume.
func (e O) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	return nil
}

// Consume a 32-bit Immediate.
func (e I) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	var err error
	inst.Immediate, err = datatypes.ParseImmediate(data, inst.ImmSize)
	inst.Literal = append(inst.Literal, inst.Immediate...)
	return err
}

// Register is encoded in the opcode itself. Consume a 32-bit Immediate.
func (e OI) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	var err error
	inst.Immediate, err = datatypes.ParseImmediate(data, 4)
	inst.Literal = append(inst.Literal, inst.Immediate...)
	return err
}

// Consume an 8-bit or 32-bit Displacement.
func (e D) Encode(data *bytes.Buffer, inst *datatypes.Instruction) error {
	var err error
	inst.Displacement, err = datatypes.ParseDisplacement(inst.Modrm, data, inst.DispSize)
	inst.Literal = append(inst.Literal, inst.Displacement...)
	return err
}

// ====================================================================================================================
// 														Stringifiers
// ====================================================================================================================

// Stringify the RM part of MODRM, depending on the Addressing Mode.
func (e M) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {

	return datatypes.StringifyRM(inst.Modrm, inst.Displacement), 0, false, nil
}

// Stringify the RM part of MODRM as first Operand, and Immediate as the second.
func (e MI) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {
	rm := datatypes.StringifyRM(inst.Modrm, inst.Displacement)
	imm := datatypes.StringifyIntegerBytes(inst.Immediate)
	return fmt.Sprintf("%s, %s", rm, imm), 0, false, nil
}

// Stringify the RM part of MODRM as the first Operand, and the Reg part as the second.
func (e MR) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {
	rm := datatypes.StringifyRM(inst.Modrm, inst.Displacement)
	reg := datatypes.Registers[inst.Modrm.Reg]
	return fmt.Sprintf("%s, %s", rm, reg), 0, false, nil
}

// Stringify the Reg part of MODRM as the first Operand, and the RM part as the second.
func (e RM) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {
	rm := datatypes.StringifyRM(inst.Modrm, inst.Displacement)
	reg := datatypes.Registers[inst.Modrm.Reg]
	return fmt.Sprintf("%s, %s", reg, rm), 0, false, nil
}

// Stringify the Reg part of MODRM as the first Operand, the RM part as the second, and Immediate as the third.
func (e RMI) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {
	rm := datatypes.StringifyRM(inst.Modrm, inst.Displacement)
	reg := datatypes.Registers[inst.Modrm.Reg]
	imm := datatypes.StringifyIntegerBytes(inst.Immediate)
	return fmt.Sprintf("%s, %s, %s", reg, rm, imm), 0, false, nil
}

// Empty string. No operands.
func (e NP) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {
	return "", 0, false, nil
}

// Stringify Register as Operand from last 3 bits of Opcode.
func (e O) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {
	reg := datatypes.Register(int(inst.Op & 7))
	return datatypes.Registers[reg], 0, false, nil
}

// Stringify Immediate as the Operand.
func (e I) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {
	imm := datatypes.StringifyIntegerBytes(inst.Immediate)
	return imm, 0, false, nil
}

//  Stringify Register as first Operand from last 3 bits of Opcode, and Immediate as the second Operand.
func (e OI) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {
	reg := datatypes.Registers[datatypes.Register(int(inst.Op&7))]
	imm := datatypes.StringifyIntegerBytes(inst.Immediate)
	return fmt.Sprintf("%s, %s", reg, imm), 0, false, nil
}

// Stringify Displacement into a Label as an offset from current instruction.
func (e D) StringifyOperands(inst *datatypes.Instruction) (string, int, bool, error) {
	start := inst.Offset + len(inst.Literal)
	disp, err := datatypes.BytesToIntSigned(inst.Displacement)
	end := int(start) + disp // int because disp could be negative
	return fmt.Sprintf("offset_%08xh", end), end, true, err
}

// ====================================================================================================================
// 														Encodings
// ====================================================================================================================
// Stringify the RM part of MODRM, depending on the Addressing Mode.
func (e M) Encoding() string {
	return "M"
}

func (e MI) Encoding() string {
	return "MI"
}

func (e MR) Encoding() string {
	return "MR"
}

func (e RM) Encoding() string {
	return "RM"
}

func (e RMI) Encoding() string {
	return "RMI"
}

func (e NP) Encoding() string {
	return "NP"
}

func (e O) Encoding() string {
	return "O"
}

func (e I) Encoding() string {
	return "I"
}

func (e OI) Encoding() string {
	return "OI"
}

func (e D) Encoding() string {
	return "D"
}
