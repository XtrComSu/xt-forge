package sysimage

import "fmt"

// PEMachine describes a PE COFF machine value.
type PEMachine struct {
	Value    uint16 `json:"value"`
	Name     string `json:"name"`
	Arm64    bool   `json:"arm64"`
	Emulated bool   `json:"emulated"` // ARM64EC: arm64 code with x64 ABI interop
}

// DescribePEMachine maps a COFF machine value to a description.
func DescribePEMachine(machine uint16) PEMachine {
	switch machine {
	case 0x014c:
		return PEMachine{Value: machine, Name: "x86"}
	case 0x8664:
		return PEMachine{Value: machine, Name: "x86-64"}
	case 0x01c0:
		return PEMachine{Value: machine, Name: "arm"}
	case 0x01c2:
		return PEMachine{Value: machine, Name: "arm-thumb"}
	case 0xaa64:
		return PEMachine{Value: machine, Name: "arm64", Arm64: true}
	case 0xa641:
		return PEMachine{Value: machine, Name: "arm64ec", Arm64: true, Emulated: true}
	case 0xa64e:
		return PEMachine{Value: machine, Name: "arm64x", Arm64: true}
	case 0x0200:
		return PEMachine{Value: machine, Name: "ia64"}
	case 0x5032:
		return PEMachine{Value: machine, Name: "riscv32"}
	case 0x5064:
		return PEMachine{Value: machine, Name: "riscv64"}
	default:
		return PEMachine{Value: machine, Name: fmt.Sprintf("unknown-0x%04x", machine)}
	}
}

// PECallingConvention names the calling convention implied by a machine value.
// x86 uses "stdcall"/"cdecl" territory, so return "x86-win32"; x86-64 returns
// "microsoft-x64"; arm64 returns "aapcs64"; arm64ec returns "arm64ec-mixed";
// anything else returns "".
func PECallingConvention(machine uint16) string {
	switch machine {
	case 0x014c:
		return "x86-win32"
	case 0x8664:
		return "microsoft-x64"
	case 0xaa64:
		return "aapcs64"
	case 0xa641:
		return "arm64ec-mixed"
	default:
		return ""
	}
}
