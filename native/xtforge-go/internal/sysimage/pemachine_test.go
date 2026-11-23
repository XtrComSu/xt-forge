package sysimage

import "testing"

func TestDescribePEMachine(t *testing.T) {
	tests := []struct {
		name     string
		machine  uint16
		wantName string
		wantArm  bool
		wantEmu  bool
	}{
		{"x86", 0x014c, "x86", false, false},
		{"x86-64", 0x8664, "x86-64", false, false},
		{"arm", 0x01c0, "arm", false, false},
		{"arm-thumb", 0x01c2, "arm-thumb", false, false},
		{"arm64", 0xaa64, "arm64", true, false},
		{"arm64ec", 0xa641, "arm64ec", true, true},
		{"arm64x", 0xa64e, "arm64x", true, false},
		{"ia64", 0x0200, "ia64", false, false},
		{"riscv32", 0x5032, "riscv32", false, false},
		{"riscv64", 0x5064, "riscv64", false, false},
		{"zero", 0x0000, "unknown-0x0000", false, false},
		{"max", 0xffff, "unknown-0xffff", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DescribePEMachine(tt.machine)
			if got.Value != tt.machine {
				t.Errorf("Value = %#04x, want %#04x", got.Value, tt.machine)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.Arm64 != tt.wantArm {
				t.Errorf("Arm64 = %v, want %v", got.Arm64, tt.wantArm)
			}
			if got.Emulated != tt.wantEmu {
				t.Errorf("Emulated = %v, want %v", got.Emulated, tt.wantEmu)
			}
		})
	}
}

func TestPECallingConvention(t *testing.T) {
	tests := []struct {
		machine uint16
		want    string
	}{
		{0x014c, "x86-win32"},
		{0x8664, "microsoft-x64"},
		{0xaa64, "aapcs64"},
		{0xa641, "arm64ec-mixed"},
		{0x0000, ""},
	}

	for _, tt := range tests {
		if got := PECallingConvention(tt.machine); got != tt.want {
			t.Errorf("PECallingConvention(%#04x) = %q, want %q", tt.machine, got, tt.want)
		}
	}
}

// TestPEMachineExhaustive exercises every possible uint16 machine value and
// verifies DescribePEMachine never panics and always echoes the input value.
func TestPEMachineExhaustive(t *testing.T) {
	for i := 0; i <= 0xffff; i++ {
		machine := uint16(i)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DescribePEMachine(%#04x) panicked: %v", machine, r)
				}
			}()
			got := DescribePEMachine(machine)
			if got.Value != machine {
				t.Errorf("DescribePEMachine(%#04x).Value = %#04x", machine, got.Value)
			}
			if got.Name == "" {
				t.Errorf("DescribePEMachine(%#04x).Name is empty", machine)
			}
		}()
	}
}
