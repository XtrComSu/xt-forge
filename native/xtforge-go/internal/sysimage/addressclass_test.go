package sysimage

import "testing"

func TestClassifyAddress(t *testing.T) {
	code := []Region{{Name: ".text", Address: 0x401000, Size: 0x1000}}
	data := []Region{{Name: ".data", Address: 0x501000, Size: 0x1000}}
	stack := Region{Name: "stack", Address: 0x7ffd00000000, Size: 0x10000}

	tests := []struct {
		name  string
		value uint64
		code  []Region
		data  []Region
		stack Region
		want  AddressClass
	}{
		{"null", 0, code, data, stack, ClassNull},
		{"code", 0x401500, code, data, stack, ClassCode},
		{"data", 0x501500, code, data, stack, ClassData},
		{"stack", 0x7ffd00008000, code, data, stack, ClassStack},
		{"heap", 0x7f1234567000, code, data, stack, ClassHeap},
		{"unknown", 0xdeadbeef, code, data, stack, ClassUnknown},
		{
			"zero-size region ignored", 0x1000,
			[]Region{{Name: "empty", Address: 0x1000, Size: 0}}, nil, Region{},
			ClassUnknown,
		},
		{"boundary at start matches", 0x401000, code, data, stack, ClassCode},
		{"boundary at end does not match", 0x402000, code, data, stack, ClassUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyAddress(tt.value, tt.code, tt.data, tt.stack); got != tt.want {
				t.Errorf("ClassifyAddress(%#x) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}
