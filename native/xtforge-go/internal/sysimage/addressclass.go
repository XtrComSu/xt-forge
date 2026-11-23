package sysimage

// AddressClass names what a pointer-sized value most likely points at.
type AddressClass string

const (
	ClassCode    AddressClass = "code"
	ClassData    AddressClass = "data"
	ClassStack   AddressClass = "stack"
	ClassHeap    AddressClass = "heap"
	ClassNull    AddressClass = "null"
	ClassUnknown AddressClass = "unknown"
)

// ClassifyAddress decides what a value points at, given the image's known
// executable and data regions plus a stack range.
// regions are (start, end) half-open ranges. stack is one range.
func ClassifyAddress(value uint64, code, data []Region, stack Region) AddressClass {
	if value == 0 {
		return ClassNull
	}
	if inRegions(value, code) {
		return ClassCode
	}
	if inRegions(value, data) {
		return ClassData
	}
	if stack.Size > 0 && inRegion(value, stack) {
		return ClassStack
	}
	if value >= 0x7f0000000000 && value < 0x800000000000 {
		return ClassHeap
	}
	return ClassUnknown
}

func inRegions(value uint64, regions []Region) bool {
	for _, region := range regions {
		if inRegion(value, region) {
			return true
		}
	}
	return false
}

func inRegion(value uint64, region Region) bool {
	// A region with Size 0 covers nothing.
	if region.Size == 0 {
		return false
	}
	return value >= region.Address && value < region.Address+region.Size
}
