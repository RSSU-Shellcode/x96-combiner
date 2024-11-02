package combiner

import (
	cr "crypto/rand"
	"encoding/binary"
	"math/rand"
	"sync"
)

var (
	rg *rand.Rand
	mu sync.Mutex
)

func init() {
	b := make([]byte, 8)
	_, _ = cr.Read(b)
	seed := binary.BigEndian.Uint64(b)
	rg = rand.New(rand.NewSource(int64(seed)))
}

// Combine is used to combine x86 and x64 shellcode to one.
func Combine(x86, x64 []byte) []byte {
	inst := make([]byte, 0, len(x86)+len(x64)+256)
	inst = append(inst, genGarbageInst()...)
	// xor eax, eax
	inst = append(inst, 0x31, 0xC0)
	inst = append(inst, genGarbageInst()...)
	// [on x86]   [on x64]
	// inc eax    nop 2
	// nop
	inst = append(inst, 0x40, 0x90)
	inst = append(inst, genGarbageInst()...)
	// jz [offset]
	inst = append(inst, 0x0F, 0x84)
	offset := make([]byte, 4)
	binary.LittleEndian.PutUint32(offset, uint32(len(x86)))
	inst = append(inst, offset...)
	inst = append(inst, x86...)
	inst = append(inst, x64...)
	return inst
}

func genGarbageInst() []byte {
	garbage := make([]byte, 0, 64)
	offset := 4 + randIntN(60)
	// jmp [4-64]
	garbage = append(garbage, 0xEB, byte(offset))
	// padding garbage data
	inst := randBytes(offset)
	garbage = append(garbage, inst...)
	return garbage
}

func randIntN(n int) int {
	mu.Lock()
	defer mu.Unlock()
	return rg.Intn(n)
}

func randBytes(n int) []byte {
	mu.Lock()
	defer mu.Unlock()
	buf := make([]byte, n)
	_, _ = rg.Read(buf)
	return buf
}
