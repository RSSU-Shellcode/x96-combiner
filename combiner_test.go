//go:build windows

package combiner

import (
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestCombine(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		x86 := []byte{
			// xor eax, eax
			0x31, 0xC0,
			// add eax, 86
			0x05, 0x86, 0x00, 0x00, 0x00,
			// ret
			0xC3,
		}
		x64 := []byte{
			// xor eax, eax
			0x31, 0xC0,
			// add rax, 64
			0x48, 0x83, 0xC0, 0x64,
			// ret
			0xC3,
		}
		shellcode := Combine(x86, x64)

		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscall.SyscallN(addr)
		rv := int(ret)
		switch runtime.GOARCH {
		case "386":
			require.Equal(t, 0x86, rv)
		case "amd64":
			require.Equal(t, 0x64, rv)
		default:
			t.Fatal("unsupported architecture")
		}
	})

	t.Run("padding x86", func(t *testing.T) {
		x64 := []byte{
			// xor eax, eax
			0x31, 0xC0,
			// add rax, 64
			0x48, 0x83, 0xC0, 0x64,
			// ret
			0xC3,
		}
		shellcode := Combine(nil, x64)

		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscall.SyscallN(addr)
		rv := int(ret)
		switch runtime.GOARCH {
		case "386":
			require.Equal(t, 0x00, rv)
		case "amd64":
			require.Equal(t, 0x64, rv)
		default:
			t.Fatal("unsupported architecture")
		}
	})

	t.Run("padding x64", func(t *testing.T) {
		x86 := []byte{
			// xor eax, eax
			0x31, 0xC0,
			// add eax, 86
			0x05, 0x86, 0x00, 0x00, 0x00,
			// ret
			0xC3,
		}
		shellcode := Combine(x86, nil)

		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscall.SyscallN(addr)
		rv := int(ret)
		switch runtime.GOARCH {
		case "386":
			require.Equal(t, 0x86, rv)
		case "amd64":
			require.Equal(t, 0x00, rv)
		default:
			t.Fatal("unsupported architecture")
		}
	})

	t.Run("padding x96", func(t *testing.T) {
		shellcode := Combine(nil, nil)

		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscall.SyscallN(addr)
		require.Equal(t, 0x00, int(ret))
	})
}

func loadShellcode(t *testing.T, sc []byte) uintptr {
	size := uintptr(len(sc))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	scAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(scAddr)), size)
	copy(dst, sc)
	return scAddr
}
