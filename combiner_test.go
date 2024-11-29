package combiner

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCombine(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		// xor eax, eax
		// add eax, 0x86
		// ret
		x86 := []byte{
			0x31, 0xC0,
			0x05, 0x86, 0x00, 0x00, 0x00,
			0xC3,
		}
		// xor eax, eax
		// add rax, 0x64
		// ret
		x64 := []byte{
			0x31, 0xC0,
			0x48, 0x83, 0xC0, 0x64,
			0xC3,
		}
		shellcode := Combine(x86, x64)

		if runtime.GOOS != "windows" {
			return
		}
		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscallN(addr)
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
		// xor eax, eax
		// add rax, 0x64
		// ret
		x64 := []byte{
			0x31, 0xC0,
			0x48, 0x83, 0xC0, 0x64,
			0xC3,
		}
		shellcode := Combine(nil, x64)

		if runtime.GOOS != "windows" {
			return
		}
		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscallN(addr)
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
		// xor eax, eax
		// add eax, 0x86
		// ret
		x86 := []byte{
			0x31, 0xC0,
			0x05, 0x86, 0x00, 0x00, 0x00,
			0xC3,
		}
		shellcode := Combine(x86, nil)

		if runtime.GOOS != "windows" {
			return
		}
		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscallN(addr)
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

		if runtime.GOOS != "windows" {
			return
		}
		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscallN(addr)
		require.Equal(t, 0x00, int(ret))
	})
}
