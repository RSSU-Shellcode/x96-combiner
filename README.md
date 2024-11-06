# x96-combiner
A tool to merge x86 and x64 shellcode to one that can run on x86/x64 at the same time.\
This technique is referenced from DoublePulsar, it added some obfuscation instructions to circumvent the feature.
## Usage
```bash
sc-combiner -x86 x86.bin -x64 x64.bin -o x96.bin
```
## Development
```go
package main

import (
    "fmt"

    "github.com/RSSU-Shellcode/x96-combiner"
)

func main() {
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
    shellcode := combiner.Combine(x86, x64)
    fmt.Println(shellcode)
}
```
