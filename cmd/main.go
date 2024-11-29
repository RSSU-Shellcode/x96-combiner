package main

import (
	"encoding/hex"
	"flag"
	"log"
	"os"

	"github.com/RSSU-Shellcode/x96-combiner"
)

var (
	ih  bool
	oh  bool
	x86 string
	x64 string
	out string
)

func init() {
	flag.BoolVar(&ih, "ih", false, "input shellcode with hex format")
	flag.BoolVar(&oh, "oh", false, "output shellcode with hex format")
	flag.StringVar(&x86, "x86", "", "x86 shellcode file path")
	flag.StringVar(&x64, "x64", "", "x64 shellcode file path")
	flag.StringVar(&out, "o", "output.bin", "output shellcode file path")
	flag.Parse()
}

func main() {
	if x86 == "" || x64 == "" {
		flag.Usage()
		return
	}

	var (
		x86SC []byte
		x64SC []byte
		err   error
	)
	if x86 != "" {
		x86SC, err = os.ReadFile(x86) // #nosec
		checkError(err)
		if ih {
			x86SC, err = hex.DecodeString(string(x86SC))
			checkError(err)
		}
	}
	if x64 != "" {
		x64SC, err = os.ReadFile(x64) // #nosec
		checkError(err)
		if ih {
			x64SC, err = hex.DecodeString(string(x64SC))
			checkError(err)
		}
	}

	shellcode := combiner.Combine(x86SC, x64SC)
	if oh {
		shellcode = []byte(hex.EncodeToString(shellcode))
	}
	err = os.WriteFile(out, shellcode, 0600)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
