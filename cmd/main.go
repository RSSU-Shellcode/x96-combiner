package main

import (
	"flag"
	"log"
	"os"

	"github.com/RSSU-Shellcode/x96-combiner"
)

var (
	x86 string
	x64 string
	out string
)

func init() {
	flag.StringVar(&x86, "x86", "", "x86 shellcode file path")
	flag.StringVar(&x64, "x64", "", "x64 shellcode file path")
	flag.StringVar(&out, "o", "output.bin", "output shellcode file path")
	flag.Parse()
}

func main() {
	if x86 == "" || x64 == "" {
		flag.PrintDefaults()
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
	}
	if x64 != "" {
		x64SC, err = os.ReadFile(x64) // #nosec
		checkError(err)
	}
	shellcode := combiner.Combine(x86SC, x64SC)
	err = os.WriteFile(out, shellcode, 0600)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
