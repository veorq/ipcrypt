package main

import (
	"encoding/csv"
	"fmt"
	"ipcrypt"
	"os"
)

func main() {
	err := test()
	if err != nil {
		fmt.Println(err)
		return
	}
	if len(os.Args) < 4 {
		fmt.Println("not enough arguments")
		return
	}
	filein := os.Args[1]
	index, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println(err)
		return
	}
	mode := os.Args[3]

	var process func([16]byte, string) (string, error)
	if mode == "e" {
		process = Encrypt
	} else if mode == "d" {
		process = Decrypt
	} else {
		fmt.Println("error: wrong mode")
		return
	}

	file, err := os.Open(filein)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = ','
	writer := csv.NewWriter(os.Stdout)
	writer.Comma = ','

	var key [16]byte
	for i := 0; i < 16; i++ {
		key[i] = byte(KEY[i])
	}

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println(err)
			return
		}
		newline := line
		newline[index], err = process(key, line[index])
		if err != nil {
			fmt.Println(err)
			return
		}
		if err == nil {
			writer.Write(newline)
		}
	}

	writer.Flush()
}
