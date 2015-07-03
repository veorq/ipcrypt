package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// copy your key here
const (
	KEY = "some 16-byte key"
)

func rotl(x, c byte) byte {
	return (x << c) | (x >> (8 - c))
}

func permute_fwd(state [4]byte) [4]byte {
	a := state[0]
	b := state[1]
	c := state[2]
	d := state[3]
	a += b
	c += d
	a &= 0xff
	c &= 0xff
	b = rotl(b, 2)
	d = rotl(d, 5)
	b ^= a
	d ^= c
	a = rotl(a, 4)
	a += d
	c += b
	a &= 0xff
	c &= 0xff
	b = rotl(b, 3)
	d = rotl(d, 7)
	b ^= c
	d ^= a
	c = rotl(c, 4)
	return [4]byte{a, b, c, d}
}

func permute_bwd(state [4]byte) [4]byte {
	a := state[0]
	b := state[1]
	c := state[2]
	d := state[3]
	c = rotl(c, 4)
	b ^= c
	d ^= a
	b = rotl(b, 5)
	d = rotl(d, 1)
	a -= d
	c -= b
	a &= 0xff
	c &= 0xff
	a = rotl(a, 4)
	b ^= a
	d ^= c
	b = rotl(b, 6)
	d = rotl(d, 3)
	a -= b
	c -= d
	a &= 0xff
	c &= 0xff
	return [4]byte{a, b, c, d}
}

func xor4(x [4]byte, y []byte) [4]byte {
	return [4]byte{x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]}

}

func encrypt(k [16]byte, ip string) string {
	ipaddr := strings.Split(ip, ".")
	a, _ := strconv.Atoi(ipaddr[0])
	b, _ := strconv.Atoi(ipaddr[1])
	c, _ := strconv.Atoi(ipaddr[2])
	d, _ := strconv.Atoi(ipaddr[3])
	state := [4]byte{byte(a), byte(b), byte(c), byte(d)}

	state = xor4(state, k[:4])
	state = permute_fwd(state)
	state = xor4(state, k[4:8])
	state = permute_fwd(state)
	state = xor4(state, k[8:12])
	state = permute_fwd(state)
	state = xor4(state, k[12:16])

	ipaddr[0] = strconv.Itoa(int(state[0]))
	ipaddr[1] = strconv.Itoa(int(state[1]))
	ipaddr[2] = strconv.Itoa(int(state[2]))
	ipaddr[3] = strconv.Itoa(int(state[3]))
	return strings.Join(ipaddr, ".")
}

func decrypt(k [16]byte, ip string) string {
	ipaddr := strings.Split(ip, ".")
	a, _ := strconv.Atoi(ipaddr[0])
	b, _ := strconv.Atoi(ipaddr[1])
	c, _ := strconv.Atoi(ipaddr[2])
	d, _ := strconv.Atoi(ipaddr[3])
	state := [4]byte{byte(a), byte(b), byte(c), byte(d)}

	state = xor4(state, k[12:16])
	state = permute_bwd(state)
	state = xor4(state, k[8:12])
	state = permute_bwd(state)
	state = xor4(state, k[4:8])
	state = permute_bwd(state)
	state = xor4(state, k[:4])

	ipaddr[0] = strconv.Itoa(int(state[0]))
	ipaddr[1] = strconv.Itoa(int(state[1]))
	ipaddr[2] = strconv.Itoa(int(state[2]))
	ipaddr[3] = strconv.Itoa(int(state[3]))
	return strings.Join(ipaddr, ".")
}

func test() int {
	ip := "1.2.3.4"
	init := ip
	var key [16]byte
	for i := 0; i < 16; i++ {
		key[i] = 0xff
	}
	for i := 0; i < 10; i++ {
		ip = encrypt(key, ip)
	}
	if ip != "191.207.11.210" {
		fmt.Println("test failed: wrong intermediate value")
		return 1
	}
	for i := 0; i < 10; i++ {
		ip = decrypt(key, ip)
	}
	if init != ip {
		fmt.Println("test failed: decrypted values doesn't match")
		return 2
	}
	return 0
}

func main() {
	if test() != 0 {
		return
	}
	filein := os.Args[1]
	index, _ := strconv.Atoi(os.Args[2])
	mode := os.Args[3]

	var process func([16]byte, string) string
	if mode == "e" {
		process = encrypt
	} else if mode == "d" {
		process = decrypt
	} else {
		fmt.Println("error: wrong mode")
		return
	}

	file, err := os.Open(filein)
	if err != nil {
		fmt.Println("open failed:", err)
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
			fmt.Println("reader error:", err)
			return
		}
		newline := line
		newline[index] = process(key, line[index])
		writer.Write(newline)
	}

	writer.Flush()
}
