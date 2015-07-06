package main

// see also https://github.com/dgryski/go-ipcrypt/

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
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

func bytes2ip(bytes [4]byte) string {
	ipaddr := []string{"", "", "", ""}
	ipaddr[0] = strconv.Itoa(int(bytes[0]))
	ipaddr[1] = strconv.Itoa(int(bytes[1]))
	ipaddr[2] = strconv.Itoa(int(bytes[2]))
	ipaddr[3] = strconv.Itoa(int(bytes[3]))
	return strings.Join(ipaddr, ".")
}

func Encrypt(k [16]byte, ip string) (string, error) {
	p := net.ParseIP(ip)
	if p == nil {
		return "", errors.New("encrypt: invalid IP")
	}
	state := [4]byte{p[12], p[13], p[14], p[15]}

	state = xor4(state, k[:4])
	state = permute_fwd(state)
	state = xor4(state, k[4:8])
	state = permute_fwd(state)
	state = xor4(state, k[8:12])
	state = permute_fwd(state)
	state = xor4(state, k[12:16])

	return bytes2ip(state), nil
}

func Decrypt(k [16]byte, ip string) (string, error) {
	p := net.ParseIP(ip)
	if p == nil {
		return "", errors.New("encrypt: invalid IP")
	}
	state := [4]byte{p[12], p[13], p[14], p[15]}

	state = xor4(state, k[12:16])
	state = permute_bwd(state)
	state = xor4(state, k[8:12])
	state = permute_bwd(state)
	state = xor4(state, k[4:8])
	state = permute_bwd(state)
	state = xor4(state, k[:4])

	return bytes2ip(state), nil
}

func test() error {
	ip := "1.2.3.4"
	init := ip
	var err error
	var key [16]byte
	for i := 0; i < 16; i++ {
		key[i] = 0xff
	}
	for i := 0; i < 10; i++ {
		ip, err = Encrypt(key, ip)
		if err != nil {
			return err
		}
	}
	if ip != "191.207.11.210" {
		return errors.New("test failed: wrong intermediate value")
	}
	for i := 0; i < 10; i++ {
		ip, err = Decrypt(key, ip)
		if err != nil {
			return err
		}
	}
	if init != ip {
		return errors.New("test failed: decrypted values doesn't match")
	}
	return nil
}

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
