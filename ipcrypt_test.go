package ipcrypt

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// initialize whatever needs to be initialized
	os.Exit(m.Run())
}

func TestIpcrypt(t *testing.T) {
	ip := "1.2.3.4"
	init := ip
	encryptedIp := "191.207.11.210"
	var err error
	var key [16]byte
	for i := 0; i < 16; i++ {
		key[i] = 0xff
	}
	for i := 0; i < 10; i++ {
		if ip, err = Encrypt(key, ip); err != nil {
			t.Fatalf("encryption error: %s for IP %s", err, ip)
		}
	}
	if ip != encryptedIp {
		t.Fatalf("expected %s have %s", ip, encryptedIp)
	}
	for i := 0; i < 10; i++ {
		if ip, err = Decrypt(key, ip); err != nil {
			t.Fatalf("decryption error: %s for IP %s", err, ip)
		}
	}
	if init != ip {
		t.Errorf("expected %s have %s", init, ip)
	}
}
