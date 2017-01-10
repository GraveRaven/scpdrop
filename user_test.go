package main

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestRandUser(t *testing.T) {
	rand.Seed(1)

	var testIn []int
	var expectedOut [][]byte

	testIn = append(testIn, 10)
	expectedOut = append(expectedOut, []byte("gmxjgsapga"))

	testIn = append(testIn, 20)
	expectedOut = append(expectedOut, []byte("tlmodzlumguqdixxmnpp"))

	for i, length := range testIn {
		user := randUser(length)
		if bytes.Compare(user, expectedOut[i]) != 0 {
			t.Errorf("Test%d user (%s) does not match expected (%s)\n", i, string(user), string(expectedOut[i]))
		}
	}
}

func TestRandPass(t *testing.T) {
	rand.Seed(1)

	var testIn []int
	var expectedOut [][]byte

	testIn = append(testIn, 10)
	expectedOut = append(expectedOut, []byte("gmxjgsapga"))

	testIn = append(testIn, 20)
	expectedOut = append(expectedOut, []byte("tlmodzlumguqdixxmnpp"))

	for i, length := range testIn {
		user := randUser(length)
		if bytes.Compare(user, expectedOut[i]) != 0 {
			t.Errorf("Test%d user (%s) does not match expected (%s)\n", i, string(user), string(expectedOut[i]))
		}
	}
}

func TestSaltNHash(t *testing.T) {
	rand.Seed(1)

	var hashes [][]byte
	var passwords [][]byte
	var expectedOut [][]byte

	hashes = append(hashes, randPass(10))
	passwords = append(passwords, []byte("myPassword123"))
	expectedOut = append(expectedOut, []byte("$6$"+string(hashes[0])+"$5073f34332071df0bd0a898bc6d4af240d43544d86edc6c114e37e877a574274e81cfd6f9b92bf1d4f3d6c48e1a363361d877ac5ac77d074c3e6c75e73f69073"))

	rand.Seed(1)

	for i, password := range passwords {
		line := saltNHash(password)

		if bytes.Compare(line, expectedOut[i]) != 0 {
			t.Errorf("Passwd line (%s) does not match expected (%s)\n", line, expectedOut[i])
		}

	}
}

func TestUserInfoPasswdString(t *testing.T) {
	rand.Seed(1)

	var testIn []UserInfo
	var expectedOut [][]byte

	testIn = append(testIn, UserInfo{[]byte("user1"), []byte("pass1"), []byte("rw"), []byte("/"), []byte("rw"), 1000, true, false})
	expectedOut = append(expectedOut, []byte("user1:$6$qcx9BSaUQA$2c6485fead7154189917fc15f659bc8974b96c56a0811a11e8c8aa7f9bc1f21b1a42d171d5b216536759c9695366c56a0cc53d7189fb16392743ef1b42d6a1fe:rw:/:1000:rw:p\n"))

	for i, input := range testIn {
		out := input.PasswdString()
		if bytes.Compare(out, expectedOut[i]) != 0 {
			t.Errorf("String (%s) does not match expected (%s)\n", out, expectedOut[i])
		}
	}
}
