package main

import (
	"io/ioutil"
	"net"
	"os"
	"testing"

	_ "golang.org/x/crypto/ssh"
)

type test_sshConn struct {
	user          string
	sessionID     []byte
	clientVersion []byte
	serverVersion []byte
}

func test_dup(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func (c *test_sshConn) User() string {
	return c.user
}

func (c *test_sshConn) RemoteAddr() net.Addr {
	ip := new(net.TCPAddr)
	ip.IP = net.ParseIP("192.168.10.1")
	ip.Port = 22

	return ip

}

func (c *test_sshConn) Close() error {
	return nil
}

func (c *test_sshConn) LocalAddr() net.Addr {
	return nil
}

func (c *test_sshConn) SessionID() []byte {
	return test_dup(c.sessionID)
}

func (c *test_sshConn) ClientVersion() []byte {
	return test_dup(c.clientVersion)
}

func (c *test_sshConn) ServerVersion() []byte {
	return test_dup(c.serverVersion)
}

func TestValidatePass(t *testing.T) {
	correctPassword := []byte("myPassword123!")

	tests := make(map[string]bool)
	tests["$6$mysalt$83c116fa5ea026067776c40c986ec51d401d9be10bc7d5412f586511b5d72b45bcb77df993bdcc6cd9a0bdaa21efdaec4ef3f58dce85fed02a2d1a79c6f605f3"] = true
	tests["$6$£@\\{$8a22f4186a0e34e585439e8c6dc2a5724c246687c806d337bc999056ed06889463475869f95e95deb32fa95fb3d77c38a38671492f1c9c1cd36cb3e1769e30cc"] = true
	tests["$0$myPassword123!"] = true
	tests["$6$mysal$83c116fa5ea026067776c40c986ec51d401d9be10bc7d5412f586511b5d72b45bcb77df993bdcc6cd9a0bdaa21efdaec4ef3f58dce85fed02a2d1a79c6f605f3"] = false
	tests["$6$£@\\{$8a22f4186a0e34e585439e8c6dc2a5724c246687c806d337bc999056ed06889463475869f95e95deb32fa95fb3d77c38a38671492f1c9c1cd36cb3e1769e30cd"] = false
	tests["$0$myPassword123"] = false
	tests[":$0$asd"] = false
	tests["$0$asd$qwe"] = false

	for testIn, expectedOut := range tests {
		if v := validatePass(correctPassword, []byte(testIn)); v != expectedOut {
			t.Errorf("Validate (%v) does not match expected (%v)\n", v, expectedOut)
		}
	}
}

func test_buildPasswdFile(passwdFile string, t *testing.T) {
	var users []byte
	users = append(users, []byte("testuser:$6$mpIfdJs54D$99fb779f928b42e7f4f7f0ba96853ea13ee3c4575ea7e852938cdd45705a658ac59ad76f7848ed3416d6e60fbb93a889f04ccbf3ff517280419963f75483d822:w:/:0::t\n")...)
	users = append(users, []byte("failuser:$6$FDVvxUdS7n$45070520fa43d9e95b83ade869442b7a5fed21f03af0628004dde3747c527f7002a847afbfa5d678a9099654af6d6212c5dc7c271388d2c46f7c76cdb2b32335:w:/:0::t\n")...)

	err := ioutil.WriteFile(passwdFile, users, 0644)
	if err != nil {
		t.Fatalf("FATAL - Unable to create temporary password file: %s\n", err)
	}
}

func TestValidateUser(t *testing.T) {
	var correctPassword []byte = []byte("myPassword123!")
	initLog("-", "none")

	//Only works for *nix
	passwdFile := "/tmp/scpdropPasswdTest"
	test_buildPasswdFile(passwdFile, t)

	var c test_sshConn
	c.user = "testuser"

	helper := validationHelper{PasswdFile: passwdFile}

	if _, err := helper.validateUser(&c, correctPassword); err != nil {
		t.Errorf("Correct password not validated correctly: %s\n", err)
	}

	if _, err := helper.validateUser(&c, []byte("?\"!/asdc&%")); err == nil {
		t.Errorf("Wrong password not validated correctly: %s\n", err)
	}

	c.user = "failuser"
	if _, err := helper.validateUser(&c, correctPassword); err == nil {
		t.Errorf("Wrong password not validated correctly: %s\n", err)
	}

	if err := os.Remove(passwdFile); err != nil {
		t.Logf("Unable to remove temporary file %s\n", passwdFile)
	}
}
