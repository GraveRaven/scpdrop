package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func verifyConfig(testNr int, testConfig Config, correctConfig Config, t *testing.T) {
	if testConfig.Listen != correctConfig.Listen {
		t.Errorf("Test%d Listen (%s) does not match expected (%s)\n", testNr, testConfig.Listen, correctConfig.Listen)
	}
	if testConfig.SharedDir != correctConfig.SharedDir {
		t.Errorf("Test%d Shared directory (%s) does not match expected (%s)\n", testNr, testConfig.SharedDir, correctConfig.SharedDir)
	}
	if testConfig.UsersDir != correctConfig.UsersDir {
		t.Errorf("Test%d Users Directory (%s) does not match expected (%s)\n", testNr, testConfig.UsersDir, correctConfig.UsersDir)
	}
	if testConfig.KeysDir != correctConfig.KeysDir {
		t.Errorf("Test%d Keys directory (%s) does not match expected (%s)\n", testNr, testConfig.KeysDir, correctConfig.KeysDir)
	}
	if testConfig.PrivateKey != correctConfig.PrivateKey {
		t.Errorf("Test%d Privkey (%s) does not match expected (%s)\n", testNr, testConfig.PrivateKey, correctConfig.PrivateKey)
	}
	if testConfig.LogLevel != correctConfig.LogLevel {
		t.Errorf("Test%d Loglevel (%s) does not match expected (%s)\n", testNr, testConfig.LogLevel, correctConfig.LogLevel)
	}
	if testConfig.LogFile != correctConfig.LogFile {
		t.Errorf("Test%d Logfile (%s) does not match expected (%s)\n", testNr, testConfig.LogFile, correctConfig.LogFile)
	}
	if testConfig.PasswdFile != correctConfig.PasswdFile {
		t.Errorf("Test%d Password file (%s) does not match expected (%s)\n", testNr, testConfig.PasswdFile, correctConfig.PasswdFile)
	}
	if len(testConfig.Cmd) != len(correctConfig.Cmd) {
		t.Errorf("Test%d Command not correct: %v != %v\n", testNr, testConfig.Cmd, correctConfig.Cmd)
	} else {
		for i, arg := range testConfig.Cmd {
			if arg != correctConfig.Cmd[i] {
				t.Errorf("Test%d cmd[%d] (%s) does not match expected (%s)\n", testNr, i, arg, correctConfig.Cmd[i])
			}
		}
	}
	if testConfig.ScpPath != correctConfig.ScpPath {
		t.Errorf("Test%d ScpPath (%s) does not match expected (%s)\n", testNr, testConfig.ScpPath, correctConfig.ScpPath)
	}
}

func verifyUserInfo(testNr int, testInfo UserInfo, correctInfo UserInfo, t *testing.T) {
	if bytes.Compare(testInfo.Username, correctInfo.Username) != 0 {
		t.Errorf("Test%d Username (%s) does not match expected (%s)\n", testNr, testInfo.Username, correctInfo.Username)
	}
	if bytes.Compare(testInfo.Password, correctInfo.Password) != 0 {
		t.Errorf("Test%d Password (%s) does not match expected (%s)\n", testNr, testInfo.Password, correctInfo.Password)
	}
	if bytes.Compare(testInfo.Privileges, correctInfo.Privileges) != 0 {
		t.Errorf("Test%d Privileges (%s) does not match expected (%s)\n", testNr, testInfo.Privileges, correctInfo.Privileges)
	}
	if bytes.Compare(testInfo.UserDir, correctInfo.UserDir) != 0 {
		t.Errorf("Test%d UserDirs (%s) does not match expected (%s)\n", testNr, testInfo.UserDir, correctInfo.UserDir)
	}
	if bytes.Compare(testInfo.Recursive, correctInfo.Recursive) != 0 {
		t.Errorf("Test%d Recursive (%s) does not match expected (%s)\n", testNr, testInfo.Recursive, correctInfo.Recursive)
	}
	if testInfo.UpSize != correctInfo.UpSize {
		t.Errorf("Test%d UpSize (%v) does not match expected (%v)\n", testNr, testInfo.UpSize, correctInfo.UpSize)
	}
	if testInfo.Permanent != correctInfo.Permanent {
		t.Errorf("Test%d Permanent (%v) does not match expected (%v)\n", testNr, testInfo.Permanent, correctInfo.Permanent)
	}
	if testInfo.Plaintext != correctInfo.Plaintext {
		t.Errorf("Test%d Plaintext (%v) does not match expected (%v)\n", testNr, testInfo.Plaintext, correctInfo.Plaintext)
	}
}

func parseConfigPassTests(t *testing.T) {
	var testIn [][]byte
	var expectedOut []Config

	//clean config with spaces
	testIn = append(testIn, []byte(`listen :2022
SharedDir /tmp/shared
UsersDir /tmp/users
KeysDir /tmp/keys
PrivateKey /tmp/test_id_rsa
LogLevel debug
LogFile -
PasswdFile /tmp/passwd
Cmd sed 's/Test/<test>/g'
ScpPath /usr/bin/scp
`))

	expectedOut = append(expectedOut, Config{Listen: ":2022", SharedDir: "/tmp/shared/", UsersDir: "/tmp/users/",
		KeysDir: "/tmp/keys/", PrivateKey: "/tmp/test_id_rsa", LogLevel: "debug", LogFile: "-",
		PasswdFile: "/tmp/passwd", Cmd: []string{"sed", "'s/Test/<test>/g'"}, ScpPath: "/usr/bin/scp"})

	//Messy config
	testIn = append(testIn, []byte(`listen :2022
#listen :2033
SharedDir /tmp/shared
UsersDir /tmp/users
KeysDir /tmp/keys
PrivateKey	/tmp/test_id_rsa
logLevel	 debug
logFile -
passwdfile /tmp/passwd
ScpPath /usr/bin/scp
`))

	expectedOut = append(expectedOut, Config{Listen: ":2022", SharedDir: "/tmp/shared/", UsersDir: "/tmp/users/",
		KeysDir: "/tmp/keys/", PrivateKey: "/tmp/test_id_rsa", LogLevel: "debug", LogFile: "-",
		PasswdFile: "/tmp/passwd", Cmd: []string{}, ScpPath: "/usr/bin/scp"})

	for i, confFile := range testIn {
		testConfig, err := parseConfig(confFile)
		if err != nil {
			t.Errorf("%v\n", err)
		} else {
			verifyConfig(1, testConfig, expectedOut[i], t)
		}
	}
}

func parseConfigFailTests(t *testing.T) {
	var testIn [][]byte

	//SharedDir path fail
	testIn = append(testIn, []byte(`listen :2022
SharedDir tmp/shared
UsersDir /tmp/users
KeysDir /tmp/keys
PrivateKey	/tmp/test_id_rsa
logLevel	 debug
logFile -
passwdfile /tmp/passwd
ScpPath /usr/bin/scp
`))

	for i, confFile := range testIn {
		_, err := parseConfig(confFile)
		if err == nil {
			t.Errorf("Test%d didnt fail as expected\n", i)
		}
	}
}

func TestParseConfig(t *testing.T) {
	parseConfigFailTests(t)
	parseConfigFailTests(t)
}

func TestGenerateRSAPrivateKeySigner(t *testing.T) {
	_, err := generateRSAPrivateKeySigner(1024)
	if err != nil {
		t.Errorf("Error generating private key signer: %s\n", err)
	}
}

func TestParseServerFlagsWithBlankConfig(t *testing.T) {
	var inputArgs [][]string
	var expectedOut []Config

	inputArgs = append(inputArgs, []string{"-l", ":2022", "-key", "/tmp/test_id_rsa", "-shared", "/tmp/shared", "-users", "/tmp/users",
		"-keys", "/tmp/keys", "-log", "debug", "-logfile", "-", "-P", "/tmp/passwd", "-cmd", "testcmd -a testy", "-scp", "/usr/bin/scp", "-c", "empty.conf"})
	expectedOut = append(expectedOut, Config{Listen: ":2022", SharedDir: "/tmp/shared" + string(filepath.Separator),
		UsersDir: "/tmp/users" + string(filepath.Separator), KeysDir: "/tmp/keys" + string(filepath.Separator),
		PrivateKey: "/tmp/test_id_rsa", LogLevel: "debug", LogFile: "-", PasswdFile: "/tmp/passwd",
		Cmd: []string{"testcmd", "-a", "testy"}, ScpPath: "/usr/bin/scp"})

	for i, args := range inputArgs {
		testConfig := parseServerFlags(args)
		verifyConfig(i+1, testConfig, expectedOut[i], t)
	}
}

func TestParseUserFlagsWithBlankConfig(t *testing.T) {
	var inputArgs [][]string
	var expectedOut []UserInfo

	inputArgs = append(inputArgs, []string{"-u", "testy", "-p", "mctest", "-up", "-plain", "-recup", "-upsize", "1024b", "-c", "empty.conf"})
	expectedOut = append(expectedOut, UserInfo{Username: []byte("testy"), Password: []byte("mctest"), Privileges: []byte("w"),
		UserDir: []byte("testy"), Recursive: []byte("w"), UpSize: 1024, Permanent: false, Plaintext: true})

	for i, args := range inputArgs {
		userInfo, _, _ := parseUserFlags(args)
		verifyUserInfo(i, userInfo, expectedOut[i], t)
	}
}
