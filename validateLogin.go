package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/ssh"
)

// validatePass tests if a password matches the corresponding salt and hash line.
func validatePass(pass []byte, hashLine []byte) bool {

	if hashLine[0] != byte('$') {
		return false
	}
	line := bytes.SplitN(hashLine[1:], []byte{'$'}, 3)

	if line[0][0] == byte('0') && bytes.Compare(pass, line[1]) == 0 {
		return true
	}

	if line[0][0] != byte('6') {
		return false
	}

	tohash := make([]byte, len(line[1]))
	copy(tohash, line[1])
	tohash = append(tohash, pass...)

	hash := sha512.Sum512(tohash)
	passhash := hex.EncodeToString(hash[:])

	if bytes.Compare([]byte(passhash), line[2]) == 0 {
		return true
	}

	return false
}

// validationHelper structs removes the need for a global config with the
// PasswdFile and KeysDir entries.
type validationHelper struct {
	PasswdFile string
	KeysDir    string
}

// validateUser uses the passwd file to validate incoming autentications
// and set user configuration values.
func (h validationHelper) validateUser(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	file, err := ioutil.ReadFile(h.PasswdFile)
	if err != nil {
		logError.Fatalf("Unable to read passwd file: %s\n", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(file))
	var outfile []byte

	for scanner.Scan() {
		line := strings.SplitN(scanner.Text(), ":", 7)

		if strings.HasPrefix(line[0], "#") || len(line) != 7 {
			outfile = append(outfile, scanner.Bytes()...)
			outfile = append(outfile, '\n')
			continue
		}

		if c.User() != line[0] || !validatePass(pass, []byte(line[1])) {
			outfile = append(outfile, scanner.Bytes()...)
			outfile = append(outfile, '\n')
			continue
		}

		if line[6] != "p" {
			for scanner.Scan() {
				outfile = append(outfile, scanner.Bytes()...)
				outfile = append(outfile, '\n')
			}
			ioutil.WriteFile(h.PasswdFile, outfile, 0644)
		}
		var perm ssh.Permissions
		perm.CriticalOptions = make(map[string]string)
		perm.CriticalOptions["privs"] = line[2]
		if line[3] != "" {
			perm.CriticalOptions["dir"] = addSepSuffix(line[3])
		} else {
			perm.CriticalOptions["dir"] = line[3]
		}
		perm.CriticalOptions["size"] = line[4]
		perm.CriticalOptions["recurse"] = line[5]

		logDebug.Printf("Login from user %q with password %q", c.User(), string(pass))
		logInfo.Printf("Login: %s\n", c.User())

		return &perm, nil
	}

	logWarning.Printf("Invalid password %q from user %q at %q", string(pass), c.User(), c.RemoteAddr())
	return nil, fmt.Errorf("Password rejected")
}

// validatePubKey finds the authorizedkeys file for a user and validates incoming authentications.
// It also sets user configuration values.
func (h validationHelper) validatePubKey(c ssh.ConnMetadata, remoteKey ssh.PublicKey) (*ssh.Permissions, error) {
	logDebug.Printf("Validating public key with file %s\n", h.KeysDir+c.User())
	if keyFile, err := ioutil.ReadFile(h.KeysDir + c.User()); err == nil {

		scanner := bufio.NewScanner(bytes.NewReader(keyFile))

		for scanner.Scan() {
			localKey, comment, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				logWarning.Printf("Unable to parse key file: %v\n", err)
				return nil, fmt.Errorf("No valid key file")
			}

			if len(comment) == 0 {
				logWarning.Printf("Invalid permissions for keyfile %s\n", "keys/"+c.User())
				return nil, fmt.Errorf("No valid key file")
			}

			if bytes.Compare(localKey.Marshal(), remoteKey.Marshal()) == 0 {

				privs := strings.SplitN(comment, ":", 4)

				var perm ssh.Permissions
				perm.CriticalOptions = make(map[string]string)
				perm.CriticalOptions["privs"] = privs[0]
				perm.CriticalOptions["dir"] = addSepSuffix(privs[1])
				perm.CriticalOptions["size"] = privs[2]
				perm.CriticalOptions["recurse"] = privs[3]

				logInfo.Printf("Login: %s\n", c.User())
				return &perm, nil
			}
		}
	}

	return nil, fmt.Errorf("No valid key file")
}
