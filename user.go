/*
Copyright 2017 Oscar Carlsson

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

// UserInfo is a struct that hold information about a user.
type UserInfo struct {
	Username   []byte
	Password   []byte
	Privileges []byte
	UserDir    []byte
	Recursive  []byte
	UpSize     uint64
	Permanent  bool
	Plaintext  bool
}

// PasswdString returns the users password hash string as a byte array.
func (u UserInfo) PasswdString() (r []byte) {
	r = append(u.Username, byte(':'))

	if u.Plaintext {
		r = append(r, []byte("$0$")...)
		r = append(r, u.Password...)
	} else {
		r = append(r, saltNHash(u.Password)...)
	}

	r = append(r, byte(':'))
	r = append(r, u.ConfigString()...)
	r = append(r, byte('\n'))

	return r
}

// ConfigString returns the config information part of the users password string as a byte array.
func (u UserInfo) ConfigString() (r []byte) {
	r = append(r, u.Privileges...)
	r = append(r, byte(':'))

	r = append(r, u.UserDir...)
	r = append(r, byte(':'))

	r = append(r, strconv.FormatUint(u.UpSize, 10)...)
	r = append(r, byte(':'))

	r = append(r, u.Recursive...)
	r = append(r, byte(':'))

	if u.Permanent {
		r = append(r, byte('p'))
	} else {
		r = append(r, byte('t'))
	}

	return r
}

// characters used in password and username generation.
const passwordChars = "ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvxyz01234567890"

// randUser creates a random user name.
func randUser(length int) (username []byte) {
	for i := 0; i < length; i++ {
		username = append(username, passwordChars[rand.Int31n(25)+25])
	}

	return
}

// randPass creates a random password.
func randPass(length int) (password []byte) {
	for i := 0; i < length; i++ {
		password = append(password, passwordChars[rand.Int31n(60)])
	}

	return
}

// saltNHash salts and hashes a password with sha512.
func saltNHash(password []byte) (line []byte) {
	salt := randPass(10)
	tohash := append(salt, password...)
	hash := sha512.Sum512(tohash)
	hex := hex.EncodeToString(hash[:])
	line = append(line, []byte("$6$")...)
	line = append(line, salt...)
	line = append(line, byte('$'))
	line = append(line, hex...)

	return line
}

// addUser adds a user to the passwd file.
// This function may prompt the user for further information.
func addUser(userInfo UserInfo, passwdFile string) {
	rand.Seed(time.Now().UnixNano())

	var err error
	randpass := false

	if bytes.Compare(userInfo.Username, []byte("")) == 0 {
		userInfo.Username = randUser(8)
	}

	if bytes.Compare(userInfo.Password, []byte("")) == 0 {

		fmt.Printf("Enter password (<blank> to randomize): ")

		userInfo.Password, err = terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()

		if err != nil {
			log.Fatalf("Error creating password: %v\n", err)
		}

		if len(userInfo.Password) == 0 {
			randpass = true
			userInfo.Password = randPass(12)
		}
	}
	if bytes.Compare(userInfo.UserDir, []byte("")) != 0 {
		if err := os.Mkdir(string(userInfo.UserDir), 0750); err != nil {
			if os.IsExist(err) {
				logWarning.Printf("User directory %s already exists\n", userInfo.UserDir)
			} else {
				logError.Fatalf("Unable to create user directory: %s\n", err)
			}
		}
	}

	appendToFile(passwdFile, userInfo.PasswdString())

	if randpass {
		fmt.Printf("User: %s Pass: %s\n", string(userInfo.Username), string(userInfo.Password))
	} else {
		logInfo.Printf("User %s added\n", string(userInfo.Username))
	}
}

// createKeyFile creates an authorizedKeys config.
// Don't forget to add the actual public key afterwards.
func createKeyFile(userInfo UserInfo, keysDir string) {
	filename := keysDir + string(userInfo.Username)
	var buf []byte
	buf = append(buf, []byte("type keyhash ")...)
	buf = append(buf, userInfo.ConfigString()...)
	appendToFile(filename, buf)
}
