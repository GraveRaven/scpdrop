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
	"errors"
	"golang.org/x/crypto/ssh"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// characters disallowed in scp commands.
const disallowedChars = ";&|><~`"

// errors returned by the scp server to clients
var (
	errOnlySCP            = errors.New("Only scp allowed")
	errFewArgs            = errors.New("Too few arguments to scp")
	errDisallowedChars    = errors.New("Disallowed characters in command")
	errAbsolutePath       = errors.New("Only relative paths allowed")
	errPathTraversal      = errors.New("Path traversal not allowed")
	errUploadPrivs        = errors.New("This user do not have upload privileges")
	errDownloadPrivs      = errors.New("This user do not have download privileges")
	errUnsupportedScpFlag = errors.New("Unsupported scp flag in command")
	errRecursiveDownload  = errors.New("No recursive downloads allowed")
	errRecursiveUpload    = errors.New("No recursive uploads allowed")
)

// handleRequests logs and discards from the passed-in channel
func handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		logInfo.Printf("received out-of-band request: %+v\n", req)
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

// handleChannels handles incoming channels and only allows exec request types
func handleChannels(chans <-chan ssh.NewChannel, perm *ssh.Permissions, address string, config Config) {
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			logWarning.Printf("%s tried channel type %s\n", address, newChannel.ChannelType())
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			logWarning.Printf("Could not accept channel from %s: %s\n", address, err)
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false

				logDebug.Printf("Request type %q from %s\n", req.Type, address)
				logDebug.Printf("Req.Payload: %q\n", string(req.Payload))

				switch req.Type {
				case "env":
					//Evaluate env variable
					ok = true
				case "exec":
					ok = true
					handleExec(channel, req, perm, address, config)
				case "simple@putty.projects.tartarus.org":
					channel.Write([]byte("Putty not supported\r\n"))
				case "subsystem":
					logWarning.Printf("Unsupported subsystem: %s\n", string(req.Payload))
				default:
					channel.Write([]byte("Unsupported request type\r\n"))
					logWarning.Printf("Unsupported request type: %s\n", req.Type)
				}

				if req.WantReply {
					logDebug.Println("Want reply")
					req.Reply(ok, nil)
				}
			}
		}(requests)
	}
}

// handleExec handles incoming exec requests. Only scp requests are allowed.
func handleExec(channel ssh.Channel, req *ssh.Request, perm *ssh.Permissions, address string, config Config) {
	defer channel.Close()

	command := string(req.Payload[4:])
	logInfo.Printf("Command from %s: %q\n", address, command)

	_, err := validateCommand(command, perm, perm.CriticalOptions["recurse"])
	if err != nil {
		channel.Write([]byte(string(err.Error()) + "\r\n"))
		logWarning.Printf("%s ran illegal command %q\n", address, command)
		logWarning.Printf("%s received error message \"%q\"\n", address, err.Error())
		return
	}

	args := strings.Split(command, " ")

	if perm.CriticalOptions["dir"] == "/" {
		logWarning.Println("DIR == /")
	}

	dir := perm.CriticalOptions["dir"]
	if dir == "" {
		dir = config.SharedDir
	}

	args[len(args)-1] = dir + args[len(args)-1]

	cmd := exec.Command(config.ScpPath, args[1:]...)

	filechan := make(chan string)
	defer close(filechan)

	maxSize, _ := strconv.ParseUint(perm.CriticalOptions["size"], 10, 64)

	cmd.Stdin = scpReader{reader: channel, phase: new(int), filesize: new(uint64),
		currsize: new(uint64), maxSize: maxSize, dirname: new(string),
		filename: new(string), filechan: filechan}
	cmd.Stdout = scpWriter{writer: channel, phase: new(int), filesize: new(uint64),
		currsize: new(uint64), dirname: new(string), filename: new(string), filechan: filechan}
	cmd.Stderr = scpWriter{writer: channel, phase: new(int), filesize: new(uint64),
		currsize: new(uint64), dirname: new(string), filename: new(string), filechan: filechan}

	var uploadedFiles []string
	go func() {
		for file := range filechan {
			uploadedFiles = append(uploadedFiles, file)
		}
	}()

	logDebug.Printf("Running command: %q\n", cmd.Args)
	if err = cmd.Start(); err != nil {
		logError.Printf("Could not start command: %q\n", err)
		return
	}

	if _, err = cmd.Process.Wait(); err != nil {
		logError.Printf("Unable to wait for %q: %s\n", command, err)
	}

	if len(config.Cmd) != 0 {
		for _, f := range uploadedFiles {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			args = append(config.Cmd[1:], dir+f)

			cmd = exec.Command(config.Cmd[0], args...)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err = cmd.Run(); err != nil {
				logError.Printf("Unable to run command \"%q\" on file %s\n", cmd.Args, f)
			}

			if stdout.Len() > 0 {
				logInfo.Printf("STDOUT: %s\n", stdout.String())
			}

			if stderr.Len() > 0 {
				logError.Printf("STDERR: %s\n", stderr.String())
			}
		}
	}
}

// validateCommand makes sure unallowed or dangerous commands are not executed.
func validateCommand(command string, perm *ssh.Permissions, recPerms string) (cmd string, err error) {
	c := strings.Split(command, " ")

	if c[0] != "scp" {
		return "", errOnlySCP
	}

	if len(c) == 1 {
		return "", errFewArgs
	}

	if strings.IndexAny(command, disallowedChars) != -1 {
		return "", errDisallowedChars
	}

	if strings.HasPrefix(c[len(c)-1], string(filepath.Separator)) {
		return "", errAbsolutePath
	}

	if strings.Index(command, "..") != -1 {
		return "", errPathTraversal
	}

	recurse := false
	download := false
	for _, flag := range c[1 : len(c)-1] {
		switch flag {
		case "-r":
			recurse = true
		case "-d":
		case "--":
		//case "-v": //Verbose mode messes up the the reader/writer
		case "-t":
			cmd = "-t"
			if !strings.Contains(perm.CriticalOptions["privs"], "w") {
				return "", errUploadPrivs
			}
		case "-f":
			cmd = "-f"
			download = true
			if !strings.Contains(perm.CriticalOptions["privs"], "r") {
				return "", errDownloadPrivs
			}
		default:
			return "", errUnsupportedScpFlag
		}
	}

	if recurse {
		if download && !strings.Contains(recPerms, "r") {
			return "", errRecursiveDownload
		}

		if !download && !strings.Contains(recPerms, "w") {
			return "", errRecursiveUpload
		}
	}

	return cmd, nil
}
