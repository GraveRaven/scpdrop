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
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

var scpDropVersion string = "1.0"

// Config is the struct used to hold config information.
type Config struct {
	Listen     string
	SharedDir  string
	UsersDir   string
	KeysDir    string
	PrivateKey string
	LogLevel   string
	LogFile    string
	PasswdFile string
	Cmd        []string
	ScpPath    string
}

// Loggers for the different log levels.
var (
	logError   *log.Logger
	logWarning *log.Logger
	logInfo    *log.Logger
	logDebug   *log.Logger
)

// printUsage prints some short usage information.
func printUsage() {
	uString := `Usage: %s server|user
  server
  	Start the server
  user
  	Add a new user
`
	fmt.Fprintf(os.Stderr, uString, os.Args[0])
}

// parseConfig takes a config file in the form of a byte array
// and parses into a Config struct.
func parseConfig(content []byte) (c Config, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))

	lineNr := 0
	for scanner.Scan() {
		lineNr += 1
		line := scanner.Text()
		line = strings.Trim(line, " \t")

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		s := strings.SplitN(strings.Replace(line, "\t", " ", -1), " ", 2)
		if len(s) != 2 {
			return c, fmt.Errorf("Error in config line %d", lineNr)
		}

		key := strings.ToLower(s[0])
		value := strings.Trim(s[1], " ")

		switch key {
		case "listen":
			c.Listen = value
		case "shareddir":
			if strings.HasPrefix(value, string(filepath.Separator)) == false {
				return c, fmt.Errorf("Only absolute path allowed for SharedDir line %d", lineNr)
			}
			c.SharedDir = addSepSuffix(value)
		case "usersdir":
			if strings.HasPrefix(value, "/") == false {
				return c, fmt.Errorf("Only absolute path allowed for UsersDir line %d", lineNr)
			}
			c.UsersDir = addSepSuffix(value)
		case "keysdir":
			if strings.HasPrefix(value, "/") == false {
				return c, fmt.Errorf("Only absolute path allowed for KeysDir line %d", lineNr)
			}
			c.KeysDir = addSepSuffix(value)
		case "privatekey":
			if strings.HasPrefix(value, string(filepath.Separator)) == false {
				return c, fmt.Errorf("Only absolute path allowed for PrivateKey line %d", lineNr)
			}
			c.PrivateKey = value
		case "loglevel":
			value = strings.ToLower(value)
			switch value {
			case "debug", "info", "warning", "error", "none":
				c.LogLevel = value
			default:
				return c, fmt.Errorf("Unknown debug level line %d", lineNr)
			}
		case "logfile":
			if strings.HasPrefix(value, "/") == false && value != "-" {
				return c, fmt.Errorf("Only absolute path or \"-\" allowed for LogFile line %d", lineNr)
			}
			c.LogFile = value
		case "passwdfile":
			if strings.HasPrefix(value, "/") == false {
				return c, fmt.Errorf("Only absolute path allowed for PasswdFile line %d", lineNr)
			}
			c.PasswdFile = value
		case "cmd":
			c.Cmd = parseCmdLine(value)
		case "scppath":
			if strings.HasPrefix(value, "/") == false {
				return c, fmt.Errorf("Only absolute path allowed for ScpPath line %d", lineNr)
			}
			c.ScpPath = value
		default:
			return c, fmt.Errorf("Unknown setting line %d: %s", lineNr, value)
		}
	}

	return c, nil
}

// getConfig finds the config file to be used and returns it as a Config struct.
// If path is an empty string the default locations are used in order.
func getConfig(path string) (c Config, err error) {
	usr, _ := user.Current()
	homeDir := usr.HomeDir
	defaultLocations := []string{
		"scpdrop.conf",
		homeDir + "/.config/scpdrop/scpdrop.conf",
		"/etc/scpdrop/scpdrop.conf",
	}

	confPath := path

	if path != "" {
		if _, err := os.Stat(path); err != nil {
			log.Fatalf("Unable to open config file (%s): %s\n", path, err)
		}
		confPath = path
	} else {
		for _, p := range defaultLocations {
			if _, err := os.Stat(p); err != nil {
				if os.IsNotExist(err) {
					continue
				} else {
					log.Fatalf("Unable to open config file (%s): %s\n", p, err)
				}
			} else {
				confPath = p
			}
		}
	}

	if confPath == "" {
		return c, nil
	}

	b, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatalf("Unable to open config file (%s): %s\n", confPath, err)
	}
	c, err = parseConfig(b)
	if err != nil {
		return c, err
	}

	return c, nil
}

// addConfigDefaults fills in missing defaults in a config.
func addConfigDefaults(c Config) Config {
	if c.Listen == "" {
		c.Listen = ":2022"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.LogFile == "" {
		c.LogFile = "-"
	}
	if c.ScpPath == "" {
		c.ScpPath = "/usr/bin/scp"
	}

	return c
}

// generateRSAPrivateKeySigner generates a new private key and returns a signer for it.
func generateRSAPrivateKeySigner(bits int) (s ssh.Signer, err error) {
	rng := rand.Reader
	key, err := rsa.GenerateKey(rng, bits)

	if err != nil {
		return s, err
	}
	return ssh.NewSignerFromKey(key)
}

// loadPrivateKey reads a private key from file and returns a signer for it.
func loadPrivateKey(keyname string) (s ssh.Signer, err error) {
	privatekey, err := ioutil.ReadFile(keyname)
	if err != nil {
		return s, err
	}

	return ssh.ParsePrivateKey(privatekey)
}

// runServer starts the scp server.
func runServer(config Config) {
	passwdExists, _ := isFile(config.PasswdFile)
	keysDirEmpty, _ := isEmptyDir(config.KeysDir)
	if !passwdExists && keysDirEmpty {
		logError.Fatalf("No passwd file or keys directory")
	}

	b, err := dirExists(config.UsersDir)
	if err != nil {
		logError.Fatalf("UsersDir: %v\n", err)
	} else if b == false {
		logError.Fatalln("UsersDir does not exist")
	}

	helper := validationHelper{PasswdFile: config.PasswdFile, KeysDir: config.KeysDir}
	sshConfig := &ssh.ServerConfig{
		ServerVersion:     "SSH-2.0-scpDrop-" + scpDropVersion,
		PasswordCallback:  helper.validateUser,
		PublicKeyCallback: helper.validatePubKey,
	}

	var private ssh.Signer
	if config.PrivateKey == "" {
		private, err = generateRSAPrivateKeySigner(2048)
		if err != nil {
			log.Fatalf("Error while generating private key: %s\n", err)
		}
	} else {
		private, err = loadPrivateKey(config.PrivateKey)
		if err != nil {
			log.Fatalf("Error while reading private key: %s\n", err)
		}
	}
	sshConfig.AddHostKey(private)

	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		log.Fatalf("Failed to listen for connection: %s\n", err)
	}

	logInfo.Println("Service started")

	for {
		nConn, err := listener.Accept()
		if err != nil {
			logWarning.Printf("Failed to accept incoming connection: %s\n", err)
			continue
		}

		sshConn, chans, reqs, err := ssh.NewServerConn(nConn, sshConfig)
		if err != nil {
			logWarning.Printf("Failed to handshake with %s: %s\n", nConn.RemoteAddr().String(), err)
			continue
		}

		logInfo.Printf("Connection established  with %s\n", sshConn.RemoteAddr().String())

		go handleRequests(reqs)
		go handleChannels(chans, sshConn.Permissions, sshConn.RemoteAddr().String(), config)
	}
}

// initLog initiates the loggers for the different log levels.
func initLog(filename string, level string) {
	var out *os.File

	if filename == "-" {
		out = os.Stdout
	} else {
		var err error
		out, err = os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)

		if err != nil {
			log.Fatalln("Unable to open log file: ", err)
		}
	}

	logDebug = log.New(ioutil.Discard, "", 0)
	logInfo = log.New(ioutil.Discard, "", 0)
	logWarning = log.New(ioutil.Discard, "", 0)
	logError = log.New(ioutil.Discard, "", 0)

	logflags := log.Ldate | log.Ltime

	switch level {
	case "debug":
		logflags = log.Ldate | log.Ltime | log.Lshortfile
		logDebug = log.New(out, "Debug: ", logflags)
		fallthrough
	case "info":
		logInfo = log.New(out, "Info: ", logflags)
		fallthrough
	case "warning":
		logWarning = log.New(out, "Warning: ", logflags)
		fallthrough
	case "error":
		logError = log.New(out, "Error: ", logflags)
	case "none":
	default:
		log.Fatalln("Unknown log level: ", level)
	}
}

// parseServerFlags parses flags for the server run option.
func parseServerFlags(args []string) Config {
	f := flag.NewFlagSet("Server", flag.ExitOnError)

	var laddr = f.String("l", "", "Listen (default \":2022\")")
	var privateKeyPath = f.String("key", "", "Private key location")
	var sharedDir = f.String("shared", "", "Path to the shared working directory")
	var usersDir = f.String("users", "", "Path to where users directories are created")
	var keysDir = f.String("keys", "", "Path to keys directory")
	var logLevel = f.String("log", "", "Log level [debug,info,warning,error,none]. Warning: debug will echo passwords to log (default \"info\")")
	var logFile = f.String("logfile", "", "Log filename (use - for stdout) (default stdout)")
	var passwdFile = f.String("P", "", "Password file")
	var cmd = f.String("cmd", "", "Command to run on an uploaded file. Filname will be past as the last argument. @filename to run file")
	var scpPath = f.String("scp", "", "Path to scp (default \"/usr/bin/scp\")")
	var configFile = f.String("c", "", "Config file path")
	var genprivkey = f.Bool("genpriv", false, "Generate random private key")

	f.Parse(args)

	var config Config

	var err error
	config, err = getConfig(*configFile)
	config = addConfigDefaults(config)
	if err != nil {
		log.Fatalf("Unable to read config: %v\n", err)
	}

	if len(config.Cmd) != 0 || *cmd != "" {
		if runtime.GOOS == "windows" {
			logError.Fatalln("Cmd not available on windows")
		}
		if *cmd != "" {
			config.Cmd = parseCmdLine(*cmd)
		}
	}

	if *scpPath != "" {
		config.ScpPath = *scpPath
	}

	if *laddr != "" {
		config.Listen = *laddr
	}
	if *privateKeyPath != "" {
		config.PrivateKey = *privateKeyPath
	}
	if *sharedDir != "" {
		if !strings.HasPrefix(*sharedDir, string(filepath.Separator)) {
			log.Fatalf("shared must be an absolute path\n")
		}
		config.SharedDir = addSepSuffix(*sharedDir)
	}
	if *usersDir != "" {
		if !strings.HasPrefix(*usersDir, string(filepath.Separator)) {
			log.Fatal("users must be an absolute path\n")
		}
		config.UsersDir = addSepSuffix(*usersDir)
	}
	if *keysDir != "" {
		config.KeysDir = addSepSuffix(*keysDir)
	}
	if *logLevel != "" {
		config.LogLevel = *logLevel
	}
	if *logFile != "" {
		config.LogFile = *logFile
	}
	if *passwdFile != "" {
		config.PasswdFile = *passwdFile
	}
	if *genprivkey {
		config.PrivateKey = ""
	}

	return config
}

// parseUserFlags parses flags for the add user option.
func parseUserFlags(args []string) (userInfo UserInfo, config Config, t int) {
	f := flag.NewFlagSet("User", flag.ExitOnError)

	// Mandatory
	var upload = f.Bool("up", false, "Upload privileges")
	var download = f.Bool("down", false, "Download privileges")

	// Can be randomized
	var username = f.String("u", "", "The username, will be randomized if non is set")
	var password = f.String("p", "", "The Password, will be queried or randomized if non is set")

	f.BoolVar(&userInfo.Plaintext, "plain", false, "Create a plain text password")
	f.BoolVar(&userInfo.Permanent, "perm", false, "Permanent user")

	var userDir = f.String("dir", "", "Set a users working directory (default \"<usersDir>/<username>\")")
	var nouserDir = f.Bool("nouserdir", false, "Make the user use the default up/download dirs")
	var revUp = f.Bool("recup", false, "Allow recursive uploads")
	var revDown = f.Bool("recdown", false, "Allow recursive downloads")
	var upSize = f.String("upsize", "0", "Maximum upload size")

	var keyfile = f.Bool("key", false, "Create key file template")

	var passwdFile = f.String("passfile", "", "Output passwd file")
	var configFile = f.String("c", "", "Config file path")

	f.Parse(args)

	config, err := getConfig(*configFile)
	config = addConfigDefaults(config)
	if err != nil {
		log.Fatalf("Unable to read config: %v\n", err)
	}

	if !*upload && !*download {
		log.Println("Privileges need to be defined")
		f.PrintDefaults()
		os.Exit(1)
	}

	if userInfo.Plaintext && bytes.Contains(userInfo.Password, []byte(":")) {
		log.Fatalln("Colons \":\" not allowed in plain text passwords")
	}

	userInfo.Username = []byte(*username)
	userInfo.Password = []byte(*password)

	if *userDir == "" && !*nouserDir {
		userInfo.UserDir = []byte(config.UsersDir)
		userInfo.UserDir = append(userInfo.UserDir, userInfo.Username...)
	} else if *userDir != "" {

		userInfo.UserDir = []byte(addSepSuffix(*userDir))
		if !bytes.HasPrefix(userInfo.UserDir, []byte(string(filepath.Separator))) {
			log.Fatalf("userDir must be an absolute path\n")
		}
	}

	if *download {
		userInfo.Privileges = append(userInfo.Privileges, byte('r'))
	}
	if *upload {
		userInfo.Privileges = append(userInfo.Privileges, byte('w'))
	}

	if *revDown {
		userInfo.Recursive = append(userInfo.Recursive, byte('r'))
	}
	if *revUp {
		userInfo.Recursive = append(userInfo.Recursive, byte('w'))
	}

	si, err := strconv.Atoi(*upSize)
	if err != nil {
		userInfo.UpSize, err = toBytes(*upSize)
		if err != nil {
			log.Fatalf("Unable to parse size %s:%s\n", *upSize, err)
		}
	} else {
		userInfo.UpSize = uint64(si)
	}

	if *passwdFile != "" {
		config.PasswdFile = *passwdFile
	}
	t = 1
	if *keyfile {
		t = 2
	}

	return userInfo, config, t
}

func main() {
	flag.Usage = printUsage
	flag.Parse()

	switch flag.Arg(0) {
	case "server":
		config := parseServerFlags(flag.Args()[1:])
		initLog(config.LogFile, config.LogLevel)
		logDebug.Printf("%+v", config)
		runServer(config)
	case "user":
		userInfo, config, t := parseUserFlags(flag.Args()[1:])
		initLog(config.LogFile, config.LogLevel)
		switch t {
		case 1:
			addUser(userInfo, config.PasswdFile)
		case 2:
			createKeyFile(userInfo, config.KeysDir)
		}
	default:
		printUsage()
	}
}
