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
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// scpReader is a struct that handles reading from an scp stream.
type scpReader struct {
	reader   io.Reader
	phase    *int
	dirname  *string
	filename *string
	filesize *uint64
	currsize *uint64
	maxSize  uint64
	filechan chan string
}

// Read keeps track of read states and logs information about the transfer.
// It is also capable of setting a file size to 0 if it exceeds the allowed size.
func (r scpReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)

	if n < 30 {
		logDebug.Printf("Read %d bytes: %q", n, string(p[:n]))
	} else {
		logDebug.Printf("Read %d bytes: %q", n, string(p[:30]))
		logDebug.Printf("Read Last 30: %q", string(p[n-30:n]))
	}

	if n == 0 || (*r.phase == 0 && n == 1 && p[0] == 0) {
		return n, err
	}

	if *r.phase == 0 {
		switch p[0] {
		case byte('E'): // Exit directory
			*r.dirname = path.Dir(*r.dirname)
		case byte('D'): // Change path
			nameStart := bytes.Index(p[6:], []byte(" ")) + 7
			*r.dirname = path.Join(*r.dirname, string(p[nameStart:n-1]))
		case byte('C'): // Handle file
			sizeEnd := bytes.Index(p[6:], []byte(" ")) + 6
			sb := p[6:sizeEnd]
			size, err := strconv.ParseUint(string(sb), 10, 64)
			if err != nil {
				logError.Printf("Unable to convert file size %q : %s\n", sb, err)
			}

			*r.filename = string(p[sizeEnd+1 : n-1])
			*r.filesize = size

			if r.maxSize != 0 && size > r.maxSize {
				logInfo.Printf("Filesize exceeded for %s/%s\n", *r.dirname, *r.filename)
				newBuf := bytes.Join([][]byte{p[:5], []byte("0"), p[sizeEnd+1 : n]}, []byte(" "))

				logDebug.Printf("newBuf %d: %q\n", len(newBuf), newBuf)
				copy(p, newBuf)
				*r.phase = 2
				logDebug.Println("Switch to phase 2")

				return len(newBuf), err
			}

			*r.phase = 1
			logDebug.Println("Switch to phase 1")
		default:
			logWarning.Printf("Neither dirname nor filename at phase 0: %q\n", string(p[:10]))
		}
	} else {
		*r.currsize += uint64(n)

		if *r.currsize == *r.filesize+1 {
			if *r.phase == 1 {
				logInfo.Printf("Uploaded file %s/%s Size %d\n", *r.dirname, *r.filename, *r.currsize-1)
				r.filechan <- fmt.Sprintf("%s/%s", *r.dirname, *r.filename)
			} else if *r.phase == 2 {
				logInfo.Printf("Suppressed file %s/%s Size %d\n", *r.dirname, *r.filename, *r.currsize-1)
				p[0] = 0
				n = 1
			} else {
				logError.Fatalf("Unknown phase %d\n", *r.phase)
			}

			*r.currsize = 0
			*r.filename = ""
			*r.phase = 0
			logDebug.Printf("Switch to phase0")
		} else if *r.phase == 2 {
			return 0, err
		}
	}

	return n, err
}

// scpWriter is a struct that handles writing to an scp stream.
type scpWriter struct {
	writer   io.Writer
	phase    *int
	dirname  *string
	filename *string
	filesize *uint64
	currsize *uint64
	filechan chan string
}

// Write keeps track of write states and logs information about the transfer.
func (w scpWriter) Write(p []byte) (n int, err error) {
	n, err = w.writer.Write(p)

	if n < 30 {
		logDebug.Printf("Write: %q", string(p[:n]))
	} else {
		logDebug.Printf("Write: %q", string(p[:30]))
		logDebug.Printf("Write Last 30: %q", string(p[n-30:n]))
	}

	if n == 0 || (n == 1 && p[0] == 0) {
		return n, err
	}

	switch *w.phase {
	case 0:
		switch p[0] {
		case byte('E'): // Exit directory
			*w.dirname = path.Dir(*w.dirname)
		case byte('D'): // Change directory
			nameStart := bytes.Index(p[6:], []byte(" ")) + 7
			*w.dirname = path.Join(*w.dirname, string(p[nameStart:n-1]))
		case byte('C'): //Handle file
			sizeEnd := bytes.Index(p[6:], []byte(" ")) + 6
			sb := p[6:sizeEnd]
			size, err := strconv.ParseUint(string(sb), 10, 64)
			if err != nil {
				logError.Printf("Unable to convert file size %q : %s\n", sb, err)
			}
			*w.filesize = size
			*w.filename = string(p[sizeEnd+1 : n-1])
			*w.phase = 1
			logDebug.Println("Switch to phase 1")
		default:
			logWarning.Printf("Neither dirname nor filename at phase 0: %q\n", string(p[:10]))
		}
	case 1:
		*w.currsize += uint64(n)
		if *w.currsize == *w.filesize+1 {
			logDebug.Printf("Switch to phase0")
			logInfo.Printf("Downloaded file %s/%s Size %d\n", *w.dirname, *w.filename, *w.currsize-1)
			w.filechan <- fmt.Sprintf("%s/%s", *w.dirname, *w.filename)
			*w.phase = 0
			*w.currsize = 0
			*w.filename = ""
		}
	}

	return n, err
}

// parseCmdLine takes a string and splits it into command line options
func parseCmdLine(cmdline string) (args []string) {

	if strings.HasPrefix(cmdline, "@") {
		if strings.Contains(cmdline, "/") {
			args = append(args, cmdline[1:])
		} else {
			args = append(args, "./"+cmdline[1:])
		}
	} else {
		lastQuote := rune(0)
		f := func(c rune) bool {
			switch {
			case c == lastQuote:
				lastQuote = rune(0)
				return false
			case lastQuote != rune(0):
				return false
			case unicode.In(c, unicode.Quotation_Mark):
				lastQuote = c
				return false
			default:
				return unicode.IsSpace(c)
			}
		}

		args = strings.FieldsFunc(cmdline, f)
	}

	return args
}

// removeSepPrefix removes a separator character if it's prefixed to the string.
func removeSepPrefix(s string) string {
	sep := string(filepath.Separator)
	if strings.HasPrefix(s, sep) {
		s = strings.TrimLeft(s, sep)
	}
	return s
}

// addSepSuffic adds a separator character if non is suffixed to the string.
func addSepSuffix(s string) string {
	sep := string(filepath.Separator)
	if !strings.HasSuffix(s, sep) {
		s += sep
	}
	return s
}

const (
	BYTE     = 1.0
	KILOBYTE = 1024 * BYTE
	MEGABYTE = 1024 * KILOBYTE
	GIGABYTE = 1024 * MEGABYTE
	TERABYTE = 1024 * GIGABYTE
)

var bytesPattern = regexp.MustCompile(`(?i)^(-?\d+)([KMGT]B?|B)$`)
var errInvalidByteQuantity = errors.New("Byte quantity must be a positive integer with a unit of measurement like M, MB, G, or GB")

// toBytes takes a string representation of a size and returns it in bytes.
func toBytes(s string) (uint64, error) {
	parts := bytesPattern.FindStringSubmatch(strings.TrimSpace(s))
	if len(parts) < 3 {
		return 0, errInvalidByteQuantity
	}

	value, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || value < 1 {
		return 0, errInvalidByteQuantity
	}

	var bytes uint64
	unit := strings.ToUpper(parts[2])
	switch unit[:1] {
	case "T":
		bytes = value * TERABYTE
	case "G":
		bytes = value * GIGABYTE
	case "M":
		bytes = value * MEGABYTE
	case "K":
		bytes = value * KILOBYTE
	case "B":
		bytes = value * BYTE
	}

	return bytes, nil
}

// isEmptyDir checks if a directory exists and is empty.
func isEmptyDir(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

// isFile checks if a file exists and is indeed a file.
func isFile(path string) (bool, error) {
	f, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	if f.Mode().IsRegular() {
		return true, nil
	}

	return false, nil
}

// dirExists checks if a directory exists and is indeed a directory.
func dirExists(path string) (bool, error) {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if fi.IsDir() {
		return true, nil
	}
	return false, fmt.Errorf("Path is not a directory")
}

// appendToFile appends a byte array to a file. It will create the file if it does not exist.
func appendToFile(filename string, content []byte) {
	fileh, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logError.Fatalf("Error opening file: %s\n", err)
	}
	defer fileh.Close()

	if _, err := fileh.Write(content); err != nil {
		logError.Fatalf("Error appending to file: %s\n", err)
	}
}
