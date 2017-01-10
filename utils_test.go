package main

import (
	//"bufio"
	//"bytes"
	"path/filepath"
	"testing"
)

/*
func TestScpReader(t *testing.T) {
	type testStruct struct {
		phase         int
		dirname       string
		filename      string
		filesize      uint64
		currsize      uint64
		uploadedFiles []string
	}

	initLog("-", "debug")
	var reader scpReader
	reader.phase = new(int)
	reader.dirname = new(string)
	reader.filename = new(string)
	reader.filesize = new(uint64)
	reader.currsize = new(uint64)
	reader.filechan = make(chan string)

	tests := make(map[string]testStruct)
	tests["testbyte thingy"] = testStruct{1, "a", "b", 1, 1, []string{}}

	var uploadedFiles []string
	go func() {
		for file := range reader.filechan {
			uploadedFiles = append(uploadedFiles, file)
		}
	}()

	for testIn, expectedOut := range tests {
		b := bytes.NewBuffer([]byte(testIn))
		reader.reader = b
		uploadedFiles = uploadedFiles[:0]

		buf := make([]byte, 1000)
		_, _ = reader.Read(buf)

		if *reader.phase != expectedOut.phase {
			t.Errorf("Wrong phase (%d), expected %d\n", *reader.phase, expectedOut.phase)
		}
		if *reader.dirname != expectedOut.dirname {
			t.Errorf("Wrong dirname (%s), expected %s\n", *reader.dirname, expectedOut.dirname)
		}
		if *reader.filename != expectedOut.filename {
			t.Errorf("Wrong filename (%s), expected %s\n", *reader.filename, expectedOut.filename)
		}
		if *reader.filesize != expectedOut.filesize {
			t.Errorf("Wrong filesize (%d), expected %d\n", *reader.filesize, expectedOut.filesize)
		}
		if *reader.currsize != expectedOut.currsize {
			t.Errorf("Wrong currsize (%d), expected %d\n", *reader.currsize, expectedOut.currsize)
		}
		if len(uploadedFiles) != len(expectedOut.uploadedFiles) {
			t.Errorf("Wrong number of uploaded files (%d), expecting %d\n", len(uploadedFiles), len(expectedOut.uploadedFiles))
		}
	}

}
*/
/*
func TestScpWriter(t *testing.T) {

	type testStruct struct {
		phase         int
		dirname       string
		filename      string
		filesize      uint64
		currsize      uint64
		uploadedFiles []string
	}

	initLog("-", "debug")
	var writer scpWriter
	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	writer.writer = w
	writer.phase = new(int)
	writer.dirname = new(string)
	writer.filename = new(string)
	writer.filesize = new(uint64)
	writer.currsize = new(uint64)
	writer.filechan = make(chan string)

	tests := make(map[string]testStruct)
	tests["testbyte thingy"] = testStruct{1, "a", "b", 1, 1, []string{}}

	var uploadedFiles []string
	go func() {
		for file := range writer.filechan {
			uploadedFiles = append(uploadedFiles, file)
		}
	}()

	for testIn, expectedOut := range tests {
		uploadedFiles = uploadedFiles[:0]

		_, _ = writer.Write([]byte(testIn))
		if *writer.phase != expectedOut.phase {
			t.Errorf("Wrong phase (%d), expected %d\n", *writer.phase, expectedOut.phase)
		}
		if *writer.dirname != expectedOut.dirname {
			t.Errorf("Wrong dirname (%s), expected %s\n", *writer.dirname, expectedOut.dirname)
		}
		if *writer.filename != expectedOut.filename {
			t.Errorf("Wrong filename (%s), expected %s\n", *writer.filename, expectedOut.filename)
		}
		if *writer.filesize != expectedOut.filesize {
			t.Errorf("Wrong filesize (%d), expected %d\n", *writer.filesize, expectedOut.filesize)
		}
		if *writer.currsize != expectedOut.currsize {
			t.Errorf("Wrong currsize (%d), expected %d\n", *writer.currsize, expectedOut.currsize)
		}
		if len(uploadedFiles) != len(expectedOut.uploadedFiles) {
			t.Errorf("Wrong number of uploaded files (%d), expecting %d\n", len(uploadedFiles), len(expectedOut.uploadedFiles))
		}
	}

}
*/
func TestParseCmdLine(t *testing.T) {
	tests := make(map[string][]string)
	tests["@/test/path/filename.sh"] = []string{"/test/path/filename.sh"}
	tests["@test/path/filename.sh"] = []string{"test/path/filename.sh"}
	tests["@filename.sh"] = []string{"./filename.sh"}
	tests["program arg1 \"arg 2\" arg3"] = []string{"program", "arg1", "\"arg 2\"", "arg3"}
	tests["program -c arg1 \"arg 2\" arg3"] = []string{"program", "-c", "arg1", "\"arg 2\"", "arg3"}

	for testIn, expectedOut := range tests {
		out := parseCmdLine(testIn)
		if len(out) != len(expectedOut) {
			t.Errorf("%s output not correct length\n", testIn)
		} else {
			for i, arg := range out {
				if arg != expectedOut[i] {
					t.Errorf("Arg %d (%s) does not match expected (%s)\n", i, arg, expectedOut[i])
				}
			}
		}
	}
}

func TestRemoveSepPrefix(t *testing.T) {
	sep := string(filepath.Separator)

	tests := make(map[string]string)
	tests["string"] = "string"
	tests[sep+"string"] = "string"
	tests[sep+"string"+sep] = "string" + sep
	tests["string"+sep] = "string" + sep

	for testIn, expectedOut := range tests {
		if out := removeSepPrefix(testIn); out != expectedOut {
			t.Errorf("output (%s) does not match expected (%s)\n", out, expectedOut)
		}
	}
}

func TestAddSepSuffix(t *testing.T) {
	sep := string(filepath.Separator)

	tests := make(map[string]string)
	tests["string"] = "string" + sep
	tests["string"+sep] = "string" + sep
	tests[sep+"string"] = sep + "string" + sep
	tests[sep+"string"+sep] = sep + "string" + sep

	for testIn, expectedOut := range tests {
		if out := addSepSuffix(testIn); out != expectedOut {
			t.Errorf("output (%s) does not match expected (%s)\n", out, expectedOut)
		}
	}
}

func TestToBytes(t *testing.T) {
	type testStruct struct {
		bytes uint64
		err   error
	}

	tests := make(map[string]testStruct)
	tests["10MB"] = testStruct{10485760, nil}
	tests["10m"] = testStruct{10485760, nil}
	tests["10megabytes"] = testStruct{0, errInvalidByteQuantity}
	tests["3kb"] = testStruct{3072, nil}
	tests["3K"] = testStruct{3072, nil}
	tests["123"] = testStruct{0, errInvalidByteQuantity}

	for testIn, expectedOut := range tests {
		bytes, err := toBytes(testIn)
		if bytes != expectedOut.bytes {
			t.Errorf("bytes (%d) do not match expected (%d)\n", bytes, expectedOut.bytes)
		}
		if err != expectedOut.err {
			t.Errorf("Error (%v) does not match expected (%v)\n", err, expectedOut.err)
		}
	}
}
