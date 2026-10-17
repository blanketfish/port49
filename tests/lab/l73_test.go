//go:build lab

package lab

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// scpWrite is the source side of scp's protocol to a sink at path: wait for
// its ack, send the C line, ack, the bytes and a NUL, ack. L73 sends only
// public certificates this way.
func scpWrite(c *ssh.Client, path string, body []byte) error {
	if err := scpCheckBody(body); err != nil {
		return err
	}
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	defer time.AfterFunc(60*time.Second, func() { s.Close() }).Stop()
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	var stderr bytes.Buffer
	s.Stderr = &stderr
	if err := s.Start("scp -t " + path); err != nil {
		return err
	}
	r := bufio.NewReader(out)
	ack := func() error {
		b, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("scp: %v %s", err, oneLine(stderr.String()))
		}
		if b != 0 {
			msg, _ := r.ReadString('\n')
			return fmt.Errorf("scp refused: %s %s", strings.TrimSpace(msg), oneLine(stderr.String()))
		}
		return nil
	}
	frame := scpSinkFrame(filepath.Base(path), body)
	nl := bytes.IndexByte(frame, '\n')
	for _, step := range [][]byte{nil, frame[:nl+1], frame[nl+1:]} {
		if step != nil {
			if _, err := in.Write(step); err != nil {
				return err
			}
		}
		if err := ack(); err != nil {
			return err
		}
	}
	in.Close()
	if err := s.Wait(); err != nil && err != io.EOF {
		return fmt.Errorf("scp: %v %s", err, oneLine(stderr.String()))
	}
	return nil
}
