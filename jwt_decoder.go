// jwt_decoder.go
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
	"crypto/hmac"
	"crypto/sha256"
)

type JWT struct {
	Token          string
	Key            string
	Header         map[string]interface{}
	Payload        map[string]interface{}
	Signature      string
	ValidSignature *bool
	IsExpired      *bool
}

func (j *JWT) Decode() error {
	parts := strings.Split(j.Token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("header decode: %v", err)
	}
	if err := json.Unmarshal(headerBytes, &j.Header); err != nil {
		return err
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("payload decode: %v", err)
	}
	if err := json.Unmarshal(payloadBytes, &j.Payload); err != nil {
		return err
	}

	j.Signature = parts[2]

	// Check expiration
	if exp, ok := j.Payload["exp"]; ok {
		if expFloat, ok := exp.(float64); ok {
			expTime := time.Unix(int64(expFloat), 0)
			now := time.Now()
			expired := now.After(expTime)
			j.IsExpired = &expired
		}
	} else {
		j.IsExpired = nil
	}

	// Verify signature if key provided
	if j.Key != "" {
		valid, err := j.verifySignature()
		if err == nil {
			j.ValidSignature = &valid
		} else {
			j.ValidSignature = nil
		}
	}
	return nil
}

func (j *JWT) verifySignature() (bool, error) {
	parts := strings.Split(j.Token, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid JWT")
	}
	data := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(j.Key))
	mac.Write([]byte(data))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return expected == parts[2], nil
}

func (j *JWT) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"header":    j.Header,
		"payload":   j.Payload,
		"signature": j.Signature,
		"token":     j.Token,
	}
	if j.ValidSignature != nil {
		m["valid_signature"] = *j.ValidSignature
	}
	if j.IsExpired != nil {
		m["expired"] = *j.IsExpired
	}
	return m
}

func main() {
	var (
		key      string
		filePath string
		jsonOut  bool
		color    bool
	)
	flag.StringVar(&key, "key", "", "Secret key for HMAC")
	flag.StringVar(&filePath, "file", "", "Read JWT from file")
	flag.BoolVar(&jsonOut, "json", false, "Output as JSON")
	flag.BoolVar(&color, "color", false, "Force color output")
	flag.Parse()

	token := flag.Arg(0)
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		token = strings.TrimSpace(string(data))
	}

	if token == "" {
		// Try stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			data, _ := os.ReadAll(os.Stdin)
			token = strings.TrimSpace(string(data))
		}
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: no token provided")
		os.Exit(1)
	}

	jwt := JWT{Token: token, Key: key}
	if err := jwt.Decode(); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding JWT: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		b, _ := json.MarshalIndent(jwt.ToMap(), "", "  ")
		fmt.Println(string(b))
	} else {
		// Print pretty
		fmt.Println("Header:")
		for k, v := range jwt.Header {
			fmt.Printf("  %s: %v\n", k, v)
		}
		fmt.Println("Payload:")
		for k, v := range jwt.Payload {
			fmt.Printf("  %s: %v\n", k, v)
		}
		if jwt.IsExpired != nil {
			if *jwt.IsExpired {
				fmt.Println("  ✗ Token expired")
			} else {
				fmt.Println("  ✓ Token valid")
			}
		}
		if jwt.ValidSignature != nil {
			if *jwt.ValidSignature {
				fmt.Println("  ✓ Signature verified")
			} else {
				fmt.Println("  ✗ Signature invalid")
			}
		}
		fmt.Printf("Signature: %s\n", jwt.Signature)
	}
}
