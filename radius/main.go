package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type Config struct {
	LogFile    string
	ServerInfo struct {
		Identifier string
		IpAddress  string
	}
	Radius struct {
		Authentication struct {
			Server string
			Secret string
		}
		Accounting struct {
			Server string
			Secret string
		}
	}
}

// Generate unique session ID via MD5 hash
func getSessionID(username string) string {
	dir := "/var/run/ovpn-radius"
	path := filepath.Join(dir, username+".session")
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		return strings.TrimSpace(string(data))
	}
	hash := md5.New()
	b := make([]byte, 16)
	rand.Read(b)
	hash.Write(b)
	id := hex.EncodeToString(hash.Sum(nil))[:16]
	os.WriteFile(path, []byte(id), 0644)
	return id
}

func clearSessionID(username string) string {
	id := getSessionID(username)
	os.Remove(filepath.Join("/var/run/ovpn-radius", username+".session"))
	return id
}

// Fast Radius Exchange with strict 2-sec timeout
func sendRADIUS(packet *radius.Packet, server string) (*radius.Packet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return radius.Exchange(ctx, packet, server)
}

func main() {
	configData, err := os.ReadFile("/etc/openvpn/plugin/config.json")
	if err != nil {
		os.Exit(1)
	}
	var conf Config
	json.Unmarshal(configData, &conf)

	action := "auth"
	if len(os.Args) > 1 && os.Args[1] == "interim" {
		action = "interim"
	} else {
		switch os.Getenv("script_type") {
		case "user-pass-verify", "auth-user-pass-verify":
			action = "auth"
		case "client-connect":
			action = "acct"
		case "client-disconnect":
			action = "stop"
		}
	}

	nasIP := net.ParseIP(conf.ServerInfo.IpAddress).To4()
	nasID := conf.ServerInfo.Identifier

	// ==========================================
	// AUTHENTICATION BLOCK
	// ==========================================
	if action == "auth" {
		authFile := ""
		if len(os.Args) > 1 {
			authFile = os.Args[1]
		}
		var username, password string
		if authFile != "" {
			lines, _ := os.ReadFile(authFile)
			parts := strings.Split(string(lines), "\n")
			if len(parts) >= 2 {
				username = strings.TrimSpace(parts[0])
				password = strings.TrimSpace(parts[1])
			}
		} else {
			username = os.Getenv("username")
			password = os.Getenv("password")
		}
		if username == "" || password == "" {
			os.Exit(1)
		}

		packet := radius.New(radius.CodeAccessRequest, []byte(conf.Radius.Authentication.Secret))
		rfc2865.UserName_SetString(packet, username)
		rfc2865.UserPassword_SetString(packet, password)
		
		packet.Add(radius.Type(4), radius.Attribute(nasIP))
		packet.Add(radius.Type(32), radius.Attribute([]byte(nasID)))
		packet.Add(radius.Type(61), radius.NewInteger(5)) // Virtual
		packet.Add(radius.Type(6), radius.NewInteger(2))  // Framed-User
		packet.Add(radius.Type(7), radius.NewInteger(1))  // PPP

		calling := os.Getenv("untrusted_ip")
		if calling != "" {
			packet.Add(radius.Type(31), radius.Attribute([]byte(calling)))
		}

		res, err := sendRADIUS(packet, conf.Radius.Authentication.Server)
		if err == nil && res.Code == radius.CodeAccessAccept {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// ==========================================
	// ACCOUNTING START/STOP BLOCK
	// ==========================================
	if action == "acct" || action == "stop" {
		username := os.Getenv("common_name")
		calling := os.Getenv("untrusted_ip")
		clientIP := os.Getenv("ifconfig_pool_remote_ip")

		statusType := uint32(1) // Start
		sessionID := getSessionID(username)

		bytesIn, _ := strconv.ParseUint(os.Getenv("bytes_received"), 10, 64)
		bytesOut, _ := strconv.ParseUint(os.Getenv("bytes_sent"), 10, 64)
		sessionTime, _ := strconv.ParseUint(os.Getenv("time_duration"), 10, 32)

		if action == "stop" {
			statusType = 2 // Stop
			sessionID = clearSessionID(username)
		}

		packet := radius.New(radius.CodeAccountingRequest, []byte(conf.Radius.Accounting.Secret))
		packet.Add(radius.Type(1), radius.Attribute([]byte(username)))
		packet.Add(radius.Type(4), radius.Attribute(nasIP))
		packet.Add(radius.Type(32), radius.Attribute([]byte(nasID)))
		packet.Add(radius.Type(40), radius.NewInteger(statusType))
		packet.Add(radius.Type(44), radius.Attribute([]byte(sessionID)))
		packet.Add(radius.Type(45), radius.NewInteger(1)) // RADIUS Auth
		packet.Add(radius.Type(41), radius.NewInteger(0)) // Delay-Time

		if calling != "" {
			packet.Add(radius.Type(31), radius.Attribute([]byte(calling)))
		}
		if clientIP != "" {
			parsedIP := net.ParseIP(clientIP)
			if parsedIP != nil {
				packet.Add(radius.Type(8), radius.Attribute(parsedIP.To4()))
			}
		}
		packet.Add(radius.Type(6), radius.NewInteger(2)) // Framed-User
		packet.Add(radius.Type(7), radius.NewInteger(1)) // PPP

		if action == "stop" {
			packet.Add(radius.Type(46), radius.NewInteger(uint32(sessionTime)))
			packet.Add(radius.Type(42), radius.NewInteger(uint32(bytesIn%4294967296)))
			packet.Add(radius.Type(43), radius.NewInteger(uint32(bytesOut%4294967296)))

			if bytesIn/4294967296 > 0 {
				packet.Add(radius.Type(52), radius.NewInteger(uint32(bytesIn/4294967296))) // Gigawords In
			}
			if bytesOut/4294967296 > 0 {
				packet.Add(radius.Type(53), radius.NewInteger(uint32(bytesOut/4294967296))) // Gigawords Out
			}
		}

		sendRADIUS(packet, conf.Radius.Accounting.Server)
		os.Exit(0)
	}

	// ==========================================
	// INTERIM UPDATES (DYNAMIC HEADER PARSING)
	// ==========================================
	if action == "interim" {
		file, err := os.Open("/var/log/openvpn/openvpn-status.log")
		if err != nil {
			os.Exit(0)
		}
		defer file.Close()

		var wg sync.WaitGroup
		scanner := bufio.NewScanner(file)

		// Dynamic Indexes
		idxUser, idxRealIP, idxClientIP, idxBytesIn, idxBytesOut, idxConnTime := -1, -1, -1, -1, -1, -1

		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, ",")

			// 1. Map Headers Dynamically
			if len(parts) > 1 && parts[0] == "HEADER" && parts[1] == "CLIENT_LIST" {
				for i, col := range parts {
					col = strings.TrimSpace(col)
					switch col {
					case "Common Name":
						idxUser = i - 1
					case "Real Address":
						idxRealIP = i - 1
					case "Virtual Address":
						idxClientIP = i - 1
					case "Bytes Received":
						idxBytesIn = i - 1
					case "Bytes Sent":
						idxBytesOut = i - 1
					case "Connected Since (time_t)":
						idxConnTime = i - 1
					}
				}
				continue
			}

			// 2. Process Client Rows
			if len(parts) > 1 && parts[0] == "CLIENT_LIST" {
				// Security Check: Ensure mapping was successful
				if idxUser == -1 || idxBytesIn == -1 || idxConnTime == -1 {
					continue
				}
				if len(parts) <= idxUser || len(parts) <= idxBytesOut || len(parts) <= idxConnTime {
					continue
				}

				wg.Add(1)
				go func(p []string) {
					defer wg.Done()
					
					username := strings.TrimSpace(p[idxUser])
					realIP := strings.Split(strings.TrimSpace(p[idxRealIP]), ":")[0]
					clientIP := strings.TrimSpace(p[idxClientIP])
					
					bytesIn, _ := strconv.ParseUint(strings.TrimSpace(p[idxBytesIn]), 10, 64)
					bytesOut, _ := strconv.ParseUint(strings.TrimSpace(p[idxBytesOut]), 10, 64)
					connTime, _ := strconv.ParseInt(strings.TrimSpace(p[idxConnTime]), 10, 64)

					sessionID := getSessionID(username)
					
					// Calculate accurate session time
					currentUnix := time.Now().Unix()
					sessionTime := currentUnix - connTime
					if sessionTime < 0 || connTime == 0 {
						sessionTime = 0
					}

					packet := radius.New(radius.CodeAccountingRequest, []byte(conf.Radius.Accounting.Secret))
					packet.Add(radius.Type(1), radius.Attribute([]byte(username)))
					packet.Add(radius.Type(4), radius.Attribute(nasIP))
					packet.Add(radius.Type(32), radius.Attribute([]byte(nasID)))
					packet.Add(radius.Type(40), radius.NewInteger(3)) // Alive
					packet.Add(radius.Type(44), radius.Attribute([]byte(sessionID)))
					packet.Add(radius.Type(45), radius.NewInteger(1)) // RADIUS Auth
					packet.Add(radius.Type(41), radius.NewInteger(0)) // Delay-Time
					packet.Add(radius.Type(31), radius.Attribute([]byte(realIP)))
					
					parsedIP := net.ParseIP(clientIP)
					if parsedIP != nil {
						packet.Add(radius.Type(8), radius.Attribute(parsedIP.To4()))
					}
					
					packet.Add(radius.Type(6), radius.NewInteger(2)) // Framed-User
					packet.Add(radius.Type(7), radius.NewInteger(1)) // PPP

					// IBSng Crucial Info: SessionTime and Traffic data
					packet.Add(radius.Type(46), radius.NewInteger(uint32(sessionTime)))
					packet.Add(radius.Type(42), radius.NewInteger(uint32(bytesIn%4294967296)))
					packet.Add(radius.Type(43), radius.NewInteger(uint32(bytesOut%4294967296)))

					if bytesIn/4294967296 > 0 {
						packet.Add(radius.Type(52), radius.NewInteger(uint32(bytesIn/4294967296)))
					}
					if bytesOut/4294967296 > 0 {
						packet.Add(radius.Type(53), radius.NewInteger(uint32(bytesOut/4294967296)))
					}

					sendRADIUS(packet, conf.Radius.Accounting.Server)
				}(parts)
			}
		}
		
		wg.Wait()
		os.Exit(0)
	}
}
