package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

const wKey = "a3K8Bx%2r8Y7#xDh"

func ppad(data []byte) []byte {
	blockSize := aes.BlockSize
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func punpad(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}
	padding := int(data[length-1])
	return data[:length-padding]
}

func wencrypt(plainText []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	paddedText := ppad(plainText)
	cipherText := make([]byte, len(paddedText))
	
	for i := 0; i < len(paddedText); i += aes.BlockSize {
		block.Encrypt(cipherText[i:i+aes.BlockSize], paddedText[i:i+aes.BlockSize])
	}
	
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func wdecrypt(cipherTextBase64 string, key []byte) ([]byte, error) {
	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i += aes.BlockSize {
		block.Decrypt(plainText[i:i+aes.BlockSize], cipherText[i:i+aes.BlockSize])
	}
	
	return punpad(plainText), nil
}

func scanDevices() {
	fmt.Println("Scanning for devices...")
	
	laddr, _ := net.ResolveUDPAddr("udp", ":0")
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		fmt.Printf("Failed to create UDP listener: %v\n", err)
		return
	}
	defer conn.Close()
	
	// Send broadcast scan
	bcast, _ := net.ResolveUDPAddr("udp", "255.255.255.255:7000")
	scanJSON := `{"t":"scan"}`
	scanPack, _ := wencrypt([]byte(scanJSON), []byte(wKey))
	
	scanReq := map[string]interface{}{
		"cid":  "app",
		"t":    "scan",
		"uid":  0,
		"pack": scanPack,
	}
	
	reqData, _ := json.Marshal(scanReq)
	conn.WriteToUDP(reqData, bcast)
	
	// Listen for responses
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	devices := make(map[string]string)
	
	for {
		buf := make([]byte, 2048)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			continue
		}
		
		var resp map[string]interface{}
		if err := json.Unmarshal(buf[:n], &resp); err != nil {
			continue
		}
		
		if resp["t"] == "pack" {
			if pack, ok := resp["pack"].(string); ok {
				decrypted, err := wdecrypt(pack, []byte(wKey))
				if err == nil {
					var dev map[string]interface{}
					if err := json.Unmarshal(decrypted, &dev); err == nil {
						if dev["t"] == "dev" {
							if mac, ok := dev["mac"].(string); ok {
								devices[mac] = addr.IP.String()
							}
						}
					}
				}
			}
		}
	}
	
	if len(devices) == 0 {
		fmt.Println("No devices found")
	} else {
		// Known device labels
		knownDevices := map[string]string{
			"f4911ef6d9bf": "gang",
			"f4911ef82651": "woonkamer",
		}
		
		fmt.Println("Found devices:")
		for mac, ip := range devices {
			label := knownDevices[mac]
			if label != "" {
				fmt.Printf("  %s: MAC: %s, IP: %s\n", label, mac, ip)
			} else {
				fmt.Printf("  unknown: MAC: %s, IP: %s\n", mac, ip)
			}
		}
	}
}

func main() {
	// Device configuration
	devices := map[string]struct {
		MAC string
		IP  string
	}{
		"gang":      {"f4911ef6d9bf", "192.168.1.223"},
		"woonkamer": {"f4911ef82651", "192.168.1.222"},
	}
	
	if len(os.Args) < 2 {
		fmt.Println("Usage: tosot-ac-control scan")
		fmt.Println("       tosot-ac-control [status|start|stop] [gang|woonkamer]")
		fmt.Println("       tosot-ac-control temp [gang|woonkamer] [temperature]")
		return
	}
	
	action := os.Args[1]
	
	if action == "scan" {
		scanDevices()
		return
	}
	
	// For other actions, require device name
	if len(os.Args) < 3 {
		fmt.Printf("Error: device name required\n")
		fmt.Println("Available devices: gang, woonkamer")
		return
	}
	
	deviceName := os.Args[2]
	device, exists := devices[deviceName]
	if !exists {
		fmt.Printf("Error: unknown device '%s'\n", deviceName)
		fmt.Println("Available devices: gang, woonkamer")
		return
	}
	
	// For temp command, require temperature value
	var targetTemp int
	if action == "temp" {
		if len(os.Args) < 4 {
			fmt.Printf("Error: temperature value required\n")
			fmt.Println("Usage: tosot-ac-control temp [gang|woonkamer] [16-30]")
			return
		}
		temp, err := fmt.Sscanf(os.Args[3], "%d", &targetTemp)
		if err != nil || temp != 1 || targetTemp < 16 || targetTemp > 30 {
			fmt.Printf("Error: invalid temperature '%s'\n", os.Args[3])
			fmt.Println("Temperature must be between 16 and 30")
			return
		}
	}
	
	deviceMAC := device.MAC
	deviceIP := device.IP
	
	fmt.Printf("Controlling %s (%s)...\n", deviceName, deviceIP)
	
	// Step 1: Bind
	conn, err := net.Dial("udp", deviceIP+":7000")
	if err != nil {
		fmt.Printf("Connect error: %v\n", err)
		return
	}
	
	bindJSON := fmt.Sprintf(`{"mac":"%s","t":"bind","uid":0}`, deviceMAC)
	bindPack, _ := wencrypt([]byte(bindJSON), []byte(wKey))
	
	bindReq := map[string]interface{}{
		"cid":  "app",
		"i":    1,
		"t":    "pack",
		"uid":  0,
		"tcid": deviceMAC,
		"pack": bindPack,
	}
	
	reqData, _ := json.Marshal(bindReq)
	conn.Write(reqData)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("Bind error: %v\n", err)
		return
	}
	
	var bindResp map[string]interface{}
	json.Unmarshal(buf[:n], &bindResp)
	
	var deviceKey string
	if pack, ok := bindResp["pack"].(string); ok {
		decrypted, _ := wdecrypt(pack, []byte(wKey))
		var bindData map[string]interface{}
		json.Unmarshal(decrypted, &bindData)
		if key, ok := bindData["key"].(string); ok {
			deviceKey = key
		}
	}
	
	if deviceKey == "" {
		fmt.Println("Failed to get device key!")
		return
	}
	
	conn.Close()
	
	// Step 2: Execute command (use fresh connection)
	conn, err = net.Dial("udp", deviceIP+":7000")
	if err != nil {
		fmt.Printf("Connect error: %v\n", err)
		return
	}
	defer conn.Close()
	
	switch action {
	case "status":
		// Request comprehensive status fields
		statusJSON := fmt.Sprintf(`{"cols":["Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet","Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt","SlpMod","TemSen"],"mac":"%s","t":"status"}`, deviceMAC)
		statusPack, _ := wencrypt([]byte(statusJSON), []byte(deviceKey))
		
		statusReq := map[string]interface{}{
			"cid":  "app",
			"i":    0,
			"t":    "pack",
			"uid":  0,
			"tcid": deviceMAC,
			"pack": statusPack,
		}
		
		reqData, _ = json.Marshal(statusReq)
		conn.Write(reqData)
		
	case "start":
		cmdJSON := fmt.Sprintf(`{"t":"cmd","mac":"%s","opt":["Pow"],"p":[1]}`, deviceMAC)
		cmdPack, _ := wencrypt([]byte(cmdJSON), []byte(deviceKey))
		
		cmdReq := map[string]interface{}{
			"cid":  "app",
			"i":    0,
			"t":    "pack",
			"uid":  0,
			"tcid": deviceMAC,
			"pack": cmdPack,
		}
		
		reqData, _ = json.Marshal(cmdReq)
		conn.Write(reqData)
		
	case "stop":
		cmdJSON := fmt.Sprintf(`{"t":"cmd","mac":"%s","opt":["Pow"],"p":[0]}`, deviceMAC)
		cmdPack, _ := wencrypt([]byte(cmdJSON), []byte(deviceKey))
		
		cmdReq := map[string]interface{}{
			"cid":  "app",
			"i":    0,
			"t":    "pack",
			"uid":  0,
			"tcid": deviceMAC,
			"pack": cmdPack,
		}
		
		reqData, _ = json.Marshal(cmdReq)
		conn.Write(reqData)
		
	case "temp":
		cmdJSON := fmt.Sprintf(`{"t":"cmd","mac":"%s","opt":["SetTem"],"p":[%d]}`, deviceMAC, targetTemp)
		cmdPack, _ := wencrypt([]byte(cmdJSON), []byte(deviceKey))
		
		cmdReq := map[string]interface{}{
			"cid":  "app",
			"i":    0,
			"t":    "pack",
			"uid":  0,
			"tcid": deviceMAC,
			"pack": cmdPack,
		}
		
		reqData, _ = json.Marshal(cmdReq)
		conn.Write(reqData)
		
	default:
		fmt.Println("Unknown action")
		return
	}
	
	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Printf("Response error: %v\n", err)
		return
	}
	
	var resp map[string]interface{}
	json.Unmarshal(buf[:n], &resp)
	
	if pack, ok := resp["pack"].(string); ok {
		decrypted, err := wdecrypt(pack, []byte(deviceKey))
		if err != nil {
			fmt.Printf("Decrypt error: %v\n", err)
			return
		}
		
		var data map[string]interface{}
		json.Unmarshal(decrypted, &data)
		
		if action == "status" {
			if cols, ok := data["cols"].([]interface{}); ok {
				if dat, ok := data["dat"].([]interface{}); ok {
					fmt.Println("AC Status:")
					fmt.Println("====================")
					for i := 0; i < len(cols) && i < len(dat); i++ {
						col := cols[i].(string)
						val := int(dat[i].(float64))
						switch col {
						case "Pow":
							fmt.Printf("  Power: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "Mod":
							fmt.Printf("  Mode: %s\n", map[int]string{0: "Auto", 1: "Cool", 2: "Dry", 3: "Fan", 4: "Heat"}[val])
						case "SetTem":
							fmt.Printf("  Set Temperature: %d°C\n", val)
						case "WdSpd":
							fmt.Printf("  Fan Speed: %s\n", map[int]string{0: "Auto", 1: "Low", 2: "Medium-Low", 3: "Medium", 4: "Medium-High", 5: "High"}[val])
						case "Air":
							fmt.Printf("  Air (Fresh): %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "Blo":
							fmt.Printf("  Blow: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "Health":
							fmt.Printf("  Health: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "SwhSlp":
							fmt.Printf("  Sleep: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "Lig":
							fmt.Printf("  Light: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "SwingLfRig":
							fmt.Printf("  Swing Left/Right: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "SwUpDn":
							fmt.Printf("  Swing Up/Down: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "Quiet":
							fmt.Printf("  Quiet: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "Tur":
							fmt.Printf("  Turbo: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "StHt":
							fmt.Printf("  StHt: %d\n", val)
						case "TemUn":
							fmt.Printf("  Temperature Unit: %s\n", map[int]string{0: "Celsius", 1: "Fahrenheit"}[val])
						case "HeatCoolType":
							fmt.Printf("  Heat/Cool Type: %d\n", val)
						case "TemRec":
							fmt.Printf("  TemRec: %d\n", val)
						case "SvSt":
							fmt.Printf("  Energy Saving: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "SlpMod":
							fmt.Printf("  Sleep Mode: %d\n", val)
						case "TemSen":
							fmt.Printf("  Current Temperature: %d°C\n", val)
						case "IfMod":
							fmt.Printf("  Interface Mode: %d\n", val)
						case "BlowCnt":
							fmt.Printf("  Blow Count: %d\n", val)
						case "dBLowCnt":
							fmt.Printf("  dB Low Count: %d\n", val)
						case "dBHighCnt":
							fmt.Printf("  dB High Count: %d\n", val)
						case "LigSen":
							fmt.Printf("  Light Sensor: %d\n", val)
						case "MacClean":
							fmt.Printf("  Machine Clean: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "AirCpFail":
							fmt.Printf("  Air Compressor Fail: %d\n", val)
						case "ErrCode":
							fmt.Printf("  Error Code: %d\n", val)
						case "FilterRst":
							fmt.Printf("  Filter Reset: %d\n", val)
						case "MediumFilter":
							fmt.Printf("  Medium Filter: %d\n", val)
						case "HumidMod":
							fmt.Printf("  Humidity Mode: %d\n", val)
						case "ElecEnable":
							fmt.Printf("  Electric Enable: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "ElecHeat":
							fmt.Printf("  Electric Heat: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						case "HumidValue":
							fmt.Printf("  Humidity Value: %d%%\n", val)
						case "LowFilter":
							fmt.Printf("  Low Filter: %d\n", val)
						case "PumpStop":
							fmt.Printf("  Pump Stop: %s\n", map[int]string{0: "Off", 1: "On"}[val])
						default:
							fmt.Printf("  %s: %d\n", col, val)
						}
					}
					fmt.Println("====================")
					fmt.Printf("Raw data: cols=%v dat=%v\n", cols, dat)
				}
			}
		} else if action == "temp" {
			fmt.Printf("Temperature set to %d°C successfully\n", targetTemp)
		} else {
			fmt.Printf("Command executed successfully\n")
		}
	}
}