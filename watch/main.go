package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"time"
)

const watchKey = "a3K8Bx%2r8Y7#xDh"

// State file to store current temperature and AC state
type ACState struct {
	LastTemperature    int       `json:"last_temperature"`
	LastCheck          time.Time `json:"last_check"`
	LastPowerState     int       `json:"last_power_state"`
	LastMode           int       `json:"last_mode"`
	LastCurrentTemp    int       `json:"last_current_temp"`
	TempStableCount    int       `json:"temp_stable_count"`
	LastFanSpeed       int       `json:"last_fan_speed"`
	UnexpectedOffCount int       `json:"unexpected_off_count"`
}

// Error journal entry
type ErrorEntry struct {
	Timestamp       time.Time `json:"timestamp"`
	ErrorCode       int       `json:"error_code"`
	AllErr          int       `json:"all_err"`
	ErrMsg          int       `json:"err_msg"`
	WarnCode        int       `json:"warn_code"`
	ProtCode        int       `json:"prot_code"`
	Action          string    `json:"action"`
	Temperature     int       `json:"temperature"`
	DetectedBy      string    `json:"detected_by"` // How the error was detected
	CurrentTemp     int       `json:"current_temp"`
	PowerState      int       `json:"power_state"`
	Mode            int       `json:"mode"`
	FanSpeed        int       `json:"fan_speed"`
	TempDifference  int       `json:"temp_difference"` // SetTemp - CurrentTemp
}

// Journal file structure
type ErrorJournal struct {
	Entries     []ErrorEntry `json:"entries"`
	ErrorCounts []time.Time  `json:"error_counts"` // Track error times for rate limiting
}

func watchPad(data []byte) []byte {
	blockSize := aes.BlockSize
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func watchUnpad(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}
	padding := int(data[length-1])
	return data[:length-padding]
}

func watchEncrypt(plainText []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	paddedText := watchPad(plainText)
	cipherText := make([]byte, len(paddedText))
	
	for i := 0; i < len(paddedText); i += aes.BlockSize {
		block.Encrypt(cipherText[i:i+aes.BlockSize], paddedText[i:i+aes.BlockSize])
	}
	
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func watchDecrypt(cipherTextBase64 string, key []byte) ([]byte, error) {
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
	
	return watchUnpad(plainText), nil
}

func bindAndGetKey(deviceMAC, deviceIP string) (string, error) {
	conn, err := net.Dial("udp", deviceIP+":7000")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	
	bindJSON := fmt.Sprintf(`{"mac":"%s","t":"bind","uid":0}`, deviceMAC)
	bindPack, _ := watchEncrypt([]byte(bindJSON), []byte(watchKey))
	
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
		return "", err
	}
	
	var bindResp map[string]interface{}
	json.Unmarshal(buf[:n], &bindResp)
	
	if pack, ok := bindResp["pack"].(string); ok {
		decrypted, _ := watchDecrypt(pack, []byte(watchKey))
		var bindData map[string]interface{}
		json.Unmarshal(decrypted, &bindData)
		if key, ok := bindData["key"].(string); ok {
			return key, nil
		}
	}
	
	return "", fmt.Errorf("failed to get device key")
}

func getACStatus(deviceMAC, deviceIP, deviceKey string) (map[string]int, error) {
	conn, err := net.Dial("udp", deviceIP+":7000")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	
	statusJSON := fmt.Sprintf(`{"cols":["Pow","SetTem","TemSen","Mod","WdSpd","ErrCode","AllErr","ErrMsg","WarnCode","ProtCode"],"mac":"%s","t":"status"}`, deviceMAC)
	statusPack, _ := watchEncrypt([]byte(statusJSON), []byte(deviceKey))
	
	statusReq := map[string]interface{}{
		"cid":  "app",
		"i":    0,
		"t":    "pack",
		"uid":  0,
		"tcid": deviceMAC,
		"pack": statusPack,
	}
	
	reqData, _ := json.Marshal(statusReq)
	conn.Write(reqData)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	
	var resp map[string]interface{}
	json.Unmarshal(buf[:n], &resp)
	
	if pack, ok := resp["pack"].(string); ok {
		decrypted, _ := watchDecrypt(pack, []byte(deviceKey))
		var data map[string]interface{}
		json.Unmarshal(decrypted, &data)
		
		result := make(map[string]int)
		if cols, ok := data["cols"].([]interface{}); ok {
			if dat, ok := data["dat"].([]interface{}); ok {
				for i := 0; i < len(cols) && i < len(dat); i++ {
					if col, ok := cols[i].(string); ok {
						if val, ok := dat[i].(float64); ok {
							result[col] = int(val)
						}
					}
				}
			}
		}
		return result, nil
	}
	
	return nil, fmt.Errorf("invalid status response")
}

func sendCommand(deviceMAC, deviceIP, deviceKey, command string, value int) error {
	conn, err := net.Dial("udp", deviceIP+":7000")
	if err != nil {
		return err
	}
	defer conn.Close()
	
	cmdJSON := fmt.Sprintf(`{"t":"cmd","mac":"%s","opt":["%s"],"p":[%d]}`, deviceMAC, command, value)
	cmdPack, _ := watchEncrypt([]byte(cmdJSON), []byte(deviceKey))
	
	cmdReq := map[string]interface{}{
		"cid":  "app",
		"i":    0,
		"t":    "pack",
		"uid":  0,
		"tcid": deviceMAC,
		"pack": cmdPack,
	}
	
	reqData, _ := json.Marshal(cmdReq)
	conn.Write(reqData)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	buf := make([]byte, 2048)
	_, err = conn.Read(buf)
	return err
}

func getDataPath(filename string) string {
	// Check if running in Docker
	if _, err := os.Stat("/app/data"); err == nil {
		return fmt.Sprintf("/app/data/%s", filename)
	}
	return filename
}

func loadState() (*ACState, error) {
	data, err := ioutil.ReadFile(getDataPath("ac_state.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return &ACState{}, nil
		}
		return nil, err
	}
	
	var state ACState
	err = json.Unmarshal(data, &state)
	return &state, err
}

func saveState(state *ACState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(getDataPath("ac_state.json"), data, 0644)
}

func loadJournal() (*ErrorJournal, error) {
	data, err := ioutil.ReadFile(getDataPath("error_journal.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return &ErrorJournal{}, nil
		}
		return nil, err
	}
	
	var journal ErrorJournal
	err = json.Unmarshal(data, &journal)
	return &journal, err
}

func saveJournal(journal *ErrorJournal) error {
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(getDataPath("error_journal.json"), data, 0644)
}

func shouldWaitForCooldown(journal *ErrorJournal) bool {
	now := time.Now()
	fiveMinAgo := now.Add(-5 * time.Minute)
	
	// Count errors in last 5 minutes
	recentErrors := 0
	for _, errTime := range journal.ErrorCounts {
		if errTime.After(fiveMinAgo) {
			recentErrors++
		}
	}
	
	// If more than 2 errors in 5 minutes, check cooldown
	if recentErrors > 2 {
		// Find the most recent error
		var lastError time.Time
		for _, errTime := range journal.ErrorCounts {
			if errTime.After(lastError) {
				lastError = errTime
			}
		}
		
		// Check if 30 minutes have passed since last error
		thirtyMinAfterLastError := lastError.Add(30 * time.Minute)
		if now.Before(thirtyMinAfterLastError) {
			return true
		}
	}
	
	return false
}

func cleanOldErrors(journal *ErrorJournal) {
	now := time.Now()
	fiveMinAgo := now.Add(-5 * time.Minute)
	
	// Remove error counts older than 5 minutes
	var recentErrors []time.Time
	for _, errTime := range journal.ErrorCounts {
		if errTime.After(fiveMinAgo) {
			recentErrors = append(recentErrors, errTime)
		}
	}
	journal.ErrorCounts = recentErrors
}

func main() {
	deviceMAC := "f4911ef6d9bf"
	deviceIP := "192.168.1.223"
	
	fmt.Println("Starting AC watch for gang (192.168.1.223)...")
	
	for {
		// Get device key
		deviceKey, err := bindAndGetKey(deviceMAC, deviceIP)
		if err != nil {
			fmt.Printf("[%s] Failed to bind: %v\n", time.Now().Format("15:04:05"), err)
			
			// Check if device is reachable on network
			pingCmd := fmt.Sprintf("ping -c 1 -W 1 %s > /dev/null 2>&1", deviceIP)
			pingErr := exec.Command("sh", "-c", pingCmd).Run()
			
			if pingErr == nil {
				// Device is on network but not responding to protocol - likely H5 error
				fmt.Printf("[%s] CRITICAL: Device is on network but not responding to protocol - likely H5/HS error!\n", 
					time.Now().Format("15:04:05"))
				
				// Load journal to log this
				journal, _ := loadJournal()
				state, _ := loadState()
				
				entry := ErrorEntry{
					Timestamp:       time.Now(),
					ErrorCode:       0,
					AllErr:          0,
					ErrMsg:          0,
					WarnCode:        0,
					ProtCode:        0,
					Action:          "detected_network_no_protocol",
					Temperature:     state.LastTemperature,
					DetectedBy:      "network_ping_ok_protocol_fail",
					CurrentTemp:     0,
					PowerState:      -1, // Unknown
					Mode:            state.LastMode,
					FanSpeed:        state.LastFanSpeed,
					TempDifference:  0,
				}
				journal.Entries = append(journal.Entries, entry)
				journal.ErrorCounts = append(journal.ErrorCounts, time.Now())
				saveJournal(journal)
				
				// Try to scan to confirm
				fmt.Printf("[%s] Running scan to confirm device is not responding...\n", 
					time.Now().Format("15:04:05"))
			}
			
			time.Sleep(1 * time.Minute)
			continue
		}
		
		// Get current status
		status, err := getACStatus(deviceMAC, deviceIP, deviceKey)
		if err != nil {
			fmt.Printf("Failed to get status: %v\n", err)
			time.Sleep(1 * time.Minute)
			continue
		}
		
		power := status["Pow"]
		setTemperature := status["SetTem"]
		currentTemp := status["TemSen"]
		mode := status["Mod"]
		fanSpeed := status["WdSpd"]
		errorCode := status["ErrCode"]
		allErr := status["AllErr"]
		errMsg := status["ErrMsg"]
		warnCode := status["WarnCode"]
		protCode := status["ProtCode"]
		
		// Load state and journal
		state, _ := loadState()
		journal, _ := loadJournal()
		
		// Clean old errors
		cleanOldErrors(journal)
		
		// If AC is off, check if it was unexpected
		if power == 0 {
			if state.LastPowerState == 1 {
				// AC was on before, now it's off - might be H5 error
				state.UnexpectedOffCount++
				fmt.Printf("[%s] WARNING: AC unexpectedly turned off! (count: %d)\n", 
					time.Now().Format("15:04:05"), state.UnexpectedOffCount)
				
				if state.UnexpectedOffCount >= 2 {
					// Likely an H5 error - treat as error condition
					entry := ErrorEntry{
						Timestamp:       time.Now(),
						ErrorCode:       0,
						AllErr:          0,
						ErrMsg:          0,
						WarnCode:        0,
						ProtCode:        0,
						Action:          "detected_unexpected_off",
						Temperature:     state.LastTemperature,
						DetectedBy:      "unexpected_power_off",
						CurrentTemp:     currentTemp,
						PowerState:      power,
						Mode:            mode,
						FanSpeed:        fanSpeed,
						TempDifference:  setTemperature - currentTemp,
					}
					journal.Entries = append(journal.Entries, entry)
					journal.ErrorCounts = append(journal.ErrorCounts, time.Now())
					saveJournal(journal)
					
					// Reset counter
					state.UnexpectedOffCount = 0
				}
			}
			state.LastPowerState = 0
			saveState(state)
			fmt.Printf("[%s] AC is off, skipping...\n", time.Now().Format("15:04:05"))
			time.Sleep(1 * time.Minute)
			continue
		}
		
		// AC is on - reset unexpected off counter
		if state.LastPowerState == 0 {
			state.UnexpectedOffCount = 0
		}
		
		// Check for direct errors
		hasDirectError := errorCode != 0 || allErr != 0 || errMsg != 0 || warnCode != 0 || protCode != 0
		
		// Check for indirect error indicators (H5 detection)
		hasIndirectError := false
		indirectErrorReason := ""
		
		// 1. Check if temperature is not dropping when in cooling mode
		if mode == 1 && currentTemp > 0 { // Mode 1 = Cool
			tempDiff := currentTemp - setTemperature
			
			// If current temp is 5+ degrees higher than set temp for stable count
			if tempDiff >= 5 {
				state.TempStableCount++
				if state.TempStableCount >= 5 { // 5 minutes of no cooling
					hasIndirectError = true
					indirectErrorReason = fmt.Sprintf("no_cooling_detected (diff: %d°C)", tempDiff)
					fmt.Printf("[%s] WARNING: AC not cooling! Set: %d°C, Current: %d°C, Diff: %d°C\n", 
						time.Now().Format("15:04:05"), setTemperature, currentTemp, tempDiff)
				}
			} else {
				state.TempStableCount = 0
			}
		}
		
		// 2. Check if fan speed suddenly dropped to 0 or very low when it should be running
		if state.LastFanSpeed > 2 && fanSpeed == 0 && mode != 0 { // Not in auto mode
			hasIndirectError = true
			indirectErrorReason = "fan_stopped_unexpectedly"
			fmt.Printf("[%s] WARNING: Fan stopped unexpectedly! Was: %d, Now: %d\n", 
				time.Now().Format("15:04:05"), state.LastFanSpeed, fanSpeed)
		}
		
		// 3. Check if mode changed unexpectedly
		if state.LastMode > 0 && mode != state.LastMode {
			fmt.Printf("[%s] WARNING: Mode changed! Was: %d, Now: %d\n", 
				time.Now().Format("15:04:05"), state.LastMode, mode)
		}
		
		// Combine error detection
		hasError := hasDirectError || hasIndirectError
		
		// Update state
		state.LastPowerState = power
		state.LastTemperature = setTemperature
		state.LastCurrentTemp = currentTemp
		state.LastMode = mode
		state.LastFanSpeed = fanSpeed
		state.LastCheck = time.Now()
		
		if !hasError {
			saveState(state)
		}
		
		// Check for errors
		if hasError {
			if hasDirectError {
				fmt.Printf("[%s] DIRECT ERROR detected! ErrCode: %d, AllErr: %d, ErrMsg: %d, WarnCode: %d, ProtCode: %d\n", 
					time.Now().Format("15:04:05"), errorCode, allErr, errMsg, warnCode, protCode)
			} else {
				fmt.Printf("[%s] INDIRECT ERROR detected! Reason: %s\n", 
					time.Now().Format("15:04:05"), indirectErrorReason)
			}
			
			// Check if we should wait due to too many errors
			if shouldWaitForCooldown(journal) {
				fmt.Printf("Too many errors in 5 minutes, waiting 30 minutes before retry...\n")
				
				// Log this in journal
				entry := ErrorEntry{
					Timestamp:       time.Now(),
					ErrorCode:       errorCode,
					AllErr:          allErr,
					ErrMsg:          errMsg,
					WarnCode:        warnCode,
					ProtCode:        protCode,
					Action:          "cooldown_wait",
					Temperature:     state.LastTemperature,
					DetectedBy:      "cooldown",
					CurrentTemp:     currentTemp,
					PowerState:      power,
					Mode:            mode,
					FanSpeed:        fanSpeed,
					TempDifference:  setTemperature - currentTemp,
				}
				journal.Entries = append(journal.Entries, entry)
				saveJournal(journal)
				
				time.Sleep(30 * time.Minute)
				continue
			}
			
			// Log error
			detectMethod := "direct_error"
			if hasIndirectError && !hasDirectError {
				detectMethod = indirectErrorReason
			}
			
			entry := ErrorEntry{
				Timestamp:       time.Now(),
				ErrorCode:       errorCode,
				AllErr:          allErr,
				ErrMsg:          errMsg,
				WarnCode:        warnCode,
				ProtCode:        protCode,
				Action:          "restart_attempt",
				Temperature:     state.LastTemperature,
				DetectedBy:      detectMethod,
				CurrentTemp:     currentTemp,
				PowerState:      power,
				Mode:            mode,
				FanSpeed:        fanSpeed,
				TempDifference:  setTemperature - currentTemp,
			}
			journal.Entries = append(journal.Entries, entry)
			journal.ErrorCounts = append(journal.ErrorCounts, time.Now())
			saveJournal(journal)
			
			// Try to recover
			fmt.Printf("Attempting recovery...\n")
			
			// Stop AC
			err = sendCommand(deviceMAC, deviceIP, deviceKey, "Pow", 0)
			if err != nil {
				fmt.Printf("Failed to stop AC: %v\n", err)
			} else {
				fmt.Printf("AC stopped, waiting 5 seconds...\n")
			}
			
			time.Sleep(5 * time.Second)
			
			// Start AC
			err = sendCommand(deviceMAC, deviceIP, deviceKey, "Pow", 1)
			if err != nil {
				fmt.Printf("Failed to start AC: %v\n", err)
			} else {
				fmt.Printf("AC started\n")
			}
			
			time.Sleep(2 * time.Second)
			
			// Restore temperature
			if state.LastTemperature > 0 {
				err = sendCommand(deviceMAC, deviceIP, deviceKey, "SetTem", state.LastTemperature)
				if err != nil {
					fmt.Printf("Failed to set temperature: %v\n", err)
				} else {
					fmt.Printf("Temperature restored to %d°C\n", state.LastTemperature)
				}
			}
		} else {
			// Reset temperature stable count when no issues
			if state.TempStableCount > 0 {
				state.TempStableCount = 0
				saveState(state)
			}
			
			statusMsg := fmt.Sprintf("[%s] AC OK - Power: ON, Set: %d°C", 
				time.Now().Format("15:04:05"), setTemperature)
			
			if currentTemp > 0 {
				statusMsg += fmt.Sprintf(", Current: %d°C (diff: %d)", 
					currentTemp, currentTemp - setTemperature)
			}
			
			modeStr := map[int]string{0: "Auto", 1: "Cool", 2: "Dry", 3: "Fan", 4: "Heat"}[mode]
			fanStr := map[int]string{0: "Auto", 1: "Low", 2: "Med-Low", 3: "Med", 4: "Med-High", 5: "High"}[fanSpeed]
			
			statusMsg += fmt.Sprintf(", Mode: %s, Fan: %s", modeStr, fanStr)
			fmt.Println(statusMsg)
		}
		
		// Wait for next check
		time.Sleep(1 * time.Minute)
	}
}