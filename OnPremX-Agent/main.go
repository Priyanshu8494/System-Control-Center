package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"net"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/sys/windows/svc"
)

// Agent configuration defaults
var (
	AgentVersion  = "0.0.18"
	ServiceName   = "OnPremXAgent"
	BaseServerURL = "http://192.168.1.4:8080"
	CheckInterval = 10 * time.Second
)

// Dynamic URLs (updated from config)
var (
	ServerURL     string
	ResultURL     string
	ScreenshotURL string
)

func init() {
	// Try to load config.json
	exePath, _ := os.Executable()
	configPath := strings.Replace(exePath, ".exe", ".config.json", 1)

	if data, err := os.ReadFile(configPath); err == nil {
		var config struct {
			ServerURL string `json:"server_url"`
		}
		if err := json.Unmarshal(data, &config); err == nil && config.ServerURL != "" {
			BaseServerURL = config.ServerURL
		}
	}

	// Update URLs
	ServerURL = BaseServerURL + "/api/heartbeat"
	ResultURL = BaseServerURL + "/api/command/result"
	ScreenshotURL = BaseServerURL + "/api/agent/screenshot"
}

type myService struct{}

func (m *myService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// Start Agent Logic in a Goroutine
	go runAgent()

	// Handle Service Control Signals
loop:
	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func runAgent() {
	// Setup Logging to file
	exePath, _ := os.Executable()
	logPath := strings.Replace(exePath, ".exe", ".log", 1)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(logFile)
	}

	log.Printf("Starting OnPremX Agent v%s (Service Mode)...\n", AgentVersion)

	// Initial Inventory Collection (Run once at startup)
	log.Println("Performing initial inventory collection...")
	updateInventory()
	lastInventory = time.Now()

	for {
		stateMutex.RLock()
		localStream := streamScreen
		localAdmin := adminActive
		stateMutex.RUnlock()

		// If streaming is active, we need to capture screen
		if localStream {
			go captureAndSendScreen()
		}

		// Always collect basic system info (CPU, RAM, Disk, etc.)
		sysInfo := getSystemInfo()

		// Always include cached inventory data if available (Protected by mutex)
		inventoryMutex.RLock()
		sysInfo.Software = cachedSoftware
		sysInfo.Services = cachedServices
		sysInfo.Patches = cachedPatches
		inventoryMutex.RUnlock()

		// If server says "AdminActive" or 5 minutes passed, refresh inventory/logs
		if localAdmin || time.Since(lastInventory) > 5*time.Minute {
			if time.Since(lastInventory) > 5*time.Minute {
				log.Println("Refreshing inventory in background...")
				go updateInventory()
				lastInventory = time.Now()
			}
			// Get fresh logs if admin is active
			if localAdmin {
				sysInfo.EventLogs = getEventLogs()
			}
		}

		// Always send security info (USB/RDP status)
		sysInfo.Security = getSecurityInfo()

		go sendHeartbeat(sysInfo)

		// Dynamic Sleep
		interval := CheckInterval
		if localStream {
			interval = 500 * time.Millisecond // Fast poll for streaming
		} else if localAdmin {
			interval = 2 * time.Second // Faster poll when admin is watching
		} else {
			interval = 10 * time.Second // Normal poll
		}

		time.Sleep(interval)
	}
}

// Software structure
type Software struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Vendor          string `json:"vendor"`
	UninstallString string `json:"uninstall_string"`
}

// Service structure
type Service struct {
	Name   string `json:"name"`
	Status string `json:"status"` // Running, Stopped
}

// Patch structure (HotFixes)
type Patch struct {
	HotFixID    string    `json:"hotfix_id"`
	Description string    `json:"description"`
	InstalledBy string    `json:"installed_by"`
	InstalledOn time.Time `json:"installed_on"`
}

// EventLog structure (System Errors)
type EventLog struct {
	TimeGenerated time.Time `json:"time_generated"`
	EntryType     string    `json:"entry_type"` // Error, Warning
	Source        string    `json:"source"`
	Message       string    `json:"message"`
	EventID       int64     `json:"event_id"`
}

// Command structure (received from server)
type Command struct {
	ID      string `json:"id"`
	Type    string `json:"type"`    // "exec" or "cancel"
	Command string `json:"command"` // PowerShell script or ID to cancel
}

// SystemInfo struct to hold detailed system stats
type SystemInfo struct {
	Hostname        string  `json:"hostname"`
	OS              string  `json:"os"`
	Arch            string  `json:"arch"`
	Platform        string  `json:"platform"`
	PlatformVersion string  `json:"platform_version"`
	Uptime          uint64  `json:"uptime"`
	CPUModel        string  `json:"cpu_model"`
	CPUUsage        float64 `json:"cpu_usage"`
	TotalRAM        uint64  `json:"total_ram"`
	UsedRAM         uint64  `json:"used_ram"`
	RAMUsage        float64 `json:"ram_usage"`
	TotalDisk       uint64  `json:"total_disk"`
	UsedDisk        uint64  `json:"used_disk"`
	DiskUsage       float64 `json:"disk_usage"`
	AgentVersion    string  `json:"agent_version"`

	// New Fields
	IPAddress  string       `json:"ip_address"`
	MACAddress string       `json:"mac_address"`
	Software   []Software   `json:"software"`
	Services   []Service    `json:"services"`
	Patches    []Patch      `json:"patches"`
	EventLogs  []EventLog   `json:"event_logs"`
	Security   SecurityInfo `json:"security"`
	Browsers   []string     `json:"browsers"`
}

type SecurityInfo struct {
	USBBlocked  bool     `json:"usb_blocked"`
	RDPBlocked  bool     `json:"rdp_blocked"`
	USBDevices  []string `json:"usb_devices"`
	RDPSessions []string `json:"rdp_sessions"`
}

// Global cache for heavy operations
var (
	cachedSoftware []Software
	cachedServices []Service
	cachedPatches  []Patch
	lastInventory  time.Time
	inventoryMutex sync.RWMutex // Mutex for inventory data

	runningCmds = make(map[string]*exec.Cmd) // Command ID -> Running Process
	cmdMutex    sync.Mutex

	adminActive  = false // Track if admin is watching
	streamScreen = false // Track if we should stream screenshots
	stateMutex   sync.RWMutex
	capturing    int32 // Atomic flag for capture status
)

func getSystemInfo() SystemInfo {

	hostname, _ := os.Hostname()
	hostInfo, _ := host.Info()

	// CPU Info
	cpuStat, _ := cpu.Info()
	cpuPercent, _ := cpu.Percent(0, false)
	cpuModel := "Unknown"
	if len(cpuStat) > 0 {
		cpuModel = cpuStat[0].ModelName
	}
	currentCPU := 0.0
	if len(cpuPercent) > 0 {
		currentCPU = cpuPercent[0]
	}

	// Memory Info
	vmStat, _ := mem.VirtualMemory()

	// Disk Info (C: drive for Windows)
	diskStat, _ := disk.Usage("C:")

	// Network Info (Get IPv4)
	ip := "127.0.0.1"
	mac := "00:00:00:00:00:00"
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip = ipnet.IP.String()
					break
				}
			}
		}
	}

	// Get MAC for primary interface
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
				if len(iface.HardwareAddr) > 0 {
					mac = iface.HardwareAddr.String()
					break
				}
			}
		}
	}

	// RDP Status
	security := getSecurityInfo()

	// Update Inventory every 5 minutes
	if time.Since(lastInventory) > 5*time.Minute {
		go updateInventory() // Run in background to not block heartbeat
		lastInventory = time.Now()
	}

	return SystemInfo{
		Hostname:        hostname,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Platform:        hostInfo.Platform,
		PlatformVersion: hostInfo.PlatformVersion,
		Uptime:          hostInfo.Uptime,
		CPUModel:        cpuModel,
		CPUUsage:        currentCPU,
		TotalRAM:        vmStat.Total,
		UsedRAM:         vmStat.Used,
		RAMUsage:        vmStat.UsedPercent,
		TotalDisk:       diskStat.Total,
		UsedDisk:        diskStat.Used,
		DiskUsage:       diskStat.UsedPercent,
		AgentVersion:    AgentVersion,
		IPAddress:       ip,
		MACAddress:      mac,
		Software:        cachedSoftware,
		Services:        cachedServices,
		Security:        security,
		Browsers:        getBrowsers(),
	}
}

func getBrowsers() []string {
	var browsers []string
	psScript := `Get-ItemProperty HKLM:\SOFTWARE\Clients\StartMenuInternet\* | Select-Object -ExpandProperty PSChildName`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.Contains(strings.ToLower(trimmed), "iexplore") {
				browsers = append(browsers, trimmed)
			}
		}
	}
	// Always check for Edge as it might not be in that key sometimes
	edgePath := `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
	if _, err := os.Stat(edgePath); err == nil {
		found := false
		for _, b := range browsers {
			if strings.Contains(strings.ToLower(b), "edge") {
				found = true
				break
			}
		}
		if !found {
			browsers = append(browsers, "Microsoft Edge")
		}
	}
	return browsers
}

func getSecurityInfo() SecurityInfo {
	var info SecurityInfo

	// Check USB Block Status (HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR -> Start)
	// 3 = Enabled, 4 = Disabled
	cmdUSB := exec.Command("powershell", "-NoProfile", "-Command", `(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -ErrorAction SilentlyContinue).Start`)
	cmdUSB.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outUSB, _ := cmdUSB.Output()
	if bytes.Contains(outUSB, []byte("4")) {
		info.USBBlocked = true
	}

	// Check RDP Block Status (HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server -> fDenyTSConnections)
	// 0 = Enabled, 1 = Disabled
	cmdRDP := exec.Command("powershell", "-NoProfile", "-Command", `(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections`)
	cmdRDP.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outRDP, _ := cmdRDP.Output()
	if bytes.Contains(outRDP, []byte("1")) {
		info.RDPBlocked = true
	}

	// Get Connected USB Devices (Disks and Flash Drives)
	cmdDevices := exec.Command("powershell", "-NoProfile", "-Command", `Get-PnpDevice -PresentOnly | Where-Object { $_.Class -eq 'DiskDrive' -and $_.InstanceId -match 'USBSTOR' } | Select-Object -ExpandProperty FriendlyName`)
	cmdDevices.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outDevices, _ := cmdDevices.Output()
	lines := strings.Split(string(outDevices), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			info.USBDevices = append(info.USBDevices, trimmed)
		}
	}

	// Get RDP Sessions (quser)
	// Output Format: USERNAME SESSIONNAME ID STATE IDLE TIME LOGON TIME
	cmdSessions := exec.Command("quser")
	cmdSessions.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outSessions, err := cmdSessions.Output()
	if err == nil {
		lines := strings.Split(string(outSessions), "\n")
		for i, line := range lines {
			if i == 0 {
				continue
			} // Skip header
			parts := strings.Fields(line)
			if len(parts) > 0 {
				info.RDPSessions = append(info.RDPSessions, parts[0]) // Username
			}
		}
	}

	return info
}

func updateInventory() {
	// 1. Get Installed Software
	psScript := `
	$paths = @(
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
		"HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
	);
	$sw = Get-ItemProperty $paths -ErrorAction SilentlyContinue | 
	Select-Object DisplayName, DisplayVersion, Publisher, UninstallString | 
	Where-Object { $_.DisplayName -ne $null } | 
	Sort-Object DisplayName -Unique
	if ($sw) { $sw | ConvertTo-Json -Depth 2 } else { "[]" }`

	cmd1 := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	cmd1.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd1.CombinedOutput()
	if err == nil && len(out) > 0 {
		var softList []Software
		var raw []struct {
			DisplayName     string      `json:"DisplayName"`
			DisplayVersion  interface{} `json:"DisplayVersion"`
			Publisher       string      `json:"Publisher"`
			UninstallString string      `json:"UninstallString"`
		}
		if err := json.Unmarshal(out, &raw); err == nil {
			for _, item := range raw {
				version := ""
				if item.DisplayVersion != nil {
					version = fmt.Sprintf("%v", item.DisplayVersion)
				}
				softList = append(softList, Software{
					Name:            item.DisplayName,
					Version:         version,
					Vendor:          item.Publisher,
					UninstallString: item.UninstallString,
				})
			}
		} else {
			var singleItem struct {
				DisplayName     string      `json:"DisplayName"`
				DisplayVersion  interface{} `json:"DisplayVersion"`
				Publisher       string      `json:"Publisher"`
				UninstallString string      `json:"UninstallString"`
			}
			if err := json.Unmarshal(out, &singleItem); err == nil {
				version := ""
				if singleItem.DisplayVersion != nil {
					version = fmt.Sprintf("%v", singleItem.DisplayVersion)
				}
				softList = append(softList, Software{
					Name:            singleItem.DisplayName,
					Version:         version,
					Vendor:          singleItem.Publisher,
					UninstallString: singleItem.UninstallString,
				})
			}
		}
		if len(softList) > 0 {
			inventoryMutex.Lock()
			cachedSoftware = softList
			inventoryMutex.Unlock()
			log.Printf("✅ Collected %d software items\n", len(softList))
		}
	} else if err != nil {
		log.Printf("❌ Software collection error: %v (Out: %s)\n", err, string(out))
	}

	// 2. Get Services
	psScriptServices := `Get-Service | Select-Object Name, Status | ConvertTo-Json`
	cmd2 := exec.Command("powershell", "-NoProfile", "-Command", psScriptServices)
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outSvc, errSvc := cmd2.CombinedOutput()
	if errSvc == nil && len(outSvc) > 0 {
		var svcList []Service
		var rawSvc []struct {
			Name   string `json:"Name"`
			Status int    `json:"Status"`
		}
		if err := json.Unmarshal(outSvc, &rawSvc); err == nil {
			for _, item := range rawSvc {
				status := "Stopped"
				if item.Status == 4 {
					status = "Running"
				}
				svcList = append(svcList, Service{Name: item.Name, Status: status})
			}
		} else {
			var single struct {
				Name   string `json:"Name"`
				Status int    `json:"Status"`
			}
			if err := json.Unmarshal(outSvc, &single); err == nil {
				status := "Stopped"
				if single.Status == 4 {
					status = "Running"
				}
				svcList = append(svcList, Service{Name: single.Name, Status: status})
			}
		}
		if len(svcList) > 0 {
			inventoryMutex.Lock()
			cachedServices = svcList
			inventoryMutex.Unlock()
			log.Printf("✅ Collected %d services\n", len(svcList))
		}
	}

	// 3. Get HotFixes (Patches)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-HotFix | Select-Object HotFixID,Description,InstalledBy,InstalledOn | ConvertTo-Json")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err = cmd.CombinedOutput()
	if err == nil && len(out) > 0 {
		var patchList []Patch
		var items []struct {
			HotFixID    string      `json:"HotFixID"`
			Description string      `json:"Description"`
			InstalledBy string      `json:"InstalledBy"`
			InstalledOn interface{} `json:"InstalledOn"`
		}
		if err := json.Unmarshal(out, &items); err == nil {
			for _, item := range items {
				patchList = append(patchList, Patch{
					HotFixID:    item.HotFixID,
					Description: item.Description,
					InstalledBy: item.InstalledBy,
					InstalledOn: time.Now(),
				})
			}
		} else {
			var single struct {
				HotFixID    string      `json:"HotFixID"`
				Description string      `json:"Description"`
				InstalledBy string      `json:"InstalledBy"`
				InstalledOn interface{} `json:"InstalledOn"`
			}
			if err := json.Unmarshal(out, &single); err == nil {
				patchList = append(patchList, Patch{
					HotFixID:    single.HotFixID,
					Description: single.Description,
					InstalledBy: single.InstalledBy,
					InstalledOn: time.Now(),
				})
			}
		}
		if len(patchList) > 0 {
			inventoryMutex.Lock()
			cachedPatches = patchList
			inventoryMutex.Unlock()
			log.Printf("✅ Collected %d patches\n", len(patchList))
		}
	}
}

func getEventLogs() []EventLog {
	psScript := `Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 5 | Select-Object TimeCreated, ProviderName, Message, Id | ConvertTo-Json`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return []EventLog{}
	}

	var items []struct {
		TimeCreated  string `json:"TimeCreated"`
		ProviderName string `json:"ProviderName"`
		Message      string `json:"Message"`
		Id           int64  `json:"Id"`
	}

	var logs []EventLog

	if err := json.Unmarshal(out, &items); err != nil {
		var singleItem struct {
			TimeCreated  string `json:"TimeCreated"`
			ProviderName string `json:"ProviderName"`
			Message      string `json:"Message"`
			Id           int64  `json:"Id"`
		}
		if err := json.Unmarshal(out, &singleItem); err == nil {
			items = append(items, singleItem)
		}
	}

	for _, item := range items {
		logs = append(logs, EventLog{
			TimeGenerated: time.Now(), // Simplified
			EntryType:     "Error",
			Source:        item.ProviderName,
			Message:       item.Message,
			EventID:       item.Id,
		})
	}
	return logs
}

func sendHeartbeat(info SystemInfo) {
	jsonData, err := json.Marshal(info)
	if err != nil {
		return
	}

	resp, err := http.Post(ServerURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("⚠️ Server unreachable: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var response struct {
		Status       string   `json:"status"`
		Command      *Command `json:"command"`
		AdminActive  bool     `json:"admin_active"`
		StreamScreen bool     `json:"stream_screen"` // New Field
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err == nil {
		stateMutex.Lock()
		adminActive = response.AdminActive
		streamScreen = response.StreamScreen
		stateMutex.Unlock()

		if response.Command != nil {
			go executeCommand(*response.Command)
		}
	}
}

func executeCommand(cmd Command) {
	if cmd.Type == "update_agent" {
		log.Printf("🚀 Received update command. Downloading from: %s\n", cmd.Command)
		go handleSelfUpdate(cmd)
		return
	}

	if cmd.Type == "cancel" {
		cmdMutex.Lock()
		targetID := cmd.Command
		if proc, ok := runningCmds[targetID]; ok {
			if proc.Process != nil {
				proc.Process.Kill()
			}
			delete(runningCmds, targetID)
		}
		cmdMutex.Unlock()
		return
	}

	c := exec.Command("powershell", "-NoProfile", "-Command", cmd.Command)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmdMutex.Lock()
	runningCmds[cmd.ID] = c
	cmdMutex.Unlock()

	out, err := c.CombinedOutput()

	cmdMutex.Lock()
	delete(runningCmds, cmd.ID)
	cmdMutex.Unlock()

	outputStr := string(out)
	errorStr := ""
	if err != nil {
		errorStr = err.Error()
	}

	result := map[string]string{
		"hostname":   cachedHostname(),
		"command_id": cmd.ID,
		"output":     outputStr,
		"error":      errorStr,
	}
	jsonResult, _ := json.Marshal(result)
	http.Post(ResultURL, "application/json", bytes.NewBuffer(jsonResult))
}

func handleSelfUpdate(cmd Command) {
	downloadURL := cmd.Command
	if downloadURL == "" {
		downloadURL = BaseServerURL + "/dl/OnPremX-Agent.exe"
	}

	exePath, _ := os.Executable()
	newExePath := exePath + ".new"

	// 1. Download new binary
	resp, err := http.Get(downloadURL)
	if err != nil {
		log.Printf("❌ Update failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	out, err := os.Create(newExePath)
	if err != nil {
		log.Printf("❌ Failed to create temporary file: %v\n", err)
		return
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Printf("❌ Failed to save new binary: %v\n", err)
		return
	}
	out.Close()

	// 2. Create batch script for replacement
	// This script will: wait, stop service, kill process, replace, start service, cleanup
	batchScript := fmt.Sprintf(`@echo off
set LOGFILE=%%~dp0update_debug.log
echo [%%DATE%% %%TIME%%] Update started > "%%LOGFILE%%"
timeout /t 5 /nobreak > nul

echo [%%DATE%% %%TIME%%] Stopping service %s >> "%%LOGFILE%%"
sc stop %s >> "%%LOGFILE%%" 2>&1
timeout /t 2 /nobreak > nul

echo [%%DATE%% %%TIME%%] Killing process if still active >> "%%LOGFILE%%"
taskkill /F /IM OnPremX-Agent.exe /T >> "%%LOGFILE%%" 2>&1
timeout /t 2 /nobreak > nul

echo [%%DATE%% %%TIME%%] Copying "%s" to "%s" >> "%%LOGFILE%%"
copy /y "%s" "%s" >> "%%LOGFILE%%" 2>&1
if errorlevel 1 (
    echo [%%DATE%% %%TIME%%] COPY FAILED! >> "%%LOGFILE%%"
) else (
    echo [%%DATE%% %%TIME%%] COPY SUCCESSFUL >> "%%LOGFILE%%"
)

echo [%%DATE%% %%TIME%%] Starting service %s >> "%%LOGFILE%%"
sc start %s >> "%%LOGFILE%%" 2>&1

echo [%%DATE%% %%TIME%%] Cleaning up temporary files >> "%%LOGFILE%%"
del "%s" >> "%%LOGFILE%%" 2>&1
echo [%%DATE%% %%TIME%%] Update finished >> "%%LOGFILE%%"
del "%%~f0"
`, ServiceName, ServiceName, newExePath, exePath, newExePath, exePath, ServiceName, ServiceName, newExePath)

	batchPath := filepath.Join(filepath.Dir(exePath), "update.bat")
	err = os.WriteFile(batchPath, []byte(batchScript), 0644)
	if err != nil {
		log.Printf("❌ Failed to create update script: %v\n", err)
		return
	}

	log.Printf("✅ Update ready. Executing update script and exiting...\n")

	// 3. Execute batch script and exit
	updateCmd := exec.Command("cmd.exe", "/c", "start", "/b", "cmd.exe", "/c", batchPath)
	updateCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err = updateCmd.Start()
	if err != nil {
		log.Printf("❌ Failed to launch update script: %v\n", err)
		return
	}

	os.Exit(0)
}

func captureAndSendScreen() {
	if !atomic.CompareAndSwapInt32(&capturing, 0, 1) {
		return // Already capturing
	}
	defer atomic.StoreInt32(&capturing, 0)

	// PowerShell script to capture screen and convert to Base64
	// Using System.Drawing which is standard in .NET
	psScript := `
	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing
	
	$screen = [System.Windows.Forms.Screen]::PrimaryScreen
	$bitmap = New-Object System.Drawing.Bitmap $screen.Bounds.Width, $screen.Bounds.Height
	$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
	$graphics.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)
	
	$stream = New-Object System.IO.MemoryStream
	$bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Jpeg)
	$bytes = $stream.ToArray()
	$base64 = [Convert]::ToBase64String($bytes)
	
	$graphics.Dispose()
	$bitmap.Dispose()
	$stream.Dispose()
	
	Write-Output $base64
	`

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		log.Printf("Screen capture failed: %v\n", err)
		return
	}

	// Trim newlines
	base64Img := string(bytes.TrimSpace(out))

	// Send to server
	data := map[string]string{
		"hostname": cachedHostname(),
		"image":    base64Img,
	}
	jsonData, _ := json.Marshal(data)
	http.Post(ScreenshotURL, "application/json", bytes.NewBuffer(jsonData))
}

func cachedHostname() string {
	h, _ := os.Hostname()
	return h
}

func checkAdmin() bool {
	// Standard Windows check: Try to open physical drive
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

func runMeElevated() {
	exe, _ := os.Executable()
	// Use PowerShell to start process with RunAs verb (trigger UAC)
	cmd := exec.Command("powershell", "Start-Process", exe, "-Verb", "RunAs", "-WindowStyle", "Hidden")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Start()
}

func main() {
	// 1. Check if running as a Service
	isService, err := svc.IsWindowsService()
	if err == nil && isService {
		// Change working directory to exe directory
		exePath, _ := os.Executable()
		os.Chdir(filepath.Dir(exePath))

		err = svc.Run(ServiceName, &myService{})
		if err != nil {
			f, _ := os.OpenFile("c:\\OnPremXAgentServiceError.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			f.WriteString(fmt.Sprintf("[%s] Service Run Failed: %v\n", time.Now().Format(time.RFC3339), err))
			f.Close()
		}
		return
	}

	// 2. Interactive Mode (Console)
	// Setup Logging to file
	logFile, err := os.OpenFile("agent.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(logFile)
	}

	// Log panic recovery
	defer func() {
		if r := recover(); r != nil {
			log.Printf("CRITICAL: Agent panicked: %v\n", r)
		}
	}()

	cwd, _ := os.Getwd()
	log.Printf("Starting OnPremX Agent v%s in %s (Interactive Mode)\n", AgentVersion, cwd)

	// REMOVED: Self-Elevation Check (RunAs Admin) to avoid UAC Prompts
	// User must install as Service for Admin rights.

	log.Printf("Server URL: %s\n", ServerURL)

	runAgent()
}
