package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
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

// Agent configuration
const (
	AgentVersion  = "0.0.14"
	ServiceName   = "SystemAgent"
	ServerURL     = "http://192.168.1.4:8080/api/heartbeat"
	ResultURL     = "http://192.168.1.4:8080/api/command/result"
	ScreenshotURL = "http://192.168.1.4:8080/api/agent/screenshot"
	CheckInterval = 10 * time.Second
)

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
	// Use absolute path for log file when running as service
	exePath, _ := os.Executable()
	logPath := strings.Replace(exePath, ".exe", ".log", 1)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(logFile)
	}

	log.Printf("Starting System Agent v%s (Service Mode)...\n", AgentVersion)

	// Check if running as Admin
	isAdmin := "No"
	if _, err := os.Open("\\\\.\\PHYSICALDRIVE0"); err == nil {
		isAdmin = "Yes"
	}
	log.Printf("Running as Admin/SYSTEM: %s\n", isAdmin)

	for {
		var sysInfo SystemInfo

		stateMutex.RLock()
		localStream := streamScreen
		localAdmin := adminActive
		stateMutex.RUnlock()

		// If streaming is active, we need to capture screen
		if localStream {
			go captureAndSendScreen()
		}

		// Always run inventory logic (Service has admin rights by default)
		// We can assume AdminActive is implicitly true if we want, but let's stick to server command
		// However, for collecting data, we should try.
		// Since we run as SYSTEM, we have full access.

		// If server says "AdminActive", we do full inventory
		if localAdmin {
			sysInfo = getSystemInfo()
			if time.Since(lastInventory) > 5*time.Minute {
				updateInventory()
				sysInfo.Software = cachedSoftware
				sysInfo.Services = cachedServices
				sysInfo.Patches = cachedPatches
				lastInventory = time.Now()
			}
			sysInfo.EventLogs = getEventLogs()
		} else {
			// Basic Info
			sysInfo = SystemInfo{
				Hostname: cachedHostname(),
				Platform: "idle",
			}
		}

		// Always send security info (USB/RDP status)
		// Service runs as SYSTEM, so it can read HKLM
		sysInfo.Security = getSecurityInfo()

		go sendHeartbeat(sysInfo)

		// Dynamic Sleep
		interval := CheckInterval
		if localStream {
			interval = 500 * time.Millisecond // Fast poll for streaming
		} else if !localAdmin {
			interval = 5 * time.Second
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

	// Network Info
	ip := ""
	mac := ""
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if len(iface.HardwareAddr) > 0 {
			mac = iface.HardwareAddr.String()
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ip = addr.String()
				break
			}
			if ip != "" {
				break
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
	}
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

	// Get Connected USB Devices
	cmdDevices := exec.Command("powershell", "-NoProfile", "-Command", `Get-WmiObject Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | Select-Object -ExpandProperty Caption`)
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
	// 1. Get Installed Software (PowerShell) - Scan 32-bit, 64-bit and User keys
	psScript := `
	$paths = @(
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
		"HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
		"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
	);
	Get-ItemProperty $paths -ErrorAction SilentlyContinue | 
	Select-Object DisplayName, DisplayVersion, Publisher, UninstallString | 
	Where-Object { $_.DisplayName -ne $null } | 
	Sort-Object DisplayName -Unique | 
	ConvertTo-Json`

	cmd1 := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	cmd1.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd1.Output()
	if err == nil {
		var raw []struct {
			DisplayName     string `json:"DisplayName"`
			DisplayVersion  string `json:"DisplayVersion"`
			Publisher       string `json:"Publisher"`
			UninstallString string `json:"UninstallString"`
		}

		// Handle single object vs array JSON output from PowerShell
		if len(out) > 0 {
			if err := json.Unmarshal(out, &raw); err != nil {
				// Try single object
				var singleItem struct {
					DisplayName     string `json:"DisplayName"`
					DisplayVersion  string `json:"DisplayVersion"`
					Publisher       string `json:"Publisher"`
					UninstallString string `json:"UninstallString"`
				}
				if err := json.Unmarshal(out, &singleItem); err == nil {
					raw = append(raw, singleItem)
				}
			}

			var softList []Software
			for _, item := range raw {
				if item.DisplayName != "" {
					softList = append(softList, Software{
						Name:            item.DisplayName,
						Version:         item.DisplayVersion,
						Vendor:          item.Publisher,
						UninstallString: item.UninstallString,
					})
				}
			}
			cachedSoftware = softList
		}
	}

	// 2. Get Services
	psScriptServices := `Get-Service | Select-Object Name, Status | ConvertTo-Json`
	cmd2 := exec.Command("powershell", "-NoProfile", "-Command", psScriptServices)
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outSvc, errSvc := cmd2.Output()
	if errSvc == nil {
		var rawSvc []struct {
			Name   string `json:"Name"`
			Status int    `json:"Status"` // 1=Stopped, 4=Running
		}
		json.Unmarshal(outSvc, &rawSvc)
		var svcList []Service
		for _, item := range rawSvc {
			status := "Stopped"
			if item.Status == 4 {
				status = "Running"
			}
			svcList = append(svcList, Service{
				Name:   item.Name,
				Status: status,
			})
		}
		cachedServices = svcList
	}

	// 3. Get HotFixes (Patches)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-HotFix | Select-Object HotFixID,Description,InstalledBy,InstalledOn | ConvertTo-Json")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err = cmd.CombinedOutput()
	if err == nil {
		var items []struct {
			HotFixID    string      `json:"HotFixID"`
			Description string      `json:"Description"`
			InstalledBy string      `json:"InstalledBy"`
			InstalledOn interface{} `json:"InstalledOn"`
		}
		// Try unmarshal as array
		if err := json.Unmarshal(out, &items); err != nil {
			// Try single object
			var singleItem struct {
				HotFixID    string      `json:"HotFixID"`
				Description string      `json:"Description"`
				InstalledBy string      `json:"InstalledBy"`
				InstalledOn interface{} `json:"InstalledOn"`
			}
			if err := json.Unmarshal(out, &singleItem); err == nil {
				items = append(items, singleItem)
			}
		}

		var patchList []Patch
		for _, item := range items {
			patchList = append(patchList, Patch{
				HotFixID:    item.HotFixID,
				Description: item.Description,
				InstalledBy: item.InstalledBy,
				InstalledOn: time.Now(), // Simplified date
			})
		}
		cachedPatches = patchList
	}
}

func getEventLogs() []EventLog {
	cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-EventLog -LogName System -EntryType Error -Newest 5 | Select-Object TimeGenerated,EntryType,Source,Message,EventID | ConvertTo-Json")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return []EventLog{}
	}

	var items []struct {
		TimeGenerated string `json:"TimeGenerated"`
		EntryType     int    `json:"EntryType"`
		Source        string `json:"Source"`
		Message       string `json:"Message"`
		EventID       int64  `json:"EventID"`
	}

	var logs []EventLog

	if err := json.Unmarshal(out, &items); err != nil {
		var singleItem struct {
			TimeGenerated string `json:"TimeGenerated"`
			EntryType     int    `json:"EntryType"`
			Source        string `json:"Source"`
			Message       string `json:"Message"`
			EventID       int64  `json:"EventID"`
		}
		if err := json.Unmarshal(out, &singleItem); err == nil {
			items = append(items, singleItem)
		}
	}

	for _, item := range items {
		logs = append(logs, EventLog{
			TimeGenerated: time.Now(),
			EntryType:     "Error",
			Source:        item.Source,
			Message:       item.Message,
			EventID:       item.EventID,
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
		err = svc.Run(ServiceName, &myService{})
		if err != nil {
			// Log to Event Log or File if Service Start Fails
			f, _ := os.OpenFile("c:\\SystemAgentServiceError.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			f.WriteString(fmt.Sprintf("Service Start Failed: %v\n", err))
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
	log.Printf("Starting System Agent v%s in %s (Interactive Mode)\n", AgentVersion, cwd)

	// REMOVED: Self-Elevation Check (RunAs Admin) to avoid UAC Prompts
	// User must install as Service for Admin rights.

	log.Printf("Server URL: %s\n", ServerURL)

	runAgent()
}
