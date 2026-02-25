package main

import (
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB Instance
var db *gorm.DB

// JWT Secret Key (Change this in production)
var jwtSecretKey = []byte("OnPremXSuperSecretKey2026")

// Login Credentials
const (
	AdminUsername = "admin"
	AdminPassword = "opx@123"
)

// Login Request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

//go:embed admin-frontend/dist/*
var staticFiles embed.FS

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

// Script structure (Library)
type Script struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"` // PowerShell Code
}

// Command structure
type Command struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	AgentID   string    `json:"agent_id"` // Hostname (Foreign Key logic manually handled or implicit)
	Type      string    `json:"type"`     // "exec", "cancel", "file_ls", "file_get"
	Command   string    `json:"command"`  // PowerShell script or ID to cancel or Path
	Status    string    `json:"status"`   // pending, sent, completed, failed, cancelling
	Output    string    `json:"output"`
	CreatedAt time.Time `json:"created_at"`
}

// ScheduledTask structure
type ScheduledTask struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	Schedule    string    `json:"schedule"` // e.g. "every 5m" or cron
	CommandType string    `json:"command_type"`
	Command     string    `json:"command"`
	TargetTags  []string  `gorm:"serializer:json" json:"target_tags"`
	TargetHosts []string  `gorm:"serializer:json" json:"target_hosts"`
	LastRun     time.Time `json:"last_run"`
	NextRun     time.Time `json:"next_run"`
}

// AgentData structure matches the JSON sent by the Agent
type AgentData struct {
	Hostname        string    `gorm:"primaryKey" json:"hostname"`
	OS              string    `json:"os"`
	Arch            string    `json:"arch"`
	Platform        string    `json:"platform"`
	PlatformVersion string    `json:"platform_version"`
	Uptime          uint64    `json:"uptime"`
	CPUModel        string    `json:"cpu_model"`
	CPUUsage        float64   `json:"cpu_usage"`
	TotalRAM        uint64    `json:"total_ram"`
	UsedRAM         uint64    `json:"used_ram"`
	RAMUsage        float64   `json:"ram_usage"`
	TotalDisk       uint64    `json:"total_disk"`
	UsedDisk        uint64    `json:"used_disk"`
	DiskUsage       float64   `json:"disk_usage"`
	AgentVersion    string    `json:"agent_version"`
	LastSeen        time.Time `json:"last_seen"`

	// New Fields for "Action1-like" features
	IPAddress  string       `json:"ip_address"`
	MACAddress string       `json:"mac_address"`
	Software   []Software   `gorm:"serializer:json" json:"software"`
	Services   []Service    `gorm:"serializer:json" json:"services"`
	Patches    []Patch      `gorm:"serializer:json" json:"patches"`
	EventLogs  []EventLog   `gorm:"serializer:json" json:"event_logs"`
	Security   SecurityInfo `gorm:"serializer:json" json:"security"`
	Tags       []string     `gorm:"serializer:json" json:"tags"`
	Group      string       `json:"group"`
}

// SecurityInfo structure
type SecurityInfo struct {
	USBBlocked  bool     `json:"usb_blocked"`
	RDPBlocked  bool     `json:"rdp_blocked"`
	USBDevices  []string `json:"usb_devices"`
	RDPSessions []string `json:"rdp_sessions"`
}

var (
	// agentStore    = make(map[string]AgentData) // REPLACED BY DB
	// commandQueue  = make(map[string][]Command) // REPLACED BY DB
	scriptLibrary = []Script{
		{ID: "1", Name: "Clear Temp Files", Description: "Removes temporary files to free up space", Content: "Remove-Item -Path $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue"},
		{ID: "2", Name: "Restart Print Spooler", Description: "Restarts the print spooler service", Content: "Restart-Service -Name Spooler -Force"},
		{ID: "3", Name: "Check Disk Space (GB)", Description: "Checks disk space on C: drive in GB", Content: "Get-PSDrive C | Select-Object @{N='Used(GB)';E={'{0:N2}' -f ($_.Used/1GB)}}, @{N='Free(GB)';E={'{0:N2}' -f ($_.Free/1GB)}}"},
	}

	// Remote View State
	streamActive = make(map[string]bool)   // Hostname -> Is Streaming
	screenBuffer = make(map[string][]byte) // Hostname -> Last Screenshot (JPEG/PNG bytes)

	storeMutex        sync.RWMutex
	lastAdminActivity = time.Now()
)

func main() {
	var err error
	db, err = gorm.Open(sqlite.Open("onpremx.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	db.AutoMigrate(&AgentData{}, &Command{}, &ScheduledTask{})

	// Start Scheduler
	go schedulerLoop()

	r := gin.Default()

	// Enable CORS for React Frontend (Keep this for dev mode if needed, but not critical for embedded)
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Serve React Static Files
	distFS, _ := fs.Sub(staticFiles, "admin-frontend/dist")
	r.StaticFS("/ui", http.FS(distFS))
	r.Static("/dl", "./downloads") // Serve Agent Binary from local downloads folder

	// Redirect root to /ui
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/ui/")
	})

	api := r.Group("/api")
	{
		// Login Endpoint
		api.POST("/login", func(c *gin.Context) {
			var creds LoginRequest
			if err := c.ShouldBindJSON(&creds); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
				return
			}

			if creds.Username != AdminUsername || creds.Password != AdminPassword {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
				return
			}

			// Generate JWT
			expirationTime := time.Now().Add(24 * time.Hour)
			claims := &Claims{
				Username: creds.Username,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(expirationTime),
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(jwtSecretKey)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"token":     tokenString,
				"expiresIn": expirationTime,
			})
		})

		// Agent Heartbeat (Public, No Auth)
		api.POST("/heartbeat", func(c *gin.Context) {
			var agent AgentData
			if err := c.ShouldBindJSON(&agent); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			agent.LastSeen = time.Now()

			// DB Logic
			var existing AgentData
			result := db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).First(&existing, "hostname = ?", agent.Hostname)

			if result.Error == nil {
				// Merge logic
				if agent.CPUUsage == 0 && agent.TotalRAM == 0 {
					// Restore stats from DB if idle
					agent.CPUModel = existing.CPUModel
					agent.CPUUsage = existing.CPUUsage
					agent.TotalRAM = existing.TotalRAM
					agent.UsedRAM = existing.UsedRAM
					agent.RAMUsage = existing.RAMUsage
					agent.TotalDisk = existing.TotalDisk
					agent.UsedDisk = existing.UsedDisk
					agent.DiskUsage = existing.DiskUsage
					agent.OS = existing.OS
					agent.Arch = existing.Arch
					agent.Platform = existing.Platform
					agent.PlatformVersion = existing.PlatformVersion
					// Preserve Network info
					if agent.IPAddress == "" {
						agent.IPAddress = existing.IPAddress
					}
					if agent.MACAddress == "" {
						agent.MACAddress = existing.MACAddress
					}
				}

				if len(agent.Software) == 0 {
					agent.Software = existing.Software
				}
				if len(agent.Services) == 0 {
					agent.Services = existing.Services
				}
				if len(agent.Patches) == 0 {
					agent.Patches = existing.Patches
				}
				if len(agent.EventLogs) == 0 {
					agent.EventLogs = existing.EventLogs
				}

				// Preserve Tags and Group (Metadata)
				if len(agent.Tags) == 0 {
					agent.Tags = existing.Tags
				}
				if agent.Group == "" {
					agent.Group = existing.Group
				}
			}

			db.Save(&agent)

			// Check for pending commands
			var nextCmd *Command
			var cmd Command
			// Find oldest pending command
			if result := db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Model(&Command{}).Where("agent_id = ? AND status = ?", agent.Hostname, "pending").Order("created_at asc").First(&cmd); result.Error == nil {
				// Mark as sent
				cmd.Status = "sent"
				db.Save(&cmd)
				nextCmd = &cmd
			}

			storeMutex.Lock()
			// Check if Admin is Active (last 15 seconds)
			adminActive := time.Since(lastAdminActivity) < 15*time.Second

			// Check if Streaming is Active for this agent
			streamScreen := streamActive[agent.Hostname]
			storeMutex.Unlock()

			fmt.Printf("💓 Heartbeat received from: %s\n", agent.Hostname)

			c.JSON(http.StatusOK, gin.H{
				"status":        "ok",
				"command":       nextCmd,
				"admin_active":  adminActive, // Tell agent if it should work hard or sleep
				"stream_screen": streamScreen,
			})
		})

		// --- Remote View Endpoints ---

		// 1. Toggle Screen Streaming (Admin -> Server)
		api.POST("/agent/stream/:hostname", func(c *gin.Context) {
			hostname := c.Param("hostname")
			enabled := c.Query("enabled") == "true"

			storeMutex.Lock()
			streamActive[hostname] = enabled
			if !enabled {
				delete(screenBuffer, hostname) // Clear buffer when stopping
			}
			storeMutex.Unlock()

			c.JSON(http.StatusOK, gin.H{"status": "updated", "streaming": enabled})
		})

		// 2. Receive Screenshot (Agent -> Server)
		api.POST("/agent/screenshot", func(c *gin.Context) {
			var req struct {
				Hostname string `json:"hostname"`
				Image    string `json:"image"` // Base64 encoded image
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			storeMutex.Lock()
			// Only accept if streaming is active (security/perf)
			if streamActive[req.Hostname] {
				// Store raw bytes if possible, but keeping Base64 string is fine for now
				// Actually, storing bytes is better for serving directly as image
				// But simpler to just store the base64 string and serve it as JSON or Image
				// Let's store the Base64 string directly for simplicity in this MVP
				screenBuffer[req.Hostname] = []byte(req.Image)
			}
			storeMutex.Unlock()

			c.JSON(http.StatusOK, gin.H{"status": "received"})
		})

		// 3. Get Latest Screenshot (Admin -> Server)
		api.GET("/agent/:hostname/screen", func(c *gin.Context) {
			hostname := c.Param("hostname")
			storeMutex.RLock()
			imgData, ok := screenBuffer[hostname]
			storeMutex.RUnlock()

			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "No screen data available"})
				return
			}

			// Decode Base64 to Image Bytes
			rawBytes, err := base64.StdEncoding.DecodeString(string(imgData))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode image"})
				return
			}

			// Serve as Image
			c.Data(http.StatusOK, "image/jpeg", rawBytes)
		})

		// Protected Routes Group
		protected := api.Group("/")
		protected.Use(authMiddleware())
		{
			// List Files (Admin -> Server -> Agent)
			protected.POST("/file/ls", func(c *gin.Context) {
				var req struct {
					Hostname string `json:"hostname"`
					Path     string `json:"path"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				cmd := Command{
					ID:        fmt.Sprintf("ls-%d", time.Now().UnixNano()),
					AgentID:   req.Hostname,
					Type:      "file_ls",
					Command:   req.Path,
					Status:    "pending",
					CreatedAt: time.Now(),
				}
				db.Create(&cmd)

				c.JSON(http.StatusOK, gin.H{"status": "queued", "command_id": cmd.ID})
			})

			// Get File (Admin -> Server -> Agent)
			protected.POST("/file/get", func(c *gin.Context) {
				var req struct {
					Hostname string `json:"hostname"`
					Path     string `json:"path"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				cmd := Command{
					ID:        fmt.Sprintf("get-%d", time.Now().UnixNano()),
					AgentID:   req.Hostname,
					Type:      "file_get",
					Command:   req.Path,
					Status:    "pending",
					CreatedAt: time.Now(),
				}
				db.Create(&cmd)

				c.JSON(http.StatusOK, gin.H{"status": "queued", "command_id": cmd.ID})
			})

			// Queue a Command (Admin -> Server)
			protected.POST("/command/queue", func(c *gin.Context) {
				var req struct {
					Hostname string `json:"hostname"`
					Command  string `json:"command"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				cmd := Command{
					ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
					AgentID:   req.Hostname,
					Type:      "exec",
					Command:   req.Command,
					Status:    "pending",
					CreatedAt: time.Now(),
				}

				db.Create(&cmd)

				c.JSON(http.StatusOK, gin.H{"status": "queued", "command_id": cmd.ID})
			})

			// Cancel a Command (Admin -> Server)
			protected.POST("/command/cancel", func(c *gin.Context) {
				var req struct {
					Hostname  string `json:"hostname"`
					CommandID string `json:"command_id"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				var cmd Command
				if err := db.First(&cmd, "id = ? AND agent_id = ?", req.CommandID, req.Hostname).Error; err != nil {
					c.JSON(http.StatusNotFound, gin.H{"error": "Command not found"})
					return
				}

				if cmd.Status == "pending" {
					cmd.Status = "cancelled"
					cmd.Output = "Cancelled by user before execution"
					db.Save(&cmd)
				} else if cmd.Status == "sent" {
					// Queue cancellation command
					cancelCmd := Command{
						ID:        fmt.Sprintf("cancel-%s", req.CommandID),
						AgentID:   req.Hostname,
						Type:      "cancel",
						Command:   req.CommandID,
						Status:    "pending",
						CreatedAt: time.Now(),
					}
					db.Create(&cancelCmd)

					cmd.Status = "cancelling"
					db.Save(&cmd)
				}

				c.JSON(http.StatusOK, gin.H{"status": "cancellation_requested"})
			})

			// Receive Command Result (Agent -> Server)
			api.POST("/command/result", func(c *gin.Context) {
				var res struct {
					Hostname  string `json:"hostname"`
					CommandID string `json:"command_id"`
					Output    string `json:"output"`
					Error     string `json:"error"`
				}
				if err := c.ShouldBindJSON(&res); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				var cmd Command
				if err := db.First(&cmd, "id = ?", res.CommandID).Error; err == nil {
					// Ignore updates for cancelled commands unless it's the final output
					if cmd.Status != "cancelled" {
						cmd.Status = "completed"
						if res.Error != "" {
							cmd.Status = "failed"
							cmd.Output = res.Error + "\n" + res.Output
						} else {
							cmd.Output = res.Output
						}
						db.Save(&cmd)
					}
				}

				c.JSON(http.StatusOK, gin.H{"status": "received"})
			})

			// Update Agent Metadata (Tags & Group) - Admin -> Server
			protected.POST("/agent/metadata", func(c *gin.Context) {
				var req struct {
					Hostname string   `json:"hostname"`
					Tags     []string `json:"tags"`
					Group    string   `json:"group"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				var agent AgentData
				if err := db.First(&agent, "hostname = ?", req.Hostname).Error; err == nil {
					agent.Tags = req.Tags
					agent.Group = req.Group
					db.Save(&agent)
					c.JSON(http.StatusOK, gin.H{"status": "updated"})
				} else {
					c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
				}
			})

			// Get Agent Commands (Admin -> Server)
			protected.GET("/commands/:hostname", func(c *gin.Context) {
				hostname := c.Param("hostname")
				var cmds []Command
				db.Where("agent_id = ?", hostname).Order("created_at desc").Find(&cmds)
				c.JSON(http.StatusOK, cmds)
			})

			// List Agents (Polled by Admin Dashboard)
			protected.GET("/agents", func(c *gin.Context) {
				storeMutex.Lock()
				lastAdminActivity = time.Now() // Admin is active
				storeMutex.Unlock()

				var agents []AgentData
				db.Find(&agents)
				c.JSON(http.StatusOK, agents)
			})

			// Bulk Update Agents
			protected.POST("/agents/bulk-update", func(c *gin.Context) {
				var req struct {
					Hostnames []string `json:"hostnames"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				// Construct Download URL (Use the hardcoded server IP to avoid localhost issues on remote agents)
				// Find local IP if request is from localhost
				serverHost := c.Request.Host
				if strings.HasPrefix(serverHost, "localhost") || strings.HasPrefix(serverHost, "127.0.0.1") {
					addrs, err := net.InterfaceAddrs()
					if err == nil {
						for _, addr := range addrs {
							if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
								if ipnet.IP.To4() != nil {
									serverHost = fmt.Sprintf("%s:8080", ipnet.IP.String())
									break
								}
							}
						}
					}
				}

				// PowerShell Update Command (Service-Aware & Path-Agnostic)
				downloadURL := "http://192.168.1.4:8080/dl/OnPremX-Agent.exe"

				// Note: We use [[BT]] as a placeholder for backtick (`) because we can't use backticks inside a Go raw string literal.
				updateCmdTemplate := `
$url = "%s";
$tempDir = [System.IO.Path]::GetTempPath();
$dest = Join-Path $tempDir "OnPremX-Agent.new.exe";
$script = Join-Path $tempDir "update_agent.ps1";
$log = Join-Path $tempDir "update_log.txt";

// Clean up previous runs
if (Test-Path $dest) { Remove-Item $dest -Force }
if (Test-Path $script) { Remove-Item $script -Force }

Start-Transcript -Path $log -Force;
try {
    // Check for Admin privileges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Not running as Administrator. Attempting to elevate..."
        
        $elevationScript = @"
Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command & {
    [[BT]]$url = '$url'
    [[BT]]$tempDir = [System.IO.Path]::GetTempPath()
    [[BT]]$dest = Join-Path [[BT]]$tempDir 'OnPremX-Agent.new.exe'
    [[BT]]$script = Join-Path [[BT]]$tempDir 'update_agent_elevated.ps1'
    
    # Download again in elevated context to be safe or just pass path? Better pass path.
    # Actually, let's just re-download inside the elevated block to avoid passing complex args.
    Invoke-WebRequest -Uri [[BT]]$url -OutFile [[BT]]$dest -ErrorAction Stop

    # Stop Service
    Stop-Service -Name 'OnPremXAgent' -Force -ErrorAction SilentlyContinue
    Get-Process -Name 'OnPremX-Agent' -ErrorAction SilentlyContinue | Stop-Process -Force

    # Find Original Path (We need to find it again or pass it)
    [[BT]]$originalExePath = '$((Get-Process -Name "OnPremX-Agent" -ErrorAction SilentlyContinue).Path)'
    if (-not [[BT]]$originalExePath) {
        [[BT]]$svc = Get-WmiObject win32_service | Where-Object { [[BT]]$_.Name -eq 'OnPremXAgent' }
        if ([[BT]]$svc) {
             [[BT]]$path = [[BT]]$svc.PathName -replace '"',''
             if ([[BT]]$path -match '^(.*\.exe)') { [[BT]]$path = [[BT]]$matches[1] }
             [[BT]]$originalExePath = [[BT]]$path
        }
    }
    
    if (-not [[BT]]$originalExePath) {
         # Fallback default
         [[BT]]$originalExePath = 'C:\Program Files\OnPremX Agent\OnPremX-Agent.exe'
    }

    # Replace
    Move-Item -Path [[BT]]$dest -Destination [[BT]]$originalExePath -Force
    
    # Restart
    Start-Service -Name 'OnPremXAgent' -ErrorAction SilentlyContinue
    Start-Process [[BT]]$originalExePath -WindowStyle Hidden
}"
"@
        Invoke-Expression $elevationScript
        exit
    }

    // Get Current Agent Location
    $originalExePath = $null
    
    # 1. Try to find running process
    $proc = Get-Process -Name "OnPremX-Agent" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) {
        $originalExePath = $proc.Path
    }
    
    # 2. If process not found (e.g. stopped service), try Service Config
    if (-not $originalExePath) {
        $serviceName = "OnPremXAgent"
        $svc = Get-WmiObject win32_service | Where-Object { $_.Name -eq $serviceName }
        if ($svc) {
             $path = $svc.PathName -replace '"',''
             if ($path -match '^(.*\.exe)') { $path = $matches[1] }
             $originalExePath = $path
        }
    }
    
    # 3. Fallback: Check standard install location (Program Files)
    if (-not $originalExePath) {
        $progFiles = "C:\Program Files\OnPremX Agent\OnPremX-Agent.exe"
        if (Test-Path $progFiles) {
            $originalExePath = $progFiles
        }
    }
    
    # Safety Check: Do NOT overwrite PowerShell
    if ($originalExePath -like "*powershell.exe") {
        Throw "Error: Detected path is PowerShell, not OnPremX-Agent."
    }
    
    if (-not $originalExePath) {
        Throw "Could not find OnPremX-Agent executable path. Is the agent installed/running?"
    }
    
    Write-Output "Target Agent Path: $originalExePath";
    
    Write-Output "Downloading update from $url to $dest...";
    Invoke-WebRequest -Uri $url -OutFile $dest -ErrorAction Stop;
    
    # Check if download was successful
    if ((Get-Item $dest).Length -lt 1000) {
        Throw "Downloaded file is too small. Update failed."
    }

    $updateScript = @"
[[BT]]$ErrorActionPreference = 'Stop'
[[BT]]$tempDir = [System.IO.Path]::GetTempPath()
[[BT]]$logPath = "[[BT]]$tempDir\OnPremXUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path [[BT]]$logPath -Force

Write-Output "Update started at $(Get-Date)"
Write-Output "Target: $originalExePath"

# 1. Stop Services/Processes
Write-Output "Stopping OnPremX Agent..."
[[BT]]$serviceName = "OnPremXAgent"
[[BT]]$svc = Get-Service -Name [[BT]]$serviceName -ErrorAction SilentlyContinue

if ([[BT]]$svc -and [[BT]]$svc.Status -eq 'Running') {
    Write-Output "Stopping Service..."
    Stop-Service -Name [[BT]]$serviceName -Force
    Start-Sleep -Seconds 5
}

# Kill any remaining processes
Get-Process -Name "OnPremX-Agent" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# 2. Swap Binaries (Rename + Move)
[[BT]]$backupPath = "$originalExePath.bak"
if (Test-Path [[BT]]$backupPath) { Remove-Item [[BT]]$backupPath -Force }

[[BT]]$maxRetries = 10
[[BT]]$retryCount = 0
[[BT]]$replaced = [[BT]]$false

while (-not [[BT]]$replaced -and [[BT]]$retryCount -lt [[BT]]$maxRetries) {
    try {
        if (Test-Path "$originalExePath") {
             Write-Output "Renaming current binary to .bak..."
             Rename-Item -Path "$originalExePath" -NewName "$originalExePath.bak" -Force
        }
        
        Write-Output "Moving new binary into place..."
        Move-Item -Path "$dest" -Destination "$originalExePath" -Force
        [[BT]]$replaced = [[BT]]$true
    } catch {
        Write-Output "File locked, retrying in 3 seconds... ([[BT]]$retryCount/[[BT]]$maxRetries)"
        Write-Output "Error: [[BT]]$_"
        Start-Sleep -Seconds 3
        [[BT]]$retryCount++
        
        # Try killing again
        Get-Process -Name "OnPremX-Agent" -ErrorAction SilentlyContinue | Stop-Process -Force
        if ([[BT]]$svc) { Stop-Service -Name [[BT]]$serviceName -Force -ErrorAction SilentlyContinue }
    }
}

if (-not [[BT]]$replaced) {
    Write-Error "Failed to replace binary after multiple attempts."
    exit 1
}

# 3. Restart Service/Process
Write-Output "Restarting Agent..."
if ([[BT]]$svc) {
    Start-Service -Name [[BT]]$serviceName
    Write-Output "Service started."
} else {
    Write-Output "Service not found. Installing Service..."
    New-Service -Name [[BT]]$serviceName -BinaryPathName "$originalExePath" -DisplayName "OnPremX Agent" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name [[BT]]$serviceName -ErrorAction SilentlyContinue
    
    # Fallback to process if service fails
    if (-not (Get-Service -Name [[BT]]$serviceName -ErrorAction SilentlyContinue | Where-Object { [[BT]]$_.Status -eq 'Running' })) {
         Write-Output "Service install failed. Starting as process..."
         Start-Process "$originalExePath" -WindowStyle Hidden
    }
}

Write-Output "Update Complete."
Stop-Transcript
"@
    Set-Content -Path $script -Value $updateScript
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File ""$script""" -WindowStyle Hidden
} catch {
    Write-Error "Failed to download update: $_";
}
Stop-Transcript;
`
				updateCmd := fmt.Sprintf(strings.ReplaceAll(updateCmdTemplate, "[[BT]]", "`"), downloadURL)

				for _, hostname := range req.Hostnames {
					cmd := Command{
						ID:        fmt.Sprintf("update-%s-%d", hostname, time.Now().UnixNano()),
						AgentID:   hostname,
						Type:      "exec",
						Command:   updateCmd,
						Status:    "pending",
						CreatedAt: time.Now(),
					}
					db.Create(&cmd)
				}

				c.JSON(http.StatusOK, gin.H{"status": "queued", "count": len(req.Hostnames)})
			})

			// --- Scheduled Tasks Endpoints ---

			// List Tasks
			protected.GET("/tasks", func(c *gin.Context) {
				var tasks []ScheduledTask
				db.Find(&tasks)
				c.JSON(http.StatusOK, tasks)
			})

			// Create Task
			protected.POST("/tasks", func(c *gin.Context) {
				var task ScheduledTask
				if err := c.ShouldBindJSON(&task); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				// Validate Schedule
				if _, err := parseDuration(task.Schedule); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule format. Use 'every Xm' or 'every Xh'"})
					return
				}

				// Set NextRun immediately if not provided
				if task.NextRun.IsZero() {
					task.NextRun = time.Now()
				}

				db.Create(&task)
				c.JSON(http.StatusOK, task)
			})

			// Delete Task
			protected.DELETE("/tasks/:id", func(c *gin.Context) {
				id := c.Param("id")
				db.Delete(&ScheduledTask{}, id)
				c.JSON(http.StatusOK, gin.H{"status": "deleted"})
			})

			// Run Task Manually
			protected.POST("/tasks/:id/run", func(c *gin.Context) {
				id := c.Param("id")
				var task ScheduledTask
				if err := db.First(&task, id).Error; err != nil {
					c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
					return
				}

				// Determine Target Agents (Duplicated logic from Scheduler - refactor if strict)
				var agents []AgentData
				targetAll := false
				for _, h := range task.TargetHosts {
					if h == "ALL" {
						targetAll = true
						break
					}
				}

				if targetAll {
					db.Find(&agents)
				} else {
					var allAgents []AgentData
					db.Find(&allAgents)
					for _, agent := range allAgents {
						matched := false
						for _, h := range task.TargetHosts {
							if h == agent.Hostname {
								matched = true
								break
							}
						}
						if !matched {
							for _, t := range task.TargetTags {
								for _, at := range agent.Tags {
									if t == at {
										matched = true
										break
									}
								}
								if matched {
									break
								}
							}
						}
						if matched {
							agents = append(agents, agent)
						}
					}
				}

				// Create Commands
				count := 0
				for _, agent := range agents {
					cmd := Command{
						ID:        fmt.Sprintf("manual-%d-%s", time.Now().UnixNano(), agent.Hostname),
						AgentID:   agent.Hostname,
						Type:      task.CommandType,
						Command:   task.Command,
						Status:    "pending",
						CreatedAt: time.Now(),
					}
					db.Create(&cmd)
					count++
				}

				// Update LastRun
				task.LastRun = time.Now()
				db.Save(&task)

				c.JSON(http.StatusOK, gin.H{"status": "triggered", "agents_count": count})
			})

			// Security Controls (USB/RDP)
			protected.POST("/security/control", func(c *gin.Context) {
				var req struct {
					Hostname string `json:"hostname"`
					Action   string `json:"action"` // block_usb, allow_usb, block_rdp, allow_rdp, block_clipboard, allow_clipboard, kill_stream
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
					return
				}

				if req.Action == "kill_stream" {
					storeMutex.Lock()
					delete(streamActive, req.Hostname)
					storeMutex.Unlock()
					c.JSON(http.StatusOK, gin.H{"status": "stream_killed"})
					return
				}

				var cmdStr string
				switch req.Action {
				case "block_usb":
					cmdStr = `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4 -Force; Stop-Service -Name "stisvc" -Force -ErrorAction SilentlyContinue`
				case "allow_usb":
					cmdStr = `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 3 -Force; Start-Service -Name "stisvc" -ErrorAction SilentlyContinue`
				case "block_rdp":
					cmdStr = `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Force`
				case "allow_rdp":
					// Just allow RDP (don't force clipboard disabled here, user has separate control)
					cmdStr = `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force`
				case "block_clipboard":
					// Disable Clipboard Redirection
					cmdStr = `New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Value 1 -Force`
				case "allow_clipboard":
					// Enable Clipboard Redirection
					cmdStr = `New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Value 0 -Force`
				}

				if cmdStr != "" {
					queueCommand(req.Hostname, cmdStr)
					c.JSON(http.StatusOK, gin.H{"status": "security_command_queued", "action": req.Action})
				} else {
					c.JSON(http.StatusBadRequest, gin.H{"status": "unknown_action"})
				}
			})

			// List Scripts (Admin -> Server)
			protected.GET("/scripts", func(c *gin.Context) {
				storeMutex.RLock()
				defer storeMutex.RUnlock()
				c.JSON(http.StatusOK, scriptLibrary)
			})
		}
	}

	// Serve Frontend (SPA)
	frontendFS, err := fs.Sub(staticFiles, "admin-frontend/dist")
	if err != nil {
		panic(err)
	}
	httpFS := http.FS(frontendFS)

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		// API 404
		if strings.HasPrefix(path, "/api") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Endpoint not found"})
			return
		}

		// Check if file exists in the embedded FS
		// We remove the leading slash because fs.Open expects relative paths
		cleanPath := strings.TrimPrefix(path, "/")
		if cleanPath == "" {
			cleanPath = "index.html"
		}

		f, err := frontendFS.Open(cleanPath)
		if err == nil {
			defer f.Close()
			s, err := f.Stat()
			if err == nil && !s.IsDir() {
				c.FileFromFS(cleanPath, httpFS)
				return
			}
		}

		// Fallback to index.html for SPA routes
		c.FileFromFS("index.html", httpFS)
	})

	fmt.Println("🚀 OnPremX Admin Server running on :8080")
	fmt.Println("🌐 Open Dashboard at: http://localhost:8080/")

	if err := r.Run(":8080"); err != nil {
		fmt.Printf("❌ Error starting server: %v\n", err)
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
	}
}

// Helper to queue command
func queueCommand(hostname, command string) {
	cmd := Command{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		AgentID:   hostname,
		Type:      "exec",
		Command:   command,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	db.Create(&cmd)
}

// Auth Middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TEMPORARY: Disable Auth for immediate access
		// tokenString := c.GetHeader("Authorization")
		// if tokenString == "" {
		// 	tokenString = c.Query("token")
		// }

		// if tokenString == "" {
		// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
		// 	c.Abort()
		// 	return
		// }

		// tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		// claims := &Claims{}
		// token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// 	return jwtSecretKey, nil
		// })

		// if err != nil || !token.Valid {
		// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		// 	c.Abort()
		// 	return
		// }

		// c.Set("username", claims.Username)
		c.Set("username", "admin")
		c.Next()
	}
}

// Scheduler Loop
func schedulerLoop() {
	// Check every minute
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		var tasks []ScheduledTask
		// Find tasks where next_run is due (or never run)
		// We check for next_run <= Now OR next_run is zero (if that's how we init)
		// Actually, we initialized NextRun to Now() on create if zero.
		now := time.Now()
		if err := db.Where("next_run <= ?", now).Find(&tasks).Error; err != nil {
			fmt.Println("Scheduler Error:", err)
			continue
		}

		for _, task := range tasks {
			// Calculate next run time
			duration, err := parseDuration(task.Schedule)
			if err != nil {
				fmt.Printf("Skipping task '%s': invalid schedule '%s'\n", task.Name, task.Schedule)
				continue
			}

			// Update Task
			task.LastRun = now
			task.NextRun = now.Add(duration)
			db.Save(&task)

			// Determine Target Agents
			var agents []AgentData
			targetAll := false
			for _, h := range task.TargetHosts {
				if h == "ALL" {
					targetAll = true
					break
				}
			}

			if targetAll {
				db.Find(&agents)
			} else {
				// Filter by Hosts or Tags
				// This is a bit inefficient for large datasets but fine for MVP
				var allAgents []AgentData
				db.Find(&allAgents)
				for _, agent := range allAgents {
					matched := false
					// Check Hostname
					for _, h := range task.TargetHosts {
						if h == agent.Hostname {
							matched = true
							break
						}
					}
					// Check Tags
					if !matched {
						for _, t := range task.TargetTags {
							for _, at := range agent.Tags {
								if t == at {
									matched = true
									break
								}
							}
							if matched {
								break
							}
						}
					}
					if matched {
						agents = append(agents, agent)
					}
				}
			}

			// Queue Commands
			for _, agent := range agents {
				cmd := Command{
					ID:        fmt.Sprintf("sched-%d-%s", time.Now().UnixNano(), agent.Hostname),
					AgentID:   agent.Hostname,
					Type:      task.CommandType,
					Command:   task.Command,
					Status:    "pending",
					CreatedAt: time.Now(),
				}
				db.Create(&cmd)
			}
			fmt.Printf("Scheduled Task '%s' executed for %d agents\n", task.Name, len(agents))
		}
	}
}

// Parse "every Xm" or "every Xh"
func parseDuration(schedule string) (time.Duration, error) {
	parts := strings.Split(schedule, " ")
	if len(parts) != 2 || parts[0] != "every" {
		return 0, fmt.Errorf("invalid format")
	}
	return time.ParseDuration(parts[1])
}
