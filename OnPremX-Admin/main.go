package main

import (
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/smtp"
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
	ID          uint   `gorm:"primaryKey" json:"id"`
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

// Alert structure for system-wide notifications
type Alert struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	AgentID   string    `json:"agent_id"`
	Type      string    `json:"type"` // e.g., "USB_PLUG"
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
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
	Browsers   []string     `gorm:"serializer:json" json:"browsers"`
	Policies   []string     `gorm:"serializer:json" json:"policies"`
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
	initialScripts = []Script{
		{Name: "Clear Temp Files", Description: "Clean system and all user temp folders", Content: "Get-ChildItem -Path 'C:\\Windows\\Temp\\*', 'C:\\Users\\*\\AppData\\Local\\Temp\\*' -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"},
		{Name: "System Health Report", Description: "Uptime, Defender status, and top 5 largest files", Content: "$r=@{}; $u=(Get-Date)-(Get-CimInstance Win32_OperatingSystem).LastBootUpTime; $r['Uptime']=\"$($u.Days)d $($u.Hours)h $($u.Minutes)m\"; $r['Defender']=(Get-Service WinDefend -ErrorAction SilentlyContinue).Status; $r['Top5Files']=Get-ChildItem C:\\Users -Recurse -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 5 Name, @{N='Size(MB)'; E={[math]::Round($_.Length/1MB,2)}}; $r | ConvertTo-Json"},
		{Name: "Audit Local Admins", Description: "List all users with local administrator privileges", Content: "net localgroup administrators | Where-Object {$_ -and $_ -notmatch 'command completed' -and $_ -notmatch 'Alias' -and $_ -notmatch 'Comment' -and $_ -notmatch '\\-\\-\\-'} "},
		{Name: "Network Diagnostic Reset", Description: "Flush DNS, reset Winsock and IP stack", Content: "Write-Host 'Flushing DNS...'; ipconfig /flushdns; Write-Host 'Resetting Winsock...'; netsh winsock reset; Write-Host 'Resetting IP stack...'; netsh int ip reset; Write-Host 'Done.'"},
		{Name: "VPN & Public IP Audit", Description: "Detect active VPNs and external Geo-location", Content: "$r=@{}; $r['ActiveVPN']=(Get-NetAdapter | Where-Object {$_.InterfaceDescription -match 'OpenVPN|Tunnel|WireGuard|Fortinet|AnyConnect'} | Select-Object Name, Status); $r['PublicIP']=(Invoke-RestMethod -Uri 'https://ipinfo.io/json' -ErrorAction SilentlyContinue); $r | ConvertTo-Json"},
		{Name: "Perimeter Port Audit", Description: "List all listening ports and associated apps", Content: "netstat -abno | findstr 'LISTENING'"},
		{Name: "WiFi Security Scanner", Description: "Check for unsecure or open WiFi connections", Content: "netsh wlan show interfaces | Select-String -Pattern 'SSID|Authentication|Cipher'"},
		{Name: "DNS Hijack Checker", Description: "Analyze system DNS for suspicious/unauthorized servers", Content: "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses"},
		{Name: "Check Defender Defs", Description: "Check if Anti-Virus definitions are up to date", Content: "Get-CimInstance -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, RealTimeProtectionEnabled | ConvertTo-Json"},
		{Name: "Whitelist Domain (Global)", Description: "Removes a specific domain from the blocklist (Hosts)", Content: "$d = '[DOMAIN]'; (Get-Content $env:windir\\System32\\drivers\\etc\\hosts) | Where-Object {$_ -notmatch $d} | Set-Content $env:windir\\System32\\drivers\\etc\\hosts; Write-Host \"Unblocked $d\""},
		{Name: "Block Domain (Global)", Description: "Blocks a specific domain via the Hosts file", Content: "$d = '[DOMAIN]'; if (!(Select-String -Path $env:windir\\System32\\drivers\\etc\\hosts -Pattern $d)) { Add-Content -Path $env:windir\\System32\\drivers\\etc\\hosts -Value \"`n127.0.0.1 $d\"; Write-Host \"Blocked $d\" } else { Write-Host \"Already blocked.\" }"},
		{Name: "Release RAM Now", Description: "Manually trigger immediate RAM optimization", Content: "$c = '[DllImport(\"kernel32.dll\")]public static extern bool SetProcessWorkingSetSize(IntPtr h, int min, int max);'; Add-Type -MemberDefinition $c -Name 'Mem' -Namespace 'API' -ErrorAction SilentlyContinue; Get-Process | ForEach-Object { try { [API.Mem]::SetProcessWorkingSetSize($_.Handle, -1, -1) } catch {} }; Write-Host 'Memory sets trimmed.'"},
		{Name: "Install Permanent Optimizer", Description: "Schedule a background task to optimize RAM every hour permanently", Content: "$s = '$c = \\'[DllImport(\"kernel32.dll\")]public static extern bool SetProcessWorkingSetSize(IntPtr h, int min, int max);\\'; Add-Type -MemberDefinition $c -Name \\'Mem\\' -Namespace \\'API\\' -ErrorAction SilentlyContinue; Get-Process | ForEach-Object { try { [API.Mem]::SetProcessWorkingSetSize($_.Handle, -1, -1) } catch {} }'; $b = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($s)); $cmd = \"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $b\"; schtasks /create /tn 'OnPremX_RAM_Optimizer' /tr $cmd /sc hourly /mo 1 /rl highest /f; Write-Host 'Permanent hourly optimization task installed.'"},
		{Name: "Remove Permanent Optimizer", Description: "Uninstall the scheduled RAM optimization task", Content: "schtasks /delete /tn 'OnPremX_RAM_Optimizer' /f; Write-Host 'Permanent optimization task removed.'"},
		{Name: "Remote Software Install (UNC)", Description: "Install .exe or .msi from a NAS or Network Share (UNC Path)", Content: "$p = '[UNC_PATH]'; $f = '[FILE_NAME]'; $i = Join-Path $p $f; if (Test-Path $i) { Write-Host \"Starting Install: $i\"; if ($f -match '.msi$') { Start-Process msiexec.exe -ArgumentList \"/i `\"$i`\" /quiet /norestart\" -Wait } else { Start-Process $i -ArgumentList '/S','/silent','/quiet' -Wait }; Write-Host 'Done.' } else { Write-Host 'Error: Path not found.' }"},
	}

	// Remote View State
	streamActive = make(map[string]bool)   // Hostname -> Is Streaming
	screenBuffer = make(map[string][]byte) // Hostname -> Last Screenshot (JPEG/PNG bytes)

	storeMutex        sync.RWMutex
	lastAdminActivity = time.Now()
)

// SystemSetting model for global settings
type SystemSetting struct {
	ID    uint   `gorm:"primaryKey" json:"id"`
	Key   string `gorm:"uniqueIndex" json:"key"` // e.g., "alert_email"
	Value string `json:"value"`
}

// sendEmailAlert sends an email when a USB event occurs
func sendEmailAlert(recipient, hostname, deviceName string) {
	if recipient == "" {
		return
	}

	// Basic SMTP Configuration (Should be moved to settings in a real app)
	from := "onpremx.alerts@gmail.com" // Placeholder
	password := "your-app-password"    // Placeholder
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Message
	subject := fmt.Sprintf("USB Alert: New device on %s", hostname)
	body := fmt.Sprintf("A new USB device was plugged into %s:\n\nDevice: %s\nTime: %s", hostname, deviceName, time.Now().Format(time.RFC822))
	message := []byte("Subject: " + subject + "\r\n\r\n" + body)

	// Auth
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Send
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{recipient}, message)
	if err != nil {
		fmt.Printf("❌ Failed to send email alert: %v\n", err)
	} else {
		fmt.Printf("📧 Email alert sent to %s for %s\n", recipient, hostname)
	}
}

func main() {
	var err error
	db, err = gorm.Open(sqlite.Open("onpremx.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	db.AutoMigrate(&AgentData{}, &Command{}, &ScheduledTask{}, &SystemSetting{}, &Alert{}, &Script{})

	// Pre-populate script library if empty
	var count int64
	db.Model(&Script{}).Count(&count)
	if count == 0 {
		for _, s := range initialScripts {
			db.Create(&s)
		}
	}

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

			// DB Logic - Get existing data to merge
			var existing AgentData
			err := db.First(&existing, "hostname = ?", agent.Hostname).Error

			if err == nil {
				// Detect USB Plug-in and Removal Events
				var alertEmail SystemSetting
				emailFound := db.Where("key = ?", "alert_email").First(&alertEmail).Error == nil && alertEmail.Value != ""

				// 1. Detect New Devices (Plugged In)
				for _, currentDev := range agent.Security.USBDevices {
					isNew := true
					for _, oldDev := range existing.Security.USBDevices {
						if currentDev == oldDev {
							isNew = false
							break
						}
					}
					if isNew {
						fmt.Printf("🚨 NEW USB DETECTED on %s: %s\n", agent.Hostname, currentDev)
						db.Create(&Alert{
							AgentID:   agent.Hostname,
							Type:      "USB_PLUG",
							Message:   fmt.Sprintf("New USB device: %s", currentDev),
							CreatedAt: time.Now(),
						})
						if emailFound {
							go sendEmailAlert(alertEmail.Value, agent.Hostname, "PLUGGED: "+currentDev)
						}
					}
				}

				// 2. Detect Missing Devices (Removed)
				for _, oldDev := range existing.Security.USBDevices {
					isRemoved := true
					for _, currentDev := range agent.Security.USBDevices {
						if oldDev == currentDev {
							isRemoved = false
							break
						}
					}
					if isRemoved {
						fmt.Printf("ℹ️ USB REMOVED on %s: %s\n", agent.Hostname, oldDev)
						db.Create(&Alert{
							AgentID:   agent.Hostname,
							Type:      "USB_REMOVE",
							Message:   fmt.Sprintf("USB device removed: %s", oldDev),
							CreatedAt: time.Now(),
						})
						if emailFound {
							go sendEmailAlert(alertEmail.Value, agent.Hostname, "REMOVED: "+oldDev)
						}
					}
				}

				// 1. Merge Inventory (Only if agent sent empty arrays)
				if len(agent.Software) == 0 && len(existing.Software) > 0 {
					agent.Software = existing.Software
				}
				if len(agent.Services) == 0 && len(existing.Services) > 0 {
					agent.Services = existing.Services
				}
				if len(agent.Patches) == 0 && len(existing.Patches) > 0 {
					agent.Patches = existing.Patches
				}
				if len(agent.EventLogs) == 0 && len(existing.EventLogs) > 0 {
					agent.EventLogs = existing.EventLogs
				}

				// 2. Preserve Metadata/Failsafes
				if len(agent.Tags) == 0 {
					agent.Tags = existing.Tags
				}
				if agent.Group == "" {
					agent.Group = existing.Group
				}
				if agent.OS == "" {
					agent.OS = existing.OS
				}
				if agent.Platform == "" {
					agent.Platform = existing.Platform
				}
				if agent.IPAddress == "" {
					agent.IPAddress = existing.IPAddress
				}
				if agent.MACAddress == "" {
					agent.MACAddress = existing.MACAddress
				}
				if agent.CPUModel == "" {
					agent.CPUModel = existing.CPUModel
				}
				if len(agent.Browsers) == 0 {
					agent.Browsers = existing.Browsers
				}
			}

			// Save the merged data
			if err := db.Save(&agent).Error; err != nil {
				fmt.Printf("❌ Failed to save agent data: %v\n", err)
			}

			// Check for pending commands
			var nextCmd *Command
			var cmd Command
			if result := db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Model(&Command{}).Where("agent_id = ? AND status = ?", agent.Hostname, "pending").Order("created_at asc").First(&cmd); result.Error == nil {
				cmd.Status = "sent"
				db.Save(&cmd)
				nextCmd = &cmd
			}

			storeMutex.Lock()
			adminActive := time.Since(lastAdminActivity) < 15*time.Second
			streamScreen := streamActive[agent.Hostname]
			storeMutex.Unlock()

			fmt.Printf("💓 Heartbeat from: %s (IP: %s, SW: %d, SVC: %d, PT: %d)\n", agent.Hostname, agent.IPAddress, len(agent.Software), len(agent.Services), len(agent.Patches))

			c.JSON(http.StatusOK, gin.H{
				"status":        "ok",
				"command":       nextCmd,
				"admin_active":  adminActive,
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

				// If hostnames is empty or ["all"], select all known agents
				hostnames := req.Hostnames
				if len(hostnames) == 0 || (len(hostnames) == 1 && hostnames[0] == "all") {
					var allAgents []AgentData
					db.Select("hostname").Find(&allAgents)
					hostnames = []string{}
					for _, a := range allAgents {
						hostnames = append(hostnames, a.Hostname)
					}
				}

				// Construct Download URL dynamically based on how admin is accessed
				serverHost := c.Request.Host
				// Use the IP that the agent is actually using to reach the server
				// c.Request.Host might be an IP, but if it's "localhost:8080", we need the LAN IP.
				if strings.HasPrefix(serverHost, "localhost") || strings.HasPrefix(serverHost, "127.0.0.1") || strings.HasPrefix(serverHost, "[::1]") || strings.HasPrefix(serverHost, "169.254") {
					addrs, err := net.InterfaceAddrs()
					if err == nil {
						for _, addr := range addrs {
							if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
								if ipnet.IP.To4() != nil {
									ipStr := ipnet.IP.String()
									if !strings.HasPrefix(ipStr, "169.254") { // Avoid APIPA
										serverHost = fmt.Sprintf("%s:8080", ipStr)
										break
									}
								}
							}
						}
					}
				}

				downloadURL := fmt.Sprintf("http://%s/dl/OnPremX-Agent.exe", serverHost)

				// Robust PowerShell update script for OLD agents (v0.0.14 and below)
				// This script will be sent as an "exec" command.
				updateScriptTemplate := `
$url = "%s";
$dest = "$env:TEMP\OnPremX-Agent.new.exe";
$proc = Get-Process OnPremX-Agent -ErrorAction SilentlyContinue | Select-Object -First 1;
$oldPath = if ($proc) { $proc.Path } else { "C:\OnPremX-Agent.exe" };

try {
    (New-Object System.Net.WebClient).DownloadFile($url, $dest);
    $batch = "@echo off` + "\r\n" + `
timeout /t 5 /nobreak > nul
sc stop OnPremXAgent > nul 2>&1
taskkill /F /IM OnPremX-Agent.exe /T > nul 2>&1
timeout /t 2 /nobreak > nul
copy /y ""$dest"" ""$oldPath"" > nul 2>&1
sc start OnPremXAgent > nul 2>&1
del ""$dest"" > nul 2>&1
del ""%%~f0""
";
    $batchPath = "$env:TEMP\upd_agent.bat";
    $batch | Out-File -FilePath $batchPath -Encoding ascii;
    Start-Process "cmd.exe" -ArgumentList "/c $batchPath" -WindowStyle Hidden;
    "Update triggered successfully"
} catch {
    "Update failed: $_"
}`

				for _, hostname := range hostnames {
					// We send it as "exec" so OLD agents can process it
					finalScript := strings.Replace(updateScriptTemplate, "%s", downloadURL, 1)
					cmd := Command{
						ID:        fmt.Sprintf("update-%d", time.Now().UnixNano()),
						AgentID:   hostname,
						Type:      "exec",
						Command:   finalScript,
						Status:    "pending",
						CreatedAt: time.Now(),
					}
					db.Create(&cmd)
				}

				c.JSON(http.StatusOK, gin.H{"status": "queued", "count": len(hostnames)})
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
				var scripts []Script
				db.Find(&scripts)
				c.JSON(http.StatusOK, scripts)
			})

			// Add/Update Script
			protected.POST("/scripts", func(c *gin.Context) {
				var req Script
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
					return
				}

				if req.ID != 0 {
					db.Save(&req)
				} else {
					db.Create(&req)
				}
				c.JSON(http.StatusOK, req)
			})

			// Delete Script
			protected.DELETE("/scripts/:id", func(c *gin.Context) {
				id := c.Param("id")
				db.Delete(&Script{}, id)
				c.JSON(http.StatusOK, gin.H{"status": "deleted"})
			})

			// --- Alerts ---
			protected.GET("/alerts", func(c *gin.Context) {
				var alerts []Alert
				db.Order("created_at desc").Limit(50).Find(&alerts)
				c.JSON(http.StatusOK, alerts)
			})

			// --- Global Settings ---

			// Get Settings
			protected.GET("/settings", func(c *gin.Context) {
				var settings []SystemSetting
				db.Find(&settings)
				c.JSON(http.StatusOK, settings)
			})

			// Save Settings
			protected.POST("/settings", func(c *gin.Context) {
				var req struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
					return
				}

				var setting SystemSetting
				if err := db.Where("key = ?", req.Key).First(&setting).Error; err == nil {
					setting.Value = req.Value
					db.Save(&setting)
				} else {
					setting = SystemSetting{Key: req.Key, Value: req.Value}
					db.Create(&setting)
				}
				c.JSON(http.StatusOK, setting)
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
