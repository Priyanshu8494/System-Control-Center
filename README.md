# 🛡️ OnPremX RMM (System Control Center)

A professional, high-performance, and secure Remote Monitoring and Management (RMM) system designed for Windows infrastructure. OnPremX provides a unified dashboard to manage thousands of endpoints with native speed and modern aesthetics.

---

## 🏗️ Project Structure
- **[OnPremX-Admin](./OnPremX-Admin)**: Central management server with a real-time React dashboard.
- **[OnPremX-Agent](./OnPremX-Agent)**: Zero-runtime Go agent optimized for Windows (runs as a System Service).

## 🚀 Key Features

### 💻 Endpoint Management
*   **Live Dashboard**: Real-time CPU, RAM, and Disk usage monitoring.
*   **Software Inventory**: Automatically lists all installed apps with uninstall capabilities.
*   **Service Control**: Start, stop, and restart Windows services remotely.
*   **System Patches**: Audit installed Windows KB hotfixes and security patches.

### 🔍 Advanced Detection
*   **Web Browser Audit**: Automatically detects Chrome, Edge, Firefox, and Brave installations.
*   **Enhanced Maintenance**: Multi-profile temp file cleaner (System + all User profiles).
*   **Security Logs**: Real-time collection of Windows Event Logs and system errors.

### 🛡️ Security & Integrity (New!)
*   **VPN Tracking**: Discover active VPN connections and verify Public IP Geo-locations.
*   **Network Port Audit**: Monitor all "Listening" ports to catch unauthorized backdoors.
*   **WiFi Security Scanner**: Identify unsecure/open WiFi connections on mobile endpoints.
*   **DNS Hijack Guard**: Audit system DNS settings to prevent phishing redirections.

---

## 🛠️ Quick Installation

### 1. Build & Run Admin Server
```powershell
# Build Frontend
cd OnPremX-Admin/admin-frontend
npm install && npm run build

# Run Backend
cd ..
go build -o OnPremX-Admin.exe main.go
.\OnPremX-Admin.exe
```
*Access via: `http://localhost:8080` (Default: admin/opx@123)*

### 2. Deploy Agent
Deployment is simple via the Dashboard header:
*   **One-Click Setup (.bat)**: Recommended for permanent monitoring (Installs as a Windows Service).
*   **Standalone Agent (.exe)**: Useful for quick, temporary diagnostic sessions.

---

## 📜 Full Documentation
For detailed technical guides, build instructions, and developer documentation, please see **[DOCUMENTATION.md](./DOCUMENTATION.md)**.

---
*Developed & Maintained by Priyanshu*
