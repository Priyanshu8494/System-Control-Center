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

### 🛡️ Security & Integrity (Fortress Update!)
*   **Mandatory Admin Auth (JWT)**: Dashboard access is secured via JSON Web Tokens for administrative operations.
*   **Authorized Agent Auth (X-Agent-Key)**: Exclusive "Shared Secret" key system – prevents unknown agents from connecting.
*   **HTTPS (SSL/TLS) Support**: Full support for encrypted communication between browsers, agents, and the server.
*   **Update Verification (SHA256)**: Automated binary updates are verified for integrity before installation.
*   **Persistent Policy Enforcement**: Agents automatically "re-lock" USB/RDP ports if local policies are violated.
*   **Input Sanitization Guard**: Automated PowerShell escaping prevents command injection through UI parameters.

### ⚡ Performance & Automation (New!)
*   **Permanent RAM Optimizer**: Background "Set-and-Forget" scheduling for 24/7 memory performance.
*   **Dynamic Script Engine**: Create, Edit, and Delete your own PowerShell automations directly from the UI.

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
*Access via: `http://localhost:8080` or `https://localhost:8443` (Default: admin/opx@123)*

### 2. Deploy Agent
Deployment is simple via the Dashboard header:
*   **One-Click Setup (.bat)**: Recommended for permanent monitoring (Installs as a Windows Service).
*   **Standalone Agent (.exe)**: Useful for quick, temporary diagnostic sessions.

---

## 📜 Full Documentation
For detailed technical guides, build instructions, and developer documentation, please see **[DOCUMENTATION.md](./DOCUMENTATION.md)**.

---
*Developed & Maintained by Priyanshu*
