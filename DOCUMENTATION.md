# 🛡️ OnPremX RMM (System Control Center) Documentation

OnPremX is a lightweight, high-performance Remote Monitoring and Management (RMM) system designed for Windows environments. It consists of a central **Admin Server** (Go + React) and a distributed **Endpoint Agent** (Go).

---

## 🏗️ System Architecture

### 1. Admin Server (`OnPremX-Admin`)
*   **Backend**: Written in Go, using GORM for SQLite database management. 
*   **Frontend**: A modern, premium React dashboard (Vite + Radix/Lucide) that communicates via a REST API.
*   **Embedded Storage**: Uses `onpremx.db` (SQLite) for storing agent data, command history, and security alerts.

### 2. Endpoint Agent (`OnPremX-Agent`)
*   **Engine**: Native Go binary with no external dependencies (Zero-runtime).
*   **Privileges**: Designed to run as a **Windows Service** (System privileges) for full control.
*   **Capabilities**: Collects hardware stats, manages software/services, executes remote PowerShell, and enforces security policies.

---

## 🚀 Setting Up & Building

### Prerequisites
*   **Go (Golang)**: Installed in the project directory.
*   **Node.js & npm**: For building the React dashboard.

### 1. Building the Frontend
```powershell
cd OnPremX-Admin/admin-frontend
npm install
npm run build
```

### 2. Building the Admin Server
```powershell
cd OnPremX-Admin
go build -o OnPremX-Admin.exe main.go
```

### 3. Building the Agent
```powershell
cd OnPremX-Agent
go build -o OnPremX-Agent.exe main.go
```

---

## 📈 Key Features & Modules

### 🌐 Web Browser Detection
The system automatically identifies primary web browsers installed on endpoints by scanning the Windows Registry (`HKLM:\SOFTWARE\Clients\StartMenuInternet`) and critical filesystem paths.
*   **Supported**: Google Chrome, MS Edge, Firefox, Brave, Opera.
*   **View**: Located in the **Core** tab of the Endpoint Details modal.

### 🧹 Automated Maintenance
*   **Enhanced Temp Cleaner**: Targets both System temp (`C:\Windows\Temp`) and **all user profiles** (`AppData\Local\Temp`), unlike standard cleaners that only target the active user.

### 📜 Specialized Script Library
The system includes pre-built PowerShell automations:
*   **System Health Report**: Uptime, Defender status, and Top 5 largest files.
*   **Security Audit**: Lists all local administrators and checks AV definition dates.
*   **Network Security Toolkit**: 
    *   **VPN & Public IP Audit**: Detects active VPN adapters and retrieves Geo-location.
    *   **Perimeter Port Audit**: Lists every port in "LISTENING" mode.
    *   **WiFi Security Scanner**: Checks for unsecure/open WiFi encrypted connections.
    *   **DNS Hijack Checker**: Audits assigned DNS servers for rogue entries.
    *   **Interactive Domain Manager**: Block/Whitelist specific domains using the local Hosts firewall with parametric popup input.

### ⚡ Performance Optimization
*   **Real-time RAM Release**: Immediate process working set trimming via WinAPI.
*   **Permanent Hourly Optimizer**: A system-level scheduled task that persists even when the agent is closed, ensuring long-term system stability.

---

## 🛠️ How to Update & Expand the System

### Adding New Automated Scripts (Dynamic)
As of v0.0.18, scripts are stored in the **onpremx.db** (SQLite). You no longer need to modify the source code to add scripts.
1. Navigate to the **Scripts** tab in the dashboard.
2. Click the **"New System Script"** card.
3. Your new automation is instantly indexed and available across all endpoints.

### Modifying Agent Collection
To collect more hardware data (e.g., GPU details, BIOS version), update the `AgentData` struct in both `OnPremX-Admin/main.go` and `OnPremX-Agent/main.go`, and implement the collector in the Agent.

---

## 📡 Networking & Security
*   **Port**: The server runs on port **8080** by default.
*   **Server URL**: Agents look for `OnPremX-Agent.config.json` in their directory to find the server.
*   **Auth**: The system uses JWT tokens for dashboard access.
*   **Default Login**:
    *   **User**: `admin`
    *   **Pass**: `opx@123`

---
