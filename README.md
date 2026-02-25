# System RMM (formerly Triveni)
Powershell Script Admin and Agent
An On-Premise Remote Monitoring and Management (RMM) system.

Project Structure
- System-Powershell-Admin: Centralized Go Backend + React Frontend (Vite/Tailwind).
- System-Agent: Native Go agent for Windows endpoints (supports Service mode).

## Current Version
- **Agent Version**: 0.0.14
- **Admin Server**: v1.0.0
  - Default IP: `192.168.1.4:8080` (Configurable in `main.go`)

## Setup & Installation

### 1. Admin Server
1. Navigate to `Triveni-Powershell-Admin`.
2. Build Frontend: `cd admin-frontend && npm run build`.
3. Build & Run Backend: `go run main.go`.
4. Access Dashboard: `http://localhost:8080`.

### 2. Agent Deployment
1. Download the **Agent (.exe)** or **One-Click Setup (.bat)** from the Dashboard header.
2. If using `.exe`: Run it on the client machine (requires manual setup for persistence).
3. If using `.bat`: Right-click and **Run as Administrator** to automatically download, install as `TriveniAgent` service, and start monitoring.

## Tech Stack

- **Backend**: Go (Golang), Gin Framework, GORM, SQLite (triveni.db).
- **Frontend**: React, TypeScript, Tailwind CSS, Lucide Icons.
- **Agent**: Native Go (Windows Service aware).

## Troubleshooting

- **Contrast Issues?**: Ensure Dark Mode is toggled via the Sun/Moon icon in the header.
- **Agent Offline?**: Check if the `TriveniAgent` service is running on the client machine (`services.msc`).
- **Build Errors?**: Ensure `Node.js` and `Go` are installed and added to your system PATH.

