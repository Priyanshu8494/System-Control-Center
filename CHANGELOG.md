# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.1.0] - 2026-02-18

### Added
- **Bulk Agent Update**: New feature in Admin Dashboard to update multiple agents simultaneously.
  - Added "Update Agents" button in the dashboard header.
  - Implemented modal for selecting agents to update.
  - Added backend API endpoint `/api/agents/bulk-update` to handle update requests.
  - Added static file serving for agent binary at `/dl/Triveni-Agent.exe`.
- **Unit Conversion**: RAM and Disk usage are now displayed in GB in the Agent Details view.
- **Custom Wallpaper**: Admin Dashboard now supports a custom background wallpaper (place `bg.png` in `downloads` folder).

### Changed
- Refactored `AgentDetailsModal` to use hardcoded GB conversion for better readability.
- Updated `App.tsx` to include `BulkUpdateModal` component.
- Updated `main.go` (Admin) to include bulk update logic and file serving.
- **Script Library Update**: Updated "Check Disk Space" script to output formatted GB values instead of raw bytes.
