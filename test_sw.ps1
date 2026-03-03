$paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$sw = Get-ItemProperty $paths -ErrorAction SilentlyContinue | 
Select-Object DisplayName, DisplayVersion, Publisher, UninstallString | 
Where-Object { $_.DisplayName -ne $null } | 
Sort-Object DisplayName -Unique
if ($sw) { $sw | Select-Object -First 5 | ConvertTo-Json } else { "[]" }
