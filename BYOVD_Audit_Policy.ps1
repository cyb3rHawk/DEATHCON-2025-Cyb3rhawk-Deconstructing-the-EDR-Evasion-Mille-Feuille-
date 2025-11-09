# BYOVD Detection - Advanced Audit Policy Configuration
# Run as Administrator

Write-Host "[+] Enabling Advanced Audit Policies for BYOVD Detection..." -ForegroundColor Cyan

# Core BYOVD Detection Categories
$policies = @(
    # Driver Loading & System Integrity
    @{Category="System";Subcategory="System Integrity";Setting="Success,Failure"},
    @{Category="System";Subcategory="Security System Extension";Setting="Success,Failure"},
    
    # Service Creation/Modification (driver services)
    @{Category="System";Subcategory="Security State Change";Setting="Success,Failure"},
    
    # Registry Operations (Services key modifications)
    @{Category="Object Access";Subcategory="Registry";Setting="Success,Failure"},
    
    # File Operations (driver file drops)
    @{Category="Object Access";Subcategory="File System";Setting="Success,Failure"},
    @{Category="Object Access";Subcategory="Detailed File Share";Setting="Success,Failure"},
    
    # Privilege Escalation Indicators
    @{Category="Privilege Use";Subcategory="Sensitive Privilege Use";Setting="Success,Failure"},
    
    # Process Execution Context
    @{Category="Detailed Tracking";Subcategory="Process Creation";Setting="Success"},
    @{Category="Detailed Tracking";Subcategory="Process Termination";Setting="Success"},
    
    # Handle Manipulation (optional - high volume)
    # @{Category="Object Access";Subcategory="Handle Manipulation";Setting="Success"},
    
    # Kernel Object Access
    @{Category="Object Access";Subcategory="Kernel Object";Setting="Success,Failure"}
)

foreach ($policy in $policies) {

    Write-Host "[*] Setting: $($policy.Category) -> $($policy.Subcategory)" -ForegroundColor Yellow
    
    $result = auditpol /set /subcategory:"$($policy.Subcategory)" /success:enable /failure:enable 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [SUCCESS] Enabled" -ForegroundColor Green
    } else {
        Write-Host "    [SUCCESS] Failed: $result" -ForegroundColor Red
    }
}

# Enable Command Line Logging in Process Creation events
Write-Host "`n[+] Enabling Command Line Process Auditing..." -ForegroundColor Cyan
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Verify configuration
Write-Host "`n[+] Current Audit Policy Configuration:" -ForegroundColor Cyan
auditpol /get /category:* | Select-String -Pattern "System Integrity|Security System Extension|Registry|File System|Sensitive Privilege|Process Creation"

Write-Host "`n[SUCCESS] Audit policies configured for BYOVD detection" -ForegroundColor Green
Write-Host "[!] Note: This will generate significant log volume. Monitor Security and System logs." -ForegroundColor Yellow