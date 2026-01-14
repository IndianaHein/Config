<#  Optimized PowerShell profile (pwsh)
    - Fast startup (no Read-Host prompts)
    - Safe installs: opt-in via -Install switch
    - Resilient config handling (YAML if available, fallback parser if not)
    - Fixes invalid function names (cd... / cd....)
#>

Write-Host ""
Write-Host "Welcome Hein ⚡" -ForegroundColor DarkCyan
Write-Host ""

# ----------------------------
# Helpers
# ----------------------------
function Write-Info { param([string]$Message) Write-Host $Message -ForegroundColor Cyan }
function Write-Ok { param([string]$Message) Write-Host $Message -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host $Message -ForegroundColor Yellow }
function Write-Err { param([string]$Message) Write-Host $Message -ForegroundColor Red }

function Test-GitHubReachable {
    [CmdletBinding()]
    param(
        [int]$TimeoutSeconds = 1
    )

    try {
        # pwsh supports -TimeoutSeconds on Test-Connection
        return [bool](Test-Connection -ComputerName "github.com" -Count 1 -Quiet -TimeoutSeconds $TimeoutSeconds -ErrorAction Stop)
    }
    catch {
        # Fallback for older hosts: best effort (still should not crash profile)
        try { return [bool](Test-Connection -ComputerName "github.com" -Count 1 -Quiet -ErrorAction Stop) } catch { return $false }
    }
}

$script:CanConnectToGitHub = Test-GitHubReachable

# Platform flags
#$IsWindowsPlatform = $IsWindows -or ($env:OS -eq 'Windows_NT')
# Detect interactive host (avoid server remote hosts)
$IsInteractive = -not ($Host.Name -in @('ServerRemoteHost', 'ConsoleHost'))

# Prefer keeping config near your profile (portable across OneDrive/paths)
$script:ProfileDir = Split-Path -Parent $PROFILE
$script:ConfigPath = Join-Path $script:ProfileDir "pwsh_custom_config.yml"

# ----------------------------
# Config (YAML w/ fallback)
# ----------------------------
function Get-ProfileConfig {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -Path $script:ConfigPath)) {
        return @{}
    }

    $raw = Get-Content -Path $script:ConfigPath -Raw -ErrorAction SilentlyContinue
    if (-not $raw) { return @{} }

    # If Powershell-Yaml is present, use it
    if (Get-Command -Name ConvertFrom-Yaml -ErrorAction SilentlyContinue) {
        try {
            $cfg = $raw | ConvertFrom-Yaml
            if ($cfg -is [hashtable]) { return $cfg }
            # Convert PSCustomObject -> Hashtable
            $ht = @{}
            $cfg.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }
            return $ht
        }
        catch { return @{} }
    }

    # Minimal fallback: parse simple "key: value" lines
    $cfg2 = @{}
    foreach ($line in ($raw -split "(`r`n|`n)")) {
        if ($line -match '^\s*#') { continue }
        if ($line -match '^\s*$') { continue }
        if ($line -match '^\s*([^:]+?)\s*:\s*(.*?)\s*$') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim().Trim('"')
            $cfg2[$key] = $val
        }
    }
    return $cfg2
}

function Save-ProfileConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config
    )

    if (-not (Test-Path -Path $script:ProfileDir)) {
        New-Item -ItemType Directory -Path $script:ProfileDir -Force | Out-Null
    }

    if (Get-Command -Name ConvertTo-Yaml -ErrorAction SilentlyContinue) {
        $Config | ConvertTo-Yaml | Set-Content -Path $script:ConfigPath -Encoding UTF8
        return
    }

    # Fallback: write simple YAML-ish "key: value"
    $out = foreach ($k in ($Config.Keys | Sort-Object)) {
        $v = $Config[$k]
        if ($null -eq $v) { "${k}: " }
        elseif ($v -match '\s') { "${k}: `"$v`"" }
        else { "${k}: $v" }
    }

    # Persist fallback config to file
    $out -join "`n" | Set-Content -Path $script:ConfigPath -Encoding UTF8
    return
}

function Get-ConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [string]$Default = ""
    )
    $cfg = Get-ProfileConfig
    if ($cfg.ContainsKey($Key)) { return [string]$cfg[$Key] }
    return $Default
}

function Set-ConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Value
    )
    $cfg = Get-ProfileConfig
    $cfg[$Key] = $Value
    Save-ProfileConfig -Config $cfg
}

# ----------------------------
# Dev environment bootstrap (opt-in install)
# ----------------------------
function Initialize-DevEnv {
    [CmdletBinding()]
    param(
        [switch]$Install
    )

    if (-not $script:CanConnectToGitHub) {
        Write-Warn "❌ Skipping DevEnv initialization: github.com not reachable."
        return
    }

    $modules = @(
        @{ Name = "Terminal-Icons"; ConfigKey = "TerminalIconsInstalled" },
        @{ Name = "powershell-yaml"; ConfigKey = "PowerShellYamlInstalled" },
        @{ Name = "PoshFunctions"; ConfigKey = "PoshFunctionsInstalled" }
    )

    foreach ($m in $modules) {
        $isInstalled = (Get-ConfigValue -Key $m.ConfigKey -Default "False")
        $cmd = Get-Module -ListAvailable -Name $m.Name

        if ($cmd) {
            Import-Module $m.Name -ErrorAction SilentlyContinue
            if ($isInstalled -ne "True") { Set-ConfigValue -Key $m.ConfigKey -Value "True" }
            Write-Ok "✅ Module loaded: $($m.Name)"
            continue
        }

        if (-not $Install) {
            Write-Warn "💭 Missing module: $($m.Name). Run: Initialize-DevEnv -Install"
            continue
        }

        try {
            Write-Info "Installing module: $($m.Name)"
            Install-Module -Name $m.Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Import-Module $m.Name -ErrorAction SilentlyContinue
            Set-ConfigValue -Key $m.ConfigKey -Value "True"
            Write-Ok "✅ Installed: $($m.Name)"
        }
        catch {
            Write-Err "❌ Failed installing $($m.Name): $($_.Exception.Message)"
        }
    }

    # App checks (non-blocking)
    if (-not (Get-Command code -ErrorAction SilentlyContinue)) {
        Write-Warn "💭 VS Code not found in PATH. (Install via winget: winget install Microsoft.VisualStudioCode)"
    }

    if (-not (Get-Command oh-my-posh -ErrorAction SilentlyContinue)) {
        Write-Warn "💭 oh-my-posh not found. (Install: winget install JanDeDobbeleer.OhMyPosh)"
    }

    Write-Ok "✅ Pwsh profile initialization complete."
}

# ----------------------------
# Fonts (no prompts on load)
# ----------------------------
function Get-InstalledFont {
    [CmdletBinding()]
    param(
        [string]$NamePattern = "*"
    )

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
    )

    $results = New-Object System.Collections.Generic.List[string]

    foreach ($p in $paths) {
        if (-not (Test-Path $p)) { continue }

        try {
            $item = Get-ItemProperty -Path $p -ErrorAction Stop

            foreach ($prop in $item.PSObject.Properties) {
                # Skip engine props like PSPath/PSParentPath/etc.
                if ($prop.Name -like "PS*") { continue }

                # Match on registry value NAME
                if ($prop.Name -like $NamePattern) { [void]$results.Add($prop.Name) }

                # Also match on registry value DATA (often the .ttf filename)
                $data = [string]$prop.Value
                if ($data -and ($data -like $NamePattern)) { [void]$results.Add($data) }
            }
        }
        catch { }
    }

    $results | Sort-Object -Unique
}




function Install-FiraCodeNerdFontZip {
    [CmdletBinding()]
    param(
        [string]$ReleaseTag = "v3.2.1"
    )

    $zipUrl = "https://github.com/ryanoasis/nerd-fonts/releases/download/$ReleaseTag/FiraCode.zip"
    $tempZip = Join-Path $env:TEMP "FiraCode.NerdFont.zip"
    $tempDir = Join-Path $env:TEMP ("FiraCodeNerdFont_" + [guid]::NewGuid().ToString("N"))

    $userFontsDir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"
    $hkcuFontsKey = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"

    try {
        Write-Info "Downloading: $zipUrl"
        Invoke-WebRequest -Uri $zipUrl -OutFile $tempZip -UseBasicParsing -ErrorAction Stop

        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force

        New-Item -ItemType Directory -Path $userFontsDir -Force | Out-Null
        if (-not (Test-Path $hkcuFontsKey)) { New-Item -Path $hkcuFontsKey -Force | Out-Null }

        $ttfs = Get-ChildItem -Path $tempDir -Recurse -File -Filter "*.ttf" |
        Where-Object { $_.Name -match '^FiraCodeNerdFont' }

        if (-not $ttfs) { throw "No FiraCode Nerd Font TTF files found in the downloaded ZIP." }

        $installed = 0
        $skippedExisting = 0
        $skippedLocked = 0

        foreach ($f in $ttfs) {
            $dest = Join-Path $userFontsDir $f.Name

            # Don't overwrite in-use fonts; skip if present
            if (Test-Path $dest) {
                $skippedExisting++
                continue
            }

            try {
                Copy-Item -Path $f.FullName -Destination $dest -Force -ErrorAction Stop
                $installed++

                $valueName = $f.BaseName + " (TrueType)"
                New-ItemProperty -Path $hkcuFontsKey -Name $valueName -Value $f.Name -PropertyType String -Force | Out-Null
            }
            catch [System.IO.IOException] {
                $skippedLocked++
                Write-Warn "Font file locked/in use, skipped: $($f.Name). Close Terminal/VS Code and retry."
            }
        }

        Write-Ok "Fonts installed: $installed"
        Write-Host "Skipped (already present): $skippedExisting" -ForegroundColor DarkGray
        if ($skippedLocked -gt 0) {
            Write-Warn "Skipped (locked): $skippedLocked"
        }
    }
    finally {
        Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-FiraCodeNerdFont {
    [CmdletBinding()]
    param(
        [ValidateSet("Winget", "Zip")]
        [string]$Method = "Winget",
        [string]$ReleaseTag = "v3.2.1"
    )

    if ($Method -eq "Zip") {
        Install-FiraCodeNerdFontZip -ReleaseTag $ReleaseTag

        if (Test-FiraCodeNerdFont) {
            Write-Ok "✅ FiraCode Nerd Font detected."
        }
        else {
            Write-Warn "Installed but not detected yet. Restart Windows Terminal/VS Code (or sign out/in)."
        }
        return
    }

    # Winget method
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warn "winget not found. Re-run with: Install-FiraCodeNerdFont -Method Zip"
        return
    }

    $candidateIds = @(
        "NerdFonts.FiraCode",
        "NerdFonts.FiraCode.NerdFont",
        "NerdFonts.FiraCodeNerdFont"
    )

    $id = $null
    foreach ($cid in $candidateIds) {
        winget show --id $cid --exact *> $null
        if ($LASTEXITCODE -eq 0) { $id = $cid; break }
    }

    if (-not $id) {
        Write-Info "Searching winget for FiraCode Nerd Font..."
        $search = winget search "FiraCode" 2>$null
        $line = ($search | Select-String -Pattern "NerdFonts\." | Select-Object -First 1).Line
        if ($line) {
            $parts = $line -split '\s{2,}'
            if ($parts.Count -ge 2) { $id = $parts[1] }
        }
    }

    if (-not $id) {
        Write-Warn "Could not find a NerdFonts package for FiraCode in winget. Re-run with: Install-FiraCodeNerdFont -Method Zip"
        return
    }

    Write-Info "Installing via winget: $id"
    winget install --id $id --exact --accept-source-agreements --accept-package-agreements

    if (Test-FiraCodeNerdFont) {
        Write-Ok "✅ FiraCode Nerd Font installed/detected."
    }
    else {
        Write-Warn "Installed, but not detected yet. Restart Windows Terminal/VS Code (or sign out/in)."
    }
}


function Test-FiraCodeNerdFont {
    [CmdletBinding()]
    param(
        [string[]]$NamePatterns = @(
            "*FiraCode*",
            "*Fira Code*",
            "*FiraCodeNerdFont*"
        )
    )

    # A) Check font files (fast and reliable)
    $fontDirs = @(
        (Join-Path $env:WINDIR "Fonts"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts")
    ) | Where-Object { Test-Path $_ }

    foreach ($dir in $fontDirs) {
        foreach ($pat in $NamePatterns) {
            $files = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like ($pat.Trim('*') + "*.ttf") -or $_.Name -like $pat }
            if ($files) {
                Set-ConfigValue -Key "FiraCodeInstalled" -Value "True"
                return $true
            }
        }
    }

    # B) Check registry (HKLM + HKCU, name and value)
    foreach ($pat in $NamePatterns) {
        $hits = Get-InstalledFont -NamePattern $pat
        if ($hits -and $hits.Count -gt 0) {
            Set-ConfigValue -Key "FiraCodeInstalled" -Value "True"
            return $true
        }
    }

    # C) Check installed font families (best signal when registry/file naming differs)
    if ($IsWindows) {
        try {
            Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue | Out-Null
            $fc = New-Object System.Drawing.Text.InstalledFontCollection
            $families = $fc.Families | ForEach-Object { $_.Name }

            foreach ($name in $families) {
                if ($name -match 'Fira\s*Code') {
                    Set-ConfigValue -Key "FiraCodeInstalled" -Value "True"
                    return $true
                }
            }
        }
        catch { }
    }

    Set-ConfigValue -Key "FiraCodeInstalled" -Value "False"
    Write-Warn "💭 FiraCode Nerd Font not detected. Run: Install-FiraCodeNerdFont"
    return $false
}


# ----------------------------
# Updates (keep non-blocking)
# ----------------------------
function Update-PowerShellIfNeeded {
    [CmdletBinding()]
    param()

    if (-not $script:CanConnectToGitHub) { return }

    try {
        # Put your existing Update-PowerShell logic here if desired.
        # IMPORTANT: do not make it noisy / blocking on profile load.
        return
    }
    catch {
        Write-Warn "PowerShell update check failed: $($_.Exception.Message)"
    }
}

# ----------------------------
# Quality-of-life functions (valid names)
# ----------------------------
function gitpush { git add .; git commit -m "update"; git push }
function grep { param($regex, $dir) if ($dir) { Get-ChildItem $dir | Select-String $regex } else { $input | Select-String $regex } }
function df { Get-Volume }
function sed { param($file, $find, $replace) (Get-Content $file -Raw).Replace("$find", $replace) | Set-Content $file }
function which { param($name) (Get-Command $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Definition) }
function export { param($name, $value) Set-Item -Force -Path "env:$name" -Value $value }
function pkill { param($name) Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -Force }
function pgrep { param($name) Get-Process $name -ErrorAction SilentlyContinue }

# Replace invalid cd... / cd.... with valid helpers
function cdup { param([int]$Levels = 1) for ($i = 0; $i -lt $Levels; $i++) { Set-Location .. } }
function cd2 { cdup 2 }
function cd3 { cdup 3 }

function md5 { Get-FileHash -Algorithm MD5    @args }
function sha1 { Get-FileHash -Algorithm SHA1   @args }
function sha256 { Get-FileHash -Algorithm SHA256 @args }
function n { notepad @args }
function vs { code @args }
function expl { explorer.exe @args }

function admin {
    if ($args.Count -gt 0) {
        $argList = "& '" + ($args -join " ") + "'"
        Start-Process "wt.exe" -Verb RunAs -ArgumentList $argList
    }
    else {
        Start-Process "wt.exe" -Verb RunAs
    }
}
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin

function sync-profile {
    clear-host
    @(
        $Profile.AllUsersAllHosts,
        $Profile.AllUsersCurrentHost,
        $Profile.CurrentUserAllHosts,
        $Profile.CurrentUserCurrentHost
    ) | ForEach-Object {
        if (Test-Path $_) { . $_ }
    }
}
Set-Alias -Name reload -Value sync-profile

# ----------------------------
# Profile entrypoint (fast + safe)
# ----------------------------
# Ensure config exists (non-noisy)
if (-not (Test-Path -Path $script:ConfigPath)) {
    Save-ProfileConfig -Config @{}
    Write-Warn "Config created: $script:ConfigPath"
}

# Load essentials (no install unless you opt-in later)
Initialize-DevEnv

# Non-blocking checks (no prompts)
Test-FiraCodeNerdFont | Out-Null

# Optional: keep your oh-my-posh init (don’t hard-fail)
if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
    try {
        oh-my-posh init pwsh --config 'https://raw.githubusercontent.com/IndianaHein/Config/main/montys.omp.json' | Invoke-Expression
    }
    catch {
        Write-Warn "oh-my-posh init failed: $($_.Exception.Message)"
    }
}

# If you still want background update checks, do it quietly:
Start-Job -ScriptBlock { Update-PowerShellIfNeeded } | Out-Null

# Winget CommandNotFound (quiet)
function Enable-WingetCommandNotFound {
    [CmdletBinding()]
    param(
        [switch]$Install
    )

    $moduleName = "Microsoft.WinGet.CommandNotFound"

    $moduleAvailable = [bool](Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue)
    if ($moduleAvailable) {
        Import-Module -Name $moduleName -ErrorAction SilentlyContinue | Out-Null
    }

    $moduleLoaded = [bool](Get-Module -Name $moduleName -ErrorAction SilentlyContinue)
    if (-not $moduleLoaded) {
        Write-Warn "💭 Optional: enable Winget CommandNotFound suggestions by installing/importing the module '$moduleName'."
        # If you want to offer install:
        # Write-Warn "Install: Install-Module $moduleName -Scope CurrentUser"
    }
}
# (Removed stray global Install-Module block that referenced undefined `$moduleName`.)


# VSCode-only prompt (ask once)
try {
    $key = "WingetCommandNotFoundPrompted"
    $prompted = (Get-ConfigValue -Key $key -Default "False")

    if ($prompted -ne "True") {
        $enabled = Enable-WingetCommandNotFound
        if (-not $enabled) {
            Write-Host "💭 Optional: install WingetCommandNotFound for better command suggestions." -ForegroundColor Yellow
            $answer = Read-Host "Install now? (y/n)"
            if ($answer -match '^(y|yes)$') {
                Enable-WingetCommandNotFound -Install | Out-Null
            }
        }

        Set-ConfigValue -Key $key -Value "True"
    }
    else {
        # If already prompted, just try to import quietly (no prompts)
        Enable-WingetCommandNotFound | Out-Null
    }
}
catch {
    # Never break VSCode profile on this feature
}

Import-Module -Name Microsoft.WinGet.CommandNotFound -ErrorAction SilentlyContinue | Out-Null
if (-not $?) { Write-Warn "💭 Optional: install WingetCommandNotFound (PowerToys) if you want command suggestions." }
