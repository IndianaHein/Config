#  Optimized PowerShell profile (pwsh)
#    - Fast startup (no Read-Host prompts)
#    - Safe installs: opt-in via -Install switch
#    - Resilient config handling (YAML if available, fallback parser if not)
#    - Fixes invalid function names (cd... / cd....)
#    - PERF: oh-my-posh loads from local cache (not GitHub on every launch)
#    - PERF: Module presence trusted from config cache (skips Get-Module -ListAvailable)
#    - PERF: FiraCode font scan skipped when already confirmed installed
#    - PERF: Start-ThreadJob used instead of Start-Job
#    - PERF: Config file reads cached in-memory for the session

Write-Host ""
Write-Host "Welcome Hein ⚡" -ForegroundColor DarkCyan
Write-Host ""

# ----------------------------
# Helpers
# ----------------------------
function Write-Info { param([string]$Message) Write-Host $Message -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host $Message -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host $Message -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host $Message -ForegroundColor Red }

function Test-GitHubReachable {
    [CmdletBinding()]
    param([int]$TimeoutSeconds = 1)
    try {
        return [bool](Test-Connection -ComputerName "github.com" -Count 1 -Quiet -TimeoutSeconds $TimeoutSeconds -ErrorAction Stop)
    }
    catch {
        try { return [bool](Test-Connection -ComputerName "github.com" -Count 1 -Quiet -ErrorAction Stop) } catch { return $false }
    }
}

$script:CanConnectToGitHub = Test-GitHubReachable

$IsInteractive = -not ($Host.Name -in @('ServerRemoteHost', 'ConsoleHost'))

$script:ProfileDir  = Split-Path -Parent $PROFILE
$script:ConfigPath  = Join-Path $script:ProfileDir "pwsh_custom_config.yml"
$script:OmpConfig   = Join-Path $script:ProfileDir "montys.omp.json"

# ----------------------------
# Config (YAML w/ fallback) — in-memory cached
# ----------------------------
$script:ConfigCache = $null   # PERF: cache parsed config for the session

function Get-ProfileConfig {
    [CmdletBinding()]
    param()

    # PERF: return cached copy if already loaded
    if ($null -ne $script:ConfigCache) { return $script:ConfigCache }

    if (-not (Test-Path -Path $script:ConfigPath)) {
        $script:ConfigCache = @{}
        return $script:ConfigCache
    }

    $raw = Get-Content -Path $script:ConfigPath -Raw -ErrorAction SilentlyContinue
    if (-not $raw) {
        $script:ConfigCache = @{}
        return $script:ConfigCache
    }

    if (Get-Command -Name ConvertFrom-Yaml -ErrorAction SilentlyContinue) {
        try {
            $cfg = $raw | ConvertFrom-Yaml
            if ($cfg -is [hashtable]) {
                $script:ConfigCache = $cfg
                return $script:ConfigCache
            }
            $ht = @{}
            $cfg.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }
            $script:ConfigCache = $ht
            return $script:ConfigCache
        }
        catch {
            $script:ConfigCache = @{}
            return $script:ConfigCache
        }
    }

    # Minimal fallback: parse simple "key: value" lines
    $cfg2 = @{}
    foreach ($line in ($raw -split "(`r`n|`n)")) {
        if ($line -match '^\s*#')  { continue }
        if ($line -match '^\s*$')  { continue }
        if ($line -match '^\s*([^:]+?)\s*:\s*(.*?)\s*$') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim().Trim('"')
            $cfg2[$key] = $val
        }
    }
    $script:ConfigCache = $cfg2
    return $script:ConfigCache
}

function Save-ProfileConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)

    if (-not (Test-Path -Path $script:ProfileDir)) {
        New-Item -ItemType Directory -Path $script:ProfileDir -Force | Out-Null
    }

    # PERF: keep cache in sync so subsequent reads don't hit disk
    $script:ConfigCache = $Config

    if (Get-Command -Name ConvertTo-Yaml -ErrorAction SilentlyContinue) {
        $Config | ConvertTo-Yaml | Set-Content -Path $script:ConfigPath -Encoding UTF8
        return
    }

    $out = foreach ($k in ($Config.Keys | Sort-Object)) {
        $v = $Config[$k]
        if ($null -eq $v)        { "${k}: " }
        elseif ($v -match '\s')  { "${k}: `"$v`"" }
        else                     { "${k}: $v" }
    }
    $out -join "`n" | Set-Content -Path $script:ConfigPath -Encoding UTF8
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
    param([switch]$Install)

    if (-not $script:CanConnectToGitHub) {
        Write-Warn "❌ Skipping DevEnv initialization: github.com not reachable."
        return
    }

    $modules = @(
        @{ Name = "Terminal-Icons";    ConfigKey = "TerminalIconsInstalled" },
        @{ Name = "powershell-yaml";   ConfigKey = "PowerShellYamlInstalled" },
        @{ Name = "PoshFunctions";     ConfigKey = "PoshFunctionsInstalled" }
    )

    foreach ($m in $modules) {
        $isInstalled = (Get-ConfigValue -Key $m.ConfigKey -Default "False") -eq "True"

        if ($isInstalled) {
            # PERF: config says it's present — skip slow Get-Module -ListAvailable
            Import-Module $m.Name -ErrorAction SilentlyContinue
            Write-Ok "✅ Module loaded: $($m.Name)"
            continue
        }

        # Config doesn't confirm it yet — do the (slower) check once
        $cmd = Get-Module -ListAvailable -Name $m.Name

        if ($cmd) {
            Import-Module $m.Name -ErrorAction SilentlyContinue
            Set-ConfigValue -Key $m.ConfigKey -Value "True"
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
    param([string]$NamePattern = "*")

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
                if ($prop.Name -like "PS*") { continue }
                if ($prop.Name -like $NamePattern)  { [void]$results.Add($prop.Name) }
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
    param([string]$ReleaseTag = "v3.2.1")

    $zipUrl     = "https://github.com/ryanoasis/nerd-fonts/releases/download/$ReleaseTag/FiraCode.zip"
    $tempZip    = Join-Path $env:TEMP "FiraCode.NerdFont.zip"
    $tempDir    = Join-Path $env:TEMP ("FiraCodeNerdFont_" + [guid]::NewGuid().ToString("N"))
    $userFontsDir  = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"
    $hkcuFontsKey  = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"

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

        $installed = $skippedExisting = $skippedLocked = 0

        foreach ($f in $ttfs) {
            $dest = Join-Path $userFontsDir $f.Name
            if (Test-Path $dest) { $skippedExisting++; continue }
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
        if ($skippedLocked -gt 0) { Write-Warn "Skipped (locked): $skippedLocked" }
    }
    finally {
        Remove-Item -Path $tempZip  -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $tempDir  -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-FiraCodeNerdFont {
    [CmdletBinding()]
    param(
        [ValidateSet("Winget","Zip")][string]$Method = "Winget",
        [string]$ReleaseTag = "v3.2.1"
    )

    if ($Method -eq "Zip") {
        Install-FiraCodeNerdFontZip -ReleaseTag $ReleaseTag
        if (Test-FiraCodeNerdFont) { Write-Ok "✅ FiraCode Nerd Font detected." }
        else { Write-Warn "Installed but not detected yet. Restart Windows Terminal/VS Code (or sign out/in)." }
        return
    }

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warn "winget not found. Re-run with: Install-FiraCodeNerdFont -Method Zip"
        return
    }

    $candidateIds = @("NerdFonts.FiraCode","NerdFonts.FiraCode.NerdFont","NerdFonts.FiraCodeNerdFont")
    $id = $null
    foreach ($cid in $candidateIds) {
        winget show --id $cid --exact *> $null
        if ($LASTEXITCODE -eq 0) { $id = $cid; break }
    }

    if (-not $id) {
        Write-Info "Searching winget for FiraCode Nerd Font..."
        $search = winget search "FiraCode" 2>$null
        $line   = ($search | Select-String -Pattern "NerdFonts\." | Select-Object -First 1).Line
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

    if (Test-FiraCodeNerdFont) { Write-Ok "✅ FiraCode Nerd Font installed/detected." }
    else { Write-Warn "Installed, but not detected yet. Restart Windows Terminal/VS Code (or sign out/in)." }
}

function Test-FiraCodeNerdFont {
    [CmdletBinding()]
    param(
        [string[]]$NamePatterns = @("*FiraCode*","*Fira Code*","*FiraCodeNerdFont*")
    )

    $fontDirs = @(
        (Join-Path $env:WINDIR "Fonts"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts")
    ) | Where-Object { Test-Path $_ }

    foreach ($dir in $fontDirs) {
        foreach ($pat in $NamePatterns) {
            $files = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -like ($pat.Trim('*') + "*.ttf") -or $_.Name -like $pat }
            if ($files) { Set-ConfigValue -Key "FiraCodeInstalled" -Value "True"; return $true }
        }
    }

    foreach ($pat in $NamePatterns) {
        $hits = Get-InstalledFont -NamePattern $pat
        if ($hits -and $hits.Count -gt 0) { Set-ConfigValue -Key "FiraCodeInstalled" -Value "True"; return $true }
    }

    if ($IsWindows) {
        try {
            Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue | Out-Null
            $fc       = New-Object System.Drawing.Text.InstalledFontCollection
            $families = $fc.Families | ForEach-Object { $_.Name }
            foreach ($name in $families) {
                if ($name -match 'Fira\s*Code') { Set-ConfigValue -Key "FiraCodeInstalled" -Value "True"; return $true }
            }
        }
        catch { }
    }

    Set-ConfigValue -Key "FiraCodeInstalled" -Value "False"
    Write-Warn "💭 FiraCode Nerd Font not detected. Run: Install-FiraCodeNerdFont"
    return $false
}

# ----------------------------
# oh-my-posh theme management
# PERF: theme is cached locally — no GitHub fetch on every launch
# ----------------------------
function Update-OmpTheme {
    <#
    .SYNOPSIS
        Download the latest oh-my-posh theme from GitHub and cache it locally.
        Run this manually whenever you update your theme. Not called on profile load.
    #>
    [CmdletBinding()]
    param(
        [string]$Uri = 'https://raw.githubusercontent.com/IndianaHein/Config/main/montys.omp.json'
    )

    if (-not $script:CanConnectToGitHub) {
        Write-Warn "❌ Cannot reach GitHub. Theme not updated."
        return
    }

    try {
        Invoke-WebRequest -Uri $Uri -OutFile $script:OmpConfig -UseBasicParsing -ErrorAction Stop
        Write-Ok "✅ oh-my-posh theme updated: $script:OmpConfig"
    }
    catch {
        Write-Err "❌ Failed to download theme: $($_.Exception.Message)"
    }
}

# ----------------------------
# Updates (keep non-blocking)
# ----------------------------
function Update-PowerShellIfNeeded {
    [CmdletBinding()]
    param()
    if (-not $script:CanConnectToGitHub) { return }
    try { return } catch { Write-Warn "PowerShell update check failed: $($_.Exception.Message)" }
}

# ----------------------------
# Quality-of-life functions
# ----------------------------
function gitpush { git add .; git commit -m "update"; git push }
function grep    { param($regex, $dir) if ($dir) { Get-ChildItem $dir | Select-String $regex } else { $input | Select-String $regex } }
function df      { Get-Volume }
function sed     { param($file, $find, $replace) (Get-Content $file -Raw).Replace("$find", $replace) | Set-Content $file }
function which   { param($name) (Get-Command $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Definition) }
function export  { param($name, $value) Set-Item -Force -Path "env:$name" -Value $value }
function pkill   { param($name) Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -Force }
function pgrep   { param($name) Get-Process $name -ErrorAction SilentlyContinue }

function cdup { param([int]$Levels = 1) for ($i = 0; $i -lt $Levels; $i++) { Set-Location .. } }
function cd2  { cdup 2 }
function cd3  { cdup 3 }

function md5    { Get-FileHash -Algorithm MD5    @args }
function sha1   { Get-FileHash -Algorithm SHA1   @args }
function sha256 { Get-FileHash -Algorithm SHA256 @args }
function n      { notepad @args }
function vs     { code @args }
function expl   { explorer.exe @args }

function admin {
    if ($args.Count -gt 0) {
        $argList = "& '" + ($args -join " ") + "'"
        Start-Process "wt.exe" -Verb RunAs -ArgumentList $argList
    }
    else { Start-Process "wt.exe" -Verb RunAs }
}
Set-Alias -Name su   -Value admin
Set-Alias -Name sudo -Value admin

function sync-profile {
    Clear-Host
    @(
        $Profile.AllUsersAllHosts,
        $Profile.AllUsersCurrentHost,
        $Profile.CurrentUserAllHosts,
        $Profile.CurrentUserCurrentHost
    ) | ForEach-Object { if (Test-Path $_) { . $_ } }
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

# PERF: only run the full font scan if we don't already know the answer
if ((Get-ConfigValue -Key "FiraCodeInstalled" -Default "False") -ne "True") {
    Test-FiraCodeNerdFont | Out-Null
}

# oh-my-posh: PERF: load from local cached theme file (run Update-OmpTheme to refresh)
if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {
    if (-not (Test-Path $script:OmpConfig)) {
        Write-Warn "💭 oh-my-posh theme not cached locally. Run: Update-OmpTheme"
    }
    else {
        try {
            oh-my-posh init pwsh --config $script:OmpConfig | Invoke-Expression
        }
        catch {
            Write-Warn "oh-my-posh init failed: $($_.Exception.Message)"
        }
    }
}

# PERF: Start-ThreadJob is much lighter than Start-Job
Start-ThreadJob -ScriptBlock { Update-PowerShellIfNeeded } | Out-Null

# Winget CommandNotFound (quiet)
function Enable-WingetCommandNotFound {
    [CmdletBinding()]
    param([switch]$PromptOnce, [switch]$Install)

    $moduleName = "Microsoft.WinGet.CommandNotFound"

    $available = Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue |
                 Sort-Object Version -Descending |
                 Select-Object -First 1

    if ($available) {
        try { Import-Module -Name $moduleName -ErrorAction Stop | Out-Null } catch { }
    }

    $loaded = [bool](Get-Module -Name $moduleName -ErrorAction SilentlyContinue)
    if ($loaded) { return $true }

    if ($Install) {
        try {
            Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Import-Module -Name $moduleName -ErrorAction SilentlyContinue | Out-Null
            $loaded = [bool](Get-Module -Name $moduleName -ErrorAction SilentlyContinue)
            if ($loaded) { return $true }
        }
        catch { Write-Warn ("❌ Failed to install {0}: {1}" -f $moduleName, $_.Exception.Message) }
    }

    if ($PromptOnce) {
        $key      = "WingetCommandNotFoundPrompted"
        $prompted = Get-ConfigValue -Key $key -Default "False"
        if ($prompted -ne "True") {
            Write-Warn ("💭 Optional: enable Winget CommandNotFound suggestions by installing/importing '{0}'." -f $moduleName)
            Write-Host ("Install: Install-Module {0} -Scope CurrentUser" -f $moduleName) -ForegroundColor DarkGray
            Set-ConfigValue -Key $key -Value "True"
        }
    }

    return $false
}
Import-Module -Name Microsoft.WinGet.CommandNotFound -ErrorAction SilentlyContinue | Out-Null
if (-not $?) { Write-Warn "💭 Optional: install WingetCommandNotFound (PowerToys) if you want command suggestions." }
