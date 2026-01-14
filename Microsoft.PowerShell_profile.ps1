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
    param(
        [string]$NamePattern = "*"
    )

    try {
        $fontsKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
        if (-not (Test-Path $fontsKey)) { return @() }

        $item = Get-ItemProperty -Path $fontsKey

        # Enumerate value names under the key (these are the font display names)
        $item.PSObject.Properties |
        Where-Object {
            $_.MemberType -eq 'NoteProperty' -and
            $_.Name -like $NamePattern
        } |
        ForEach-Object { $_.Name }
    }
    catch {
        @()
    }
}



function Install-FiraCodeNerdFont {
    [CmdletBinding()]
    param()

    if (-not $script:CanConnectToGitHub) {
        Write-Warn "❌ Skipping font install: github.com not reachable."
        return
    }

    # Keep your old implementation idea, but do NOT call it automatically here.
    Write-Warn "Not implemented here: reuse your existing zip-download logic if you want."
    Write-Warn "Tip: easiest route is Nerd Fonts installer or winget/choco."
}

function Test-FiraCodeNerdFont {
    $fira = Get-InstalledFont -NamePattern "*FiraCode*"
    if ($fira) {
        Set-ConfigValue -Key "FiraCodeInstalled" -Value "True"
        return $true
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
Import-Module -Name Microsoft.WinGet.CommandNotFound -ErrorAction SilentlyContinue | Out-Null
if (-not $?) { Write-Warn "💭 Optional: install WingetCommandNotFound (PowerToys) if you want command suggestions." }
