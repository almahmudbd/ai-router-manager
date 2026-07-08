param(
    [switch]$List,
    [string]$Activate,
    [string]$Add,
    [string]$Delete,
    [switch]$Gen
)

$SettingsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DbFile      = Join-Path $SettingsDir "prov-lists.json"
$MainFile    = Join-Path $SettingsDir "settings.json"

Add-Type -AssemblyName System.Web.Extensions
$JsonSer = [System.Web.Script.Serialization.JavaScriptSerializer]::new()
$JsonSer.MaxJsonLength = 0x1000000

function Read-Db {
    if (Test-Path $DbFile) {
        $text = Get-Content $DbFile -Raw -Encoding UTF8
        return $JsonSer.DeserializeObject($text)
    }
    return $null
}

function Write-Db($db) {
    $lines = @()
    $lines += "{"
    $lines += '  "active": "' + $db["active"] + '",'
    $lines += '  "providers": {'
    $keys = @($db["providers"].Keys)
    for ($i = 0; $i -lt $keys.Count; $i++) {
        $name = $keys[$i]
        $entry = $db["providers"][$name]
        $comma = if ($i -lt $keys.Count - 1) { "," } else { "" }
        $lines += '    "' + $name + '": {'
        $props = @()
        $props += '"apiKey": "' + $entry["apiKey"] + '"'
        $props += '"baseUrl": "' + $entry["baseUrl"] + '"'
        if ($entry["model"]) { $props += '"model": "' + $entry["model"] + '"' }
        $lines += '      ' + ($props -join (",
      "))
        $lines += '    }' + $comma
    }
    $lines += "  }"
    $lines += "}"
    $content = $lines -join "
"
    [System.IO.File]::WriteAllText($DbFile, $content, [System.Text.UTF8Encoding]::new($false))
}

function Get-Providers($db) {
    if (-not $db) { return @() }
    $result = @()
    $db["providers"].Keys | ForEach-Object {
        $name = $_
        $val = $db["providers"][$_]
        $result += [PSCustomObject]@{
            Name    = $name
            Active  = ($name -eq $db["active"])
            BaseUrl = $val["baseUrl"]
            Model   = if ($val["model"]) { $val["model"] } else { "(default)" }
        }
    }
    $result | Sort-Object { -$_.Active }
}

function Generate-Settings($db) {
    if (-not $db) { Write-Host "No database." -ForegroundColor Red; return }
    $name = $db["active"]
    if (-not $name -or -not $db["providers"][$name]) { Write-Host "No active provider." -ForegroundColor Red; return }
    $prov = $db["providers"][$name]
    $key  = $prov["apiKey"]
    $url  = $prov["baseUrl"]
    $model = $prov["model"]

    $lines = @()
    $lines += "{"
    $lines += '  "apiKeyHelper": "echo ''' + $key + '''",'
    $lines += '  "env": {'
    $lines += '    "ANTHROPIC_API_KEY": "' + $key + '",'
    $lines += '    "ANTHROPIC_BASE_URL": "' + $url + '",'
    $lines += '    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"'
    if ($model) {
        $lines[-1] += ","
        $lines += '    "ANTHROPIC_MODEL": "' + $model + '"'
    }
    $lines += '  },'
    $lines += '  "permissions": {'
    $lines += '    "allow": [],'
    $lines += '    "deny": [],'
    $lines += '    "defaultMode": "default"'
    $lines += '  },'
    $lines += '  "theme": "dark",'
    $lines += '  "effortLevel": "high"'
    $lines += "}"
    $content = $lines -join "
"
    [System.IO.File]::WriteAllText($MainFile, $content, [System.Text.UTF8Encoding]::new($false))
    Write-Host "settings.json generated for: $name" -ForegroundColor Green
}

function Activate-Provider($db, $name) {
    if (-not $db["providers"].ContainsKey($name)) { Write-Host "Not found: $name" -ForegroundColor Red; return $db }
    $db["active"] = $name
    Write-Db $db
    Generate-Settings $db
    Write-Host "Activated: $name" -ForegroundColor Green
    return $db
}

function Add-Provider($db, $name) {
    if ($db -and $db["providers"].ContainsKey($name)) { Write-Host "Already exists: $name" -ForegroundColor Red; return $db }
    Write-Host "
=== Adding: $name ===" -ForegroundColor Cyan
    $baseUrl = Read-Host "ANTHROPIC_BASE_URL"
    $apiKey  = Read-Host "ANTHROPIC_API_KEY"
    $model   = Read-Host "ANTHROPIC_MODEL (or empty)"
    $entry = @{ apiKey = $apiKey; baseUrl = $baseUrl }
    if ($model) { $entry["model"] = $model }
    if (-not $db) { $db = @{ active = ""; providers = @{} } }
    $db["providers"][$name] = $entry
    Write-Db $db
    Write-Host "Added: $name" -ForegroundColor Green
    Write-Host "[not activated - use Activate to switch]" -ForegroundColor Gray
    return $db
}

function Delete-Provider($db, $name) {
    if (-not $db["providers"].ContainsKey($name)) { Write-Host "Not found: $name" -ForegroundColor Red; return $db }
    Write-Host "Delete '$name'?" -ForegroundColor Yellow
    $c = Read-Host "Type 'yes' to confirm"
    if ($c -ne "yes") { Write-Host "Cancelled."; return $db }
    $db["providers"].Remove($name)
    if ($db["active"] -eq $name) {
        $remaining = @($db["providers"].Keys)
        $db["active"] = if ($remaining.Count -gt 0) { $remaining[0] } else { "" }
    }
    Write-Db $db
    if ($db["active"]) { Generate-Settings $db }
    Write-Host "Deleted: $name" -ForegroundColor Green
    return $db
}

function Import-Backups {
    $files = @()
    try { $files = Get-ChildItem $SettingsDir -Filter "settings - *.json" -ErrorAction Stop } catch { return $null }
    if ($files.Count -eq 0) { return $null }
    $providers = @{}
    $activeName = ""
    $mainUrl = ""
    if (Test-Path $MainFile) {
        $mainText = Get-Content $MainFile -Raw -Encoding UTF8
        try { $mainData = $JsonSer.DeserializeObject($mainText); $mainUrl = $mainData["env"]["ANTHROPIC_BASE_URL"] } catch {}
    }
    foreach ($f in $files) {
        $name = $f.BaseName -replace "^settings - ", ""
        $text = Get-Content $f.FullName -Raw -Encoding UTF8
        $data = $JsonSer.DeserializeObject($text)
        $env = $data["env"]
        $entry = @{ apiKey = $env["ANTHROPIC_API_KEY"]; baseUrl = $env["ANTHROPIC_BASE_URL"] }
        if ($env["ANTHROPIC_MODEL"]) { $entry["model"] = $env["ANTHROPIC_MODEL"] }
        $providers[$name] = $entry
        if ($mainUrl -and $env["ANTHROPIC_BASE_URL"] -eq $mainUrl) { $activeName = $name }
    }
    if (-not $activeName -and $providers.Keys.Count -gt 0) { $activeName = @($providers.Keys)[0] }
    return @{ active = $activeName; providers = $providers }
}

function Show-Menu {
    Clear-Host
    Write-Host "=====" -ForegroundColor Cyan
    Write-Host "  Claude Settings Provider Manager" -ForegroundColor Cyan
    Write-Host "=====" -ForegroundColor Cyan
    $db = Ensure-Db
    $providers = Get-Providers $db
    if ($providers.Count -eq 0) {
        Write-Host "
(no providers yet)" -ForegroundColor Gray
        Write-Host "[A] Add first provider"
        Write-Host "[Q] Quit"
        $c = Read-Host "Choose"
        if ($c -eq 'A' -or $c -eq 'a') { $n = Read-Host "Name"; $db = Add-Provider $db $n }
        Read-Host "
Press Enter"; Show-Menu; return
    }
    Write-Host "
Providers:" -ForegroundColor Yellow
    Write-Host "----"
    $i = 1
    $providers | ForEach-Object {
        $mark = if ($_.Active) { " [ACTIVE]" } else { "" }
        Write-Host "$i. $($_.Name) $mark" -ForegroundColor $(if ($_.Active) { "Green" } else { "White" })
        Write-Host "   URL : $($_.BaseUrl)"
        Write-Host "   Model: $($_.Model)"
        $i++
    }
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  [1-$($providers.Count)] Activate"
    Write-Host "  [A] Add new"
    Write-Host "  [D] Delete"
    Write-Host "  [G] Regenerate settings.json"
    Write-Host "  [R] Refresh"
    Write-Host "  [Q] Quit"
    Write-Host ""
    $choice = Read-Host "Choose"
    switch -Wildcard ($choice) {
        'Q' { exit }
        'A' { $n = Read-Host "Name"; $db = Add-Provider $db $n }
        'D' { $num = Read-Host "Number to delete"; $idx = [int]$num - 1
              if ($idx -ge 0 -and $idx -lt $providers.Count) { $db = Delete-Provider $db $providers[$idx].Name }
              else { Write-Host "Invalid!" -ForegroundColor Red } }
        'G' { Generate-Settings $db }
        'R' { }
        default { $num = [int]$choice; $idx = $num - 1
              if ($idx -ge 0 -and $idx -lt $providers.Count) { $db = Activate-Provider $db $providers[$idx].Name }
              else { Write-Host "Invalid!" -ForegroundColor Red } }
    }
    Read-Host "
Press Enter"
    Show-Menu
}

function Ensure-Db {
    $db = Read-Db
    if (-not $db) {
        $db = Import-Backups
        if ($db) { Write-Db $db; Write-Host "Imported $($db.providers.Keys.Count) providers." -ForegroundColor Green }
    }
    return $db
}

if ($List) {
    $db = Ensure-Db
    if (-not $db) { Write-Host "No database."; exit }
    Get-Providers $db | Format-Table Name, Active, BaseUrl, Model -AutoSize
    exit
}
if ($Add) {
    $db = Ensure-Db
    Add-Provider $db $Add
    exit
}
if ($Delete) {
    $db = Ensure-Db
    if (-not $db) { Write-Host "No database."; exit }
    Delete-Provider $db $Delete
    exit
}
if ($Activate) {
    $db = Ensure-Db
    if (-not $db) { Write-Host "No database."; exit }
    Activate-Provider $db $Activate
    exit
}
if ($Gen) {
    $db = Ensure-Db
    Generate-Settings $db
    exit
}

Show-Menu