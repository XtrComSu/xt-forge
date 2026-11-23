# XT-Forge Windows Installer (PowerShell 5.1+ / PowerShell 7+)
# Local repo : .\install.ps1
# Remote one-liner:
#   irm https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

# Name the failing command and stop; never continue silently after an error.
trap {
    $FailedLine = if ($_.InvocationInfo -and $_.InvocationInfo.Line) { $_.InvocationInfo.Line.Trim() } else { "(unknown command)" }
    Write-Host "[xt-forge] Failed command: $FailedLine -- $($_.Exception.Message)"
    $LASTEXITCODE = 1
    break
}

function Assert-LastCommand {
    param([string]$Command)
    if ($LASTEXITCODE -ne 0) {
        throw "[xt-forge] Failed command (exit code $LASTEXITCODE): $Command"
    }
}

$RepoUrl = if ($env:XT_REPO_URL) { $env:XT_REPO_URL } else { "https://github.com/XtrComSu/xt-forge.git" }
$Branch  = if ($env:XT_BRANCH) { $env:XT_BRANCH } else { "main" }

# Validate the interpreter the launcher will use BEFORE installing anything.
$PythonExe = $env:XT_PYTHON
$PythonPrefix = @()
if ([string]::IsNullOrWhiteSpace($PythonExe)) {
    foreach ($candidate in @("python", "python3", "py")) {
        $found = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($found) {
            $PythonExe = $found.Source
            if ($candidate -eq "py") { $PythonPrefix = @("-3") }
            break
        }
    }
}
if (-not $PythonExe) {
    throw "[xt-forge] Python 3.11+ is required, but no Python interpreter was found. Install Python 3.11 or newer (or set XT_PYTHON) before running this installer."
}
$PythonVersionExpr = "import sys; print('%d.%d.%d' % sys.version_info[:3])"
$PythonVersionCommand = "& `"$PythonExe`" -c `"$PythonVersionExpr`""
try {
    $PythonVersionText = (& $PythonExe @PythonPrefix -c $PythonVersionExpr 2>&1 | Out-String).Trim()
} catch {
    throw "[xt-forge] Failed command: $PythonVersionCommand -- $_"
}
Assert-LastCommand $PythonVersionCommand
if ($PythonVersionText -notmatch '(\d+)\.(\d+)\.(\d+)') {
    throw "[xt-forge] Could not determine the Python version from: $PythonVersionCommand (output: $PythonVersionText)"
}
$FoundPythonVersion = [version]$Matches[0]
if ($FoundPythonVersion -lt [version]'3.11') {
    throw "[xt-forge] Python 3.11+ is required; found Python $PythonVersionText at `"$PythonExe`". Upgrade Python (or set XT_PYTHON) before installing."
}
Write-Host "[xt-forge] Python check: $PythonVersionText at $PythonExe"

$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not (Test-Path (Join-Path $ScriptRoot "bin\xtforge.cmd")) -or -not (Test-Path (Join-Path $ScriptRoot "VERSION"))) {
    $TargetSrc = Join-Path $env:USERPROFILE ".xt-forge-src"
    if (Test-Path (Join-Path $TargetSrc ".git")) {
        Write-Host "[xt-forge] Updating existing source checkout at $TargetSrc..."
        git -C "$TargetSrc" fetch --depth 1 origin $Branch | Out-Null
        Assert-LastCommand "git -C `"$TargetSrc`" fetch --depth 1 origin $Branch"
        git -C "$TargetSrc" checkout $Branch | Out-Null
        Assert-LastCommand "git -C `"$TargetSrc`" checkout $Branch"
        # `reset --hard` discards uncommitted work. This is an installer, not a
        # checkout manager, so someone who edited files under $TargetSrc must not
        # lose them to a convenience update. Refuse unless they opt in.
        $dirty = git -C "$TargetSrc" status --porcelain
        if ($dirty -and $env:XT_FORCE_RESET -ne "1") {
            Write-Host "[xt-forge] ERROR: $TargetSrc has local changes; refusing to discard them." -ForegroundColor Red
            $dirty | ForEach-Object { Write-Host "  $_" }
            Write-Host "[xt-forge] Commit or stash them, or re-run with `$env:XT_FORCE_RESET = 1 to discard."
            exit 1
        }
        if ($dirty) {
            Write-Host "[xt-forge] XT_FORCE_RESET=1: discarding local changes in $TargetSrc." -ForegroundColor Yellow
        }
        git -C "$TargetSrc" reset --hard "origin/$Branch" | Out-Null
        Assert-LastCommand "git -C `"$TargetSrc`" reset --hard `"origin/$Branch`""
    } else {
        Write-Host "[xt-forge] Cloning xt-forge ($Branch) to $TargetSrc..."
        git clone --depth 1 --branch $Branch $RepoUrl "$TargetSrc"
        Assert-LastCommand "git clone --depth 1 --branch $Branch $RepoUrl `"$TargetSrc`""
    }
    $ScriptRoot = $TargetSrc
}

Write-Host "[xt-forge] Installing from $ScriptRoot (Windows)"

if ((Get-Command cargo -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $ScriptRoot "native\xtforge-rs\Cargo.toml"))) {
    Write-Host "[xt-forge] Building Rust native core (native\xtforge-rs)..."
    Push-Location (Join-Path $ScriptRoot "native\xtforge-rs")
    cargo build --release --quiet
    Assert-LastCommand "cargo build --release --quiet"
    Pop-Location
}

if ((Get-Command go -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $ScriptRoot "native\xtforge-go\go.mod"))) {
    Write-Host "[xt-forge] Building Go service hub (native\xtforge-go)..."
    Push-Location (Join-Path $ScriptRoot "native\xtforge-go")
    go build -ldflags="-s -w" -o xtforge-hub.exe ./cmd/xtforge-hub
    Assert-LastCommand "go build -ldflags=`"-s -w`" -o xtforge-hub.exe ./cmd/xtforge-hub"
    Pop-Location
}

$LocalBin = Join-Path $env:USERPROFILE ".local\bin"
New-Item -ItemType Directory -Force -Path "$LocalBin" | Out-Null

if (Get-Command node -ErrorAction SilentlyContinue) {
    $NpxLauncher = Join-Path $ScriptRoot "bin\npx-xtforge.mjs"
    node "$NpxLauncher" init --quiet
    Assert-LastCommand "node `"$NpxLauncher`" init --quiet"
} else {
    $CmdLauncher = Join-Path $ScriptRoot "bin\xtforge.cmd"
    foreach ($alias in @("xt-forge.cmd", "xtforge.cmd", "xtf.cmd")) {
        $shimPath = Join-Path $LocalBin $alias
        # UTF-8 without BOM plus chcp 65001 keeps spaces and non-ASCII paths intact in cmd.exe.
        $ShimBody = "@echo off`r`nchcp 65001 >nul`r`n`"$CmdLauncher`" %*`r`n"
        [System.IO.File]::WriteAllText("$shimPath", $ShimBody, (New-Object System.Text.UTF8Encoding($false)))
    }

    $SkillsSrc = Join-Path $ScriptRoot "skills"
    $SkillTargets = @(
        (Join-Path $env:USERPROFILE ".agents\skills"),
        (Join-Path $env:USERPROFILE ".dsh\skills"),
        (Join-Path $env:USERPROFILE ".config\opencode\skills"),
        (Join-Path $env:USERPROFILE ".claude\skills")
    )
    $LegacySkills = @(
        "XTF-Pulse", "XTF-Compass", "XTF-Spark", "XTF-Shield", "XTF-Lumen", "XTF-Gage",
        "XTF-Vise", "XTF-Trace", "XTF-Beacon", "XTF-Anvil", "XTF-Sliver", "XTF-Chisel",
        "XTF-Wraith", "XTF-Cipher", "XTF-Cartographer", "XTF-Scalpel", "XTF-Sentinel", "XTF-Crucible"
    )
    foreach ($dst in $SkillTargets) {
        New-Item -ItemType Directory -Force -Path "$dst" | Out-Null
        foreach ($legacy in $LegacySkills) {
            $oldPath = Join-Path $dst $legacy
            if (Test-Path "$oldPath") { Remove-Item -Path "$oldPath" -Recurse -Force -ErrorAction SilentlyContinue }
        }
        foreach ($tier in @("simple", "complex", "advanced")) {
            $tierDir = Join-Path $SkillsSrc $tier
            if (Test-Path "$tierDir") {
                Get-ChildItem -Path "$tierDir" -Directory -Filter "XTF-*" | ForEach-Object {
                    Copy-Item -Path "$($_.FullName)" -Destination "$dst" -Recurse -Force
                }
            }
        }
    }

    foreach ($pair in @(
        @{ dir = (Join-Path $env:USERPROFILE ".dsh\commands"); body = "---`ndescription: Run xt-forge natively (/xtf --meta, /xtf re checksec, /xtf intel cve, /xtf code graph)`n---`nExecute ``xt-forge `$ARGUMENTS`` cleanly. If ``$ARGUMENTS`` is ``--meta``, inspect or run ``xt-forge --meta``.`n" },
        @{ dir = (Join-Path $env:USERPROFILE ".claude\commands"); body = "---`ndescription: Run xt-forge natively (/xtf --meta, /xtf re checksec, /xtf intel cve)`n---`nRun ``xt-forge `$ARGUMENTS`` and present crisp findings.`n" }
    )) {
        $CommandDir = $pair.dir
        New-Item -ItemType Directory -Force -Path "$CommandDir" | Out-Null
        $CommandFile = Join-Path $CommandDir "xtf.md"
        Set-Content -Path "$CommandFile" -Value $pair.body -Encoding UTF8
    }
}

# Verify the installed launcher BEFORE persisting anything to the user PATH.
Write-Host "[xt-forge] Verifying install..."
& "$LocalBin\xt-forge.cmd" version --json
if ($LASTEXITCODE -ne 0) {
    throw "[xt-forge] Install verification failed (exit code $LASTEXITCODE); PATH was not modified. Failing command: & `"$LocalBin\xt-forge.cmd`" version --json"
}

# Idempotent PATH update: keep every existing entry exactly as it was.
$UserPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if (-not $UserPath) { $UserPath = "" }
$Parts = $UserPath -split ";"
if ($Parts -notcontains $LocalBin) {
    $Separator = if ($UserPath -and -not $UserPath.EndsWith(";")) { ";" } else { "" }
    $NewUserPath = "$UserPath$Separator$LocalBin"
    [Environment]::SetEnvironmentVariable('PATH', $NewUserPath, 'User')
    Write-Host "[xt-forge] Added $LocalBin to your User PATH (open a new terminal if existing shells do not see xt-forge yet)."
} else {
    Write-Host "[xt-forge] $LocalBin is already on your User PATH."
}

# Make the command usable in this PowerShell session too, without reopening a terminal.
$SessionParts = $env:Path -split ";"
if ($SessionParts -notcontains $LocalBin) {
    $env:Path = "$LocalBin;$env:Path"
}

Write-Host "[xt-forge] Done! Try: xt-forge doctor  |  xt-forge --meta"
