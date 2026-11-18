# XT-Forge Windows Installer (PowerShell 5.1+ / PowerShell 7+)
# Local repo : .\install.ps1
# Remote one-liner:
#   irm https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$RepoUrl = if ($env:XT_REPO_URL) { $env:XT_REPO_URL } else { "https://github.com/XtrComSu/xt-forge.git" }
$Branch  = if ($env:XT_BRANCH) { $env:XT_BRANCH } else { "main" }

$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not (Test-Path (Join-Path $ScriptRoot "bin\xtforge.cmd")) -or -not (Test-Path (Join-Path $ScriptRoot "VERSION"))) {
    $TargetSrc = Join-Path $env:USERPROFILE ".xt-forge-src"
    if (Test-Path (Join-Path $TargetSrc ".git")) {
        Write-Host "[xt-forge] Updating existing source checkout at $TargetSrc..."
        git -C $TargetSrc fetch --depth 1 origin $Branch | Out-Null
        git -C $TargetSrc checkout $Branch | Out-Null
        git -C $TargetSrc reset --hard "origin/$Branch" | Out-Null
    } else {
        Write-Host "[xt-forge] Cloning xt-forge ($Branch) to $TargetSrc..."
        git clone --depth 1 --branch $Branch $RepoUrl $TargetSrc
    }
    $ScriptRoot = $TargetSrc
}

Write-Host "[xt-forge] Installing from $ScriptRoot (Windows)"

if ((Get-Command cargo -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $ScriptRoot "native\xtforge-rs\Cargo.toml"))) {
    Write-Host "[xt-forge] Building Rust native core (native\xtforge-rs)..."
    Push-Location (Join-Path $ScriptRoot "native\xtforge-rs")
    cargo build --release --quiet
    Pop-Location
}

if ((Get-Command go -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $ScriptRoot "native\xtforge-go\go.mod"))) {
    Write-Host "[xt-forge] Building Go service hub (native\xtforge-go)..."
    Push-Location (Join-Path $ScriptRoot "native\xtforge-go")
    go build -ldflags="-s -w" -o xtforge-hub.exe ./cmd/xtforge-hub
    Pop-Location
}

$LocalBin = Join-Path $env:USERPROFILE ".local\bin"
New-Item -ItemType Directory -Force -Path $LocalBin | Out-Null

if (Get-Command node -ErrorAction SilentlyContinue) {
    node (Join-Path $ScriptRoot "bin\npx-xtforge.mjs") init --quiet
} else {
    $CmdLauncher = Join-Path $ScriptRoot "bin\xtforge.cmd"
    foreach ($alias in @("xt-forge.cmd", "xtforge.cmd", "xtf.cmd")) {
        $shimPath = Join-Path $LocalBin $alias
        "@echo off`r`n`"$CmdLauncher`" %*`r`n" | Set-Content -Path $shimPath -Encoding ASCII
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
        New-Item -ItemType Directory -Force -Path $dst | Out-Null
        foreach ($legacy in $LegacySkills) {
            $oldPath = Join-Path $dst $legacy
            if (Test-Path $oldPath) { Remove-Item -Path $oldPath -Recurse -Force -ErrorAction SilentlyContinue }
        }
        foreach ($tier in @("simple", "complex", "advanced")) {
            $tierDir = Join-Path $SkillsSrc $tier
            if (Test-Path $tierDir) {
                Get-ChildItem -Path $tierDir -Directory -Filter "XTF-*" | ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination $dst -Recurse -Force
                }
            }
        }
    }

    foreach ($pair in @(
        @{ dir = (Join-Path $env:USERPROFILE ".dsh\commands"); body = "---`ndescription: Run xt-forge natively (/xtf --meta, /xtf re checksec, /xtf intel cve, /xtf code graph)`n---`nExecute ``xt-forge `$ARGUMENTS`` cleanly. If ``$ARGUMENTS`` is ``--meta``, inspect or run ``xt-forge --meta``.`n" },
        @{ dir = (Join-Path $env:USERPROFILE ".claude\commands"); body = "---`ndescription: Run xt-forge natively (/xtf --meta, /xtf re checksec, /xtf intel cve)`n---`nRun ``xt-forge `$ARGUMENTS`` and present crisp findings.`n" }
    )) {
        New-Item -ItemType Directory -Force -Path $pair.dir | Out-Null
        Set-Content -Path (Join-Path $pair.dir "xtf.md") -Value $pair.body -Encoding UTF8
    }
}

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $UserPath) { $UserPath = "" }
$Parts = $UserPath -split ";" | Where-Object { $_ -ne "" }
if ($Parts -notcontains $LocalBin) {
    $NewUserPath = (($Parts + $LocalBin) | Select-Object -Unique) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    $env:Path = "$LocalBin;$env:Path"
    Write-Host "[xt-forge] Added $LocalBin to your User PATH (open a new terminal if existing shells do not see xt-forge yet)."
}

Write-Host "[xt-forge] Verifying install..."
& (Join-Path $LocalBin "xt-forge.cmd") version --json
Write-Host "[xt-forge] Done! Try: xt-forge doctor  |  xt-forge --meta"
