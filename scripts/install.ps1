param(
    [string]$Version,
    [ValidateSet("stable", "nightly")][string]$Channel = "stable",
    [string]$Prefix,
    [string]$BinDir,
    [switch]$NoVerify,
    [switch]$DryRun,
    [ValidateSet("text", "json")][string]$Format = "text"
)

$IsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)
$IsLinux = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Linux
)
$IsMacOS = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::OSX
)
$AliasName = "pybun-cli"
$AliasBinaryName = if ($IsWindows) { "pybun-cli.exe" } else { "pybun-cli" }

function Write-Log {
    param([string]$Message)
    if ($Format -eq "json") {
        [Console]::Error.WriteLine($Message)
    } else {
        Write-Host $Message
    }
}

function Expand-Path {
    param([string]$PathValue)
    if (-not $PathValue) {
        return $null
    }
    if ($PathValue -like "~*") {
        return $PathValue -replace "^~", $HOME
    }
    return $PathValue
}

function Detect-Target {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    if ($IsWindows) {
        if ($arch -ne "X64") {
            throw "unsupported Windows architecture: $arch"
        }
        return "x86_64-pc-windows-msvc"
    }
    if ($IsMacOS) {
        if ($arch -eq "Arm64") {
            return "aarch64-apple-darwin"
        }
        if ($arch -eq "X64") {
            return "x86_64-apple-darwin"
        }
        throw "unsupported macOS architecture: $arch"
    }
    if ($IsLinux) {
        if ($arch -eq "Arm64") {
            return "aarch64-unknown-linux-gnu"
        }
        if ($arch -eq "X64") {
            if (Test-Path "/lib/ld-musl-x86_64.so.1") {
                return "x86_64-unknown-linux-musl"
            }
            return "x86_64-unknown-linux-gnu"
        }
        throw "unsupported Linux architecture: $arch"
    }
    throw "unsupported OS (use install.sh on macOS/Linux)"
}

function Download-File {
    param(
        [string]$Url,
        [string]$Destination
    )
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing | Out-Null
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $Destination | Out-Null
    }
}

function Get-ManifestData {
    param(
        [string]$ManifestPath,
        [string]$Target
    )
    $manifest = Get-Content -Raw $ManifestPath | ConvertFrom-Json
    $asset = $manifest.assets | Where-Object { $_.target -eq $Target } | Select-Object -First 1
    if (-not $asset) {
        throw "no asset found in manifest for target: $Target"
    }
    return @{
        Manifest = $manifest
        Asset = $asset
    }
}

function Detect-ExistingPybun {
    param(
        [string]$InstallPath,
        [string]$AliasPath
    )
    $script:DetectedPybunPath = $null
    $script:DetectedPybunKind = $null
    $script:DetectedPybunMessage = $null

    $cmd = Get-Command pybun -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return
    }
    $path = $cmd.Source
    if ($path -eq $InstallPath -or $path -eq $AliasPath) {
        return
    }

    $isBun = $false
    if ($path -like "*\.bun\*") {
        $isBun = $true
    }
    if (-not $isBun -and (Test-Path $path)) {
        try {
            $firstLine = (Get-Content -Path $path -TotalCount 1)[0]
            if ($firstLine -match "bun") {
                $isBun = $true
            }
        } catch {
        }
    }

    $script:DetectedPybunPath = $path
    if ($isBun) {
        $script:DetectedPybunKind = "bun-pybun-detected"
        $script:DetectedPybunMessage = "Detected existing Bun-provided pybun at $path. Use the pybun-cli alias or adjust PATH to prefer PyBun."
    } else {
        $script:DetectedPybunKind = "pybun-conflict"
        $script:DetectedPybunMessage = "Detected another pybun on PATH at $path. Use the pybun-cli alias or adjust PATH."
    }
}

function New-PybunAlias {
    param(
        [string]$Source,
        [string]$AliasPath
    )
    $script:AliasStatus = "created"
    if (Test-Path $AliasPath) {
        Write-Log "warning: alias target already exists at $AliasPath (skipping)"
        $script:AliasStatus = "skipped-existing"
        return
    }
    try {
        New-Item -ItemType SymbolicLink -Path $AliasPath -Target $Source -Force | Out-Null
        return
    } catch {
    }
    Copy-Item -Path $Source -Destination $AliasPath -Force
}

if (-not $BinDir -and -not $Prefix) {
    if ($IsWindows) {
        $Prefix = Join-Path $env:LOCALAPPDATA "pybun"
    } else {
        $Prefix = Join-Path $HOME ".local"
    }
}

if ($BinDir) {
    $BinDir = Expand-Path $BinDir
    if (-not $Prefix) {
        $Prefix = Split-Path $BinDir -Parent
    } else {
        $Prefix = Expand-Path $Prefix
    }
} else {
    $Prefix = Expand-Path $Prefix
    $BinDir = Join-Path $Prefix "bin"
}

$Target = Detect-Target
$ArchiveExt = if ($IsWindows) { "zip" } else { "tar.gz" }
$AssetName = "pybun-$Target.$ArchiveExt"
$BinaryName = if ($IsWindows) { "pybun.exe" } else { "pybun" }
$InstallPath = Join-Path $BinDir $BinaryName
$AliasPath = Join-Path $BinDir $AliasBinaryName

$ManifestSource = $env:PYBUN_INSTALL_MANIFEST
if (-not $ManifestSource) {
    if ($Version) {
        $Version = $Version.TrimStart("v")
        $ReleaseTag = "v$Version"
        $ManifestSource = "https://github.com/pybun/pybun/releases/download/$ReleaseTag/pybun-release.json"
    } elseif ($Channel -eq "nightly") {
        $ManifestSource = "https://github.com/pybun/pybun/releases/download/nightly/pybun-release.json"
    } else {
        $ManifestSource = "https://github.com/pybun/pybun/releases/latest/download/pybun-release.json"
    }
}

if ($Version) {
    $ReleaseTag = "v$($Version.TrimStart("v"))"
    $AssetUrl = "https://github.com/pybun/pybun/releases/download/$ReleaseTag/$AssetName"
} elseif ($Channel -eq "nightly") {
    $AssetUrl = "https://github.com/pybun/pybun/releases/download/nightly/$AssetName"
} else {
    $AssetUrl = "https://github.com/pybun/pybun/releases/latest/download/$AssetName"
}

$ManifestPath = $null
if ($ManifestSource -like "file://*") {
    $ManifestPath = $ManifestSource.Substring(7)
} elseif (Test-Path $ManifestSource) {
    $ManifestPath = $ManifestSource
} elseif ($ManifestSource -match "^https?://") {
    if ($env:PYBUN_INSTALL_FETCH -eq "1" -or (-not $NoVerify -and -not $DryRun)) {
        $ManifestPath = Join-Path ([System.IO.Path]::GetTempPath()) ("pybun-release-" + [System.Guid]::NewGuid().ToString() + ".json")
        Download-File -Url $ManifestSource -Destination $ManifestPath
    }
}

$ManifestVersion = $null
$ManifestChannel = $null
$ManifestReleaseUrl = $null
$AssetSha = $null
$SigType = $null
$SigValue = $null
$SigPub = $null

if ($ManifestPath) {
    $manifestData = Get-ManifestData -ManifestPath $ManifestPath -Target $Target
    $manifest = $manifestData.Manifest
    $asset = $manifestData.Asset
    $ManifestVersion = $manifest.version
    $ManifestChannel = $manifest.channel
    $ManifestReleaseUrl = $manifest.release_url
    $AssetName = $asset.name
    $AssetUrl = $asset.url
    $AssetSha = $asset.sha256
    if ($asset.signature) {
        $SigType = $asset.signature.type
        $SigValue = $asset.signature.value
        $SigPub = $asset.signature.public_key
    }
    if (-not $Version -and $ManifestVersion) {
        $Version = $ManifestVersion
    }
} elseif (-not $NoVerify -and -not $DryRun) {
    throw "manifest required for verification (set PYBUN_INSTALL_MANIFEST or use --no-verify)"
}

$AliasStatus = "planned"
Detect-ExistingPybun -InstallPath $InstallPath -AliasPath $AliasPath

if ($DryRun) {
    if ($Format -eq "json") {
        $assetInfo = [ordered]@{
            name = $AssetName
            url = $AssetUrl
            sha256 = $AssetSha
        }
        if ($SigType -or $SigValue -or $SigPub) {
            $assetInfo.signature = [ordered]@{
                type = $SigType
                value = $SigValue
                public_key = $SigPub
            }
        }
        $manifestInfo = $null
        if ($ManifestSource -or $ManifestVersion -or $ManifestChannel -or $ManifestReleaseUrl) {
            $manifestInfo = [ordered]@{
                source = $ManifestSource
                version = $ManifestVersion
                channel = $ManifestChannel
                release_url = $ManifestReleaseUrl
            }
        }
        $detail = [ordered]@{
            status = "dry-run"
            dry_run = $true
            verify = (-not $NoVerify)
            no_verify = [bool]$NoVerify
            channel = $Channel
            version = $Version
            target = $Target
            bin_dir = $BinDir
            install_path = $InstallPath
            manifest = $manifestInfo
            asset = $assetInfo
        }
        $detail.aliases = @(
            [ordered]@{
                name = $AliasName
                path = $AliasPath
                status = $AliasStatus
            }
        )
        $warnings = @()
        if ($DetectedPybunMessage) {
            $warning = [ordered]@{
                kind = $DetectedPybunKind
                message = $DetectedPybunMessage
                path = $DetectedPybunPath
            }
            $warnings += $warning
        }
        $detail.warnings = $warnings
        $detail | ConvertTo-Json -Depth 6
        exit 0
    }

    Write-Log "PyBun installer dry-run"
    Write-Log "Target: $Target"
    Write-Log "Manifest: $ManifestSource"
    Write-Log "Asset: $AssetUrl"
    Write-Log "Install path: $InstallPath"
    Write-Log ("Verify: " + ($(if ($NoVerify) { "disabled" } else { "enabled" })))
    if ($DetectedPybunMessage) {
        Write-Log ("warning: " + $DetectedPybunMessage)
    }
    exit 0
}

if ($NoVerify) {
    Write-Log "warning: verification disabled (--no-verify)"
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pybun-install-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    $ArtifactPath = Join-Path $TempDir $AssetName
    Write-Log "Downloading $AssetUrl"
    Download-File -Url $AssetUrl -Destination $ArtifactPath

    if (-not $NoVerify) {
        if (-not $AssetSha) {
            throw "manifest missing sha256 for asset"
        }
        Write-Log "Verifying SHA256"
        $computed = (Get-FileHash -Algorithm SHA256 -Path $ArtifactPath).Hash.ToLowerInvariant()
        if ($computed -ne $AssetSha.ToLowerInvariant()) {
            throw "checksum mismatch: expected $AssetSha, got $computed"
        }
        if ($SigValue -and $SigPub) {
            $minisign = Get-Command minisign -ErrorAction SilentlyContinue
            if (-not $minisign) {
                throw "minisign is required for signature verification (install minisign or use --no-verify)"
            }
            $SigPath = Join-Path $TempDir ($AssetName + ".minisig")
            $PubPath = Join-Path $TempDir "pybun-release.pub"
            Set-Content -Path $SigPath -Value $SigValue -Encoding ASCII
            Set-Content -Path $PubPath -Value $SigPub -Encoding ASCII
            Write-Log "Verifying signature (minisign)"
            & minisign -Vm $ArtifactPath -x $SigPath -P $PubPath | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "minisign verification failed"
            }
        }
    }

    Write-Log "Extracting archive"
    if ($ArchiveExt -eq "zip") {
        Expand-Archive -Path $ArtifactPath -DestinationPath $TempDir -Force
    } else {
        & tar -xzf $ArtifactPath -C $TempDir
    }

    $ExtractedDir = Join-Path $TempDir ("pybun-" + $Target)
    $BinSource = Join-Path $ExtractedDir $BinaryName
    if (-not (Test-Path $BinSource)) {
        throw "expected binary not found in archive: $BinSource"
    }

    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Copy-Item -Path $BinSource -Destination $InstallPath -Force
    if (-not $IsWindows) {
        & chmod +x $InstallPath
    }

    Write-Log "Installed pybun to $InstallPath"
    New-PybunAlias -Source $InstallPath -AliasPath $AliasPath
    if ($DetectedPybunMessage) {
        Write-Log ("warning: " + $DetectedPybunMessage)
    }
} finally {
    if (Test-Path $TempDir) {
        Remove-Item -Recurse -Force $TempDir
    }
}

if ($env:PATH -notlike "*$BinDir*") {
    Write-Log "Add $BinDir to your PATH to use pybun."
}
