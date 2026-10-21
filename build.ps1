$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$nativeRoot = Join-Path $projectRoot 'native'
$archive = Join-Path $nativeRoot 'WinDivert-2.2.2-A.zip'
$expectedHash = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'
$downloadUrl = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'

New-Item -ItemType Directory -Force -Path $nativeRoot | Out-Null
if (!(Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archive -UseBasicParsing
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'WinDivert archive SHA-256 mismatch. Build stopped.'
}

# Extract only the files referenced by the project, into fixed local paths.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    foreach ($relative in @('x64/WinDivert.dll', 'x64/WinDivert64.sys', 'LICENSE')) {
        $entry = $zip.GetEntry('WinDivert-2.2.2-A/' + $relative)
        if ($null -eq $entry) { throw ('Missing WinDivert file: ' + $relative) }
        $destination = Join-Path $nativeRoot ('WinDivert-2.2.2-A/' + $relative)
        New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destination, $true)
    }
} finally { $zip.Dispose() }

$project = Join-Path $projectRoot 'src/DPI-Unlocker/DPI-Unlocker.csproj'
$output = Join-Path $projectRoot 'dist/DPI-Unlocker'
& dotnet publish $project -c Release -r win-x64 --self-contained true '-p:PublishSingleFile=true' '-p:DebugType=None' '-p:DebugSymbols=false' -o $output
if ($LASTEXITCODE -ne 0) { throw ('dotnet publish failed: ' + $LASTEXITCODE) }
Copy-Item -LiteralPath (Join-Path $projectRoot 'licenses') -Destination $output -Recurse -Force
Copy-Item -LiteralPath (Join-Path $projectRoot 'THIRD-PARTY-NOTICES.md') -Destination $output -Force
Write-Output ('Published: ' + $output)
