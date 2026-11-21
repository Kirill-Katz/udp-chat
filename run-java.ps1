param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Passphrase,
    [int]$Port = 9000,
    [string]$Interface = ''
)

if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    & "$env:WINDIR\System32\chcp.com" 65001 | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [Console]::InputEncoding = $utf8
    [Console]::OutputEncoding = $utf8
    $OutputEncoding = $utf8
}

$project = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $project 'java-peer'
$output = Join-Path $source 'out'
$jdk = Get-ChildItem 'C:\Program Files\Java' -Directory -Filter 'jdk-*' -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
if ($jdk) {
    $compiler = Join-Path $jdk.FullName 'bin\javac.exe'
    $runtime = Join-Path $jdk.FullName 'bin\java.exe'
} else {
    $compiler = (Get-Command javac -ErrorAction Stop).Source
    $runtime = (Get-Command java -ErrorAction Stop).Source
}
New-Item -ItemType Directory -Force -Path $output | Out-Null
& $compiler -d $output (Join-Path $source 'Chat.java')
if ($LASTEXITCODE -ne 0) { throw 'Java compilation failed.' }
$arguments = @('-Dfile.encoding=UTF-8', '-cp', $output, 'Chat', '-name', $Name, '-passphrase', $Passphrase, '-port', "$Port")
if ($Interface) { $arguments += @('-interface', $Interface) }
& $runtime @arguments
if ($LASTEXITCODE -ne 0) { throw "Java peer exited with code $LASTEXITCODE." }
