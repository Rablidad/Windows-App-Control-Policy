param(
	[string]$Filename,
	[string]$Url,
	[string]$PolicyName
)

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
	[Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
	Write-Host "This script must run as Administrator."
	Write-Host "Requesting elevation..."

	$scriptPath = $MyInvocation.MyCommand.Path
	if ([string]::IsNullOrWhiteSpace($scriptPath)) {
		Write-Host "Unable to determine script path for elevation."
		exit 1
	}

	$psExe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }

	$elevatedArgs = @(
		'-NoProfile'
		'-ExecutionPolicy'
		'Bypass'
		'-File'
		$scriptPath
	)

	if (-not [string]::IsNullOrWhiteSpace($Filename)) {
		$elevatedArgs += @('-Filename', $Filename)
	}

	if (-not [string]::IsNullOrWhiteSpace($Url)) {
		$elevatedArgs += @('-Url', $Url)
	}

	if (-not [string]::IsNullOrWhiteSpace($PolicyName)) {
		$elevatedArgs += @('-PolicyName', $PolicyName)
	}

	try {
		Start-Process -FilePath $psExe -Verb RunAs -ArgumentList $elevatedArgs
		exit 0
	}
	catch {
		Write-Host "Elevation was cancelled or failed."
		Write-Host $_.Exception.Message
		exit 1
	}
}

if (($Filename -and $Url) -or (-not $Filename -and -not $Url)) {
	Write-Host "You must provide either -Filename <path> or -Url <url>, but not both."
	exit 1
}

if ([string]::IsNullOrWhiteSpace($PolicyName)) {
	Write-Host "You must provide a non-empty -PolicyName value."
	exit 1
}

$filepath = $null
$tempDownloadedFile = $null

if ($Filename) {
	if ([string]::IsNullOrWhiteSpace($Filename)) {
		Write-Host "-Filename cannot be empty."
		exit 1
	}

	if (-not (Test-Path -LiteralPath $Filename)) {
		Write-Host "File not found: $Filename"
		exit 1
	}

	try {
		$filepath = (Resolve-Path -LiteralPath $Filename).Path
	}
	catch {
		Write-Host "Failed to resolve file path: $Filename"
		Write-Host $_.Exception.Message
		exit 1
	}
}
elseif ($Url) {
	if ([string]::IsNullOrWhiteSpace($Url)) {
		Write-Host "-Url cannot be empty."
		exit 1
	}

	try {
		$uri = [System.Uri]$Url
	}
	catch {
		Write-Host "Invalid URL: $Url"
		exit 1
	}

	$xmlNameFromUrl = [System.IO.Path]::GetFileName($uri.AbsolutePath)

	if ([string]::IsNullOrWhiteSpace($xmlNameFromUrl)) {
		$xmlNameFromUrl = "policy.xml"
	}
	elseif ([string]::IsNullOrWhiteSpace([System.IO.Path]::GetExtension($xmlNameFromUrl))) {
		$xmlNameFromUrl += ".xml"
	}

	$tempDownloadedFile = Join-Path $env:TEMP $xmlNameFromUrl

	try {
		$response = Invoke-WebRequest -Uri $Url -OutFile $tempDownloadedFile -PassThru -UseBasicParsing
	}
	catch {
		Write-Host "Failed to download URL: $Url"
		Write-Host $_.Exception.Message
		exit 1
	}

	if (-not $response) {
		Write-Host "Download failed: no response returned."
		if (Test-Path -LiteralPath $tempDownloadedFile) {
			Remove-Item -LiteralPath $tempDownloadedFile -Force -ErrorAction SilentlyContinue
		}
		exit 1
	}

	if ($response.StatusCode -ne 200) {
		Write-Host "Download failed. HTTP status code: $($response.StatusCode)"
		if (Test-Path -LiteralPath $tempDownloadedFile) {
			Remove-Item -LiteralPath $tempDownloadedFile -Force -ErrorAction SilentlyContinue
		}
		exit 1
	}

	if (-not (Test-Path -LiteralPath $tempDownloadedFile)) {
		Write-Host "Download did not produce a file."
		exit 1
	}

	try {
		$filepath = (Resolve-Path -LiteralPath $tempDownloadedFile).Path
	}
	catch {
		Write-Host "Failed to resolve downloaded file path."
		Write-Host $_.Exception.Message
		exit 1
	}
}

if ([string]::IsNullOrWhiteSpace($filepath)) {
	Write-Host "Could not determine XML file path."
	exit 1
}

$diskname = Split-Path -Path $filepath -Qualifier
$folder = Split-Path -Path $filepath -Parent
$xmlBaseName = [System.IO.Path]::GetFileNameWithoutExtension($filepath)
$activeDir = "C:\Windows\System32\CodeIntegrity\CIPolicies\Active"

if ([string]::IsNullOrWhiteSpace($diskname)) {
	Write-Host "Could not determine disk name from path: $filepath"
	exit 1
}

if ([string]::IsNullOrWhiteSpace($folder)) {
	Write-Host "Could not determine folder from path: $filepath"
	exit 1
}

if ([string]::IsNullOrWhiteSpace($xmlBaseName)) {
	Write-Host "Could not determine XML base filename."
	exit 1
}

if (-not (Test-Path -LiteralPath $activeDir)) {
	Write-Host "Destination folder does not exist: $activeDir"
	exit 1
}

$tempCipPath = Join-Path $folder ($xmlBaseName + ".cip")

Write-Host "XML file   : $filepath"
Write-Host "Policy name: $PolicyName"
Write-Host "Disk name  : $diskname"
Write-Host "Temp CIP   : $tempCipPath"

try {
	Set-CIPolicyIdInfo -FilePath $filepath -PolicyName $PolicyName -ResetPolicyID
}
catch {
	Write-Host "Set-CIPolicyIdInfo failed."
	Write-Host $_.Exception.Message
	exit 1
}

try {
	[xml]$x = Get-Content -LiteralPath $filepath
}
catch {
	Write-Host "Failed to read XML file."
	Write-Host $_.Exception.Message
	exit 1
}

$uuid = $x.SiPolicy.PolicyID

if ([string]::IsNullOrWhiteSpace($uuid)) {
	Write-Host "Could not read PolicyID from XML."
	exit 1
}

$finalCipPath = Join-Path $activeDir ($uuid + ".cip")

Write-Host "Final CIP  : $finalCipPath"

try {
	ConvertFrom-CIPolicy -XmlFilePath $filepath -BinaryFilePath $tempCipPath
}
catch {
	Write-Host "ConvertFrom-CIPolicy failed."
	Write-Host $_.Exception.Message
	exit 1
}

if (-not (Test-Path -LiteralPath $tempCipPath)) {
	Write-Host "CIP file was not created: $tempCipPath"
	exit 1
}

try {
	Move-Item -LiteralPath $tempCipPath -Destination $finalCipPath -Force
}
catch {
	Write-Host "Failed to move CIP file to Active folder."
	Write-Host $_.Exception.Message
	exit 1
}

try {
	"`n" | citool --update-policy $finalCipPath
}
catch {
	Write-Host "citool --update-policy failed."
	Write-Host $_.Exception.Message
	exit 1
}

try {
	Invoke-CimMethod `
		-Namespace root\Microsoft\Windows\CI `
		-ClassName PS_UpdateAndCompareCIPolicy `
		-MethodName Update `
		-Arguments @{ FilePath = $finalCipPath } | Out-Null
}
catch {
	Write-Host "Invoke-CimMethod Update failed."
	Write-Host $_.Exception.Message
	exit 1
}

Write-Host "Policy deployed successfully."
Write-Host "PolicyID    : $uuid"
Write-Host "Installed   : $finalCipPath"
pause
