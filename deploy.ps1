param()

$argList = @()
foreach ($arg in $args) {
	$argList += ('"{0}"' -f ($arg -replace '"', '\"'))
}

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
	$fullArgString = @(
		'-NoProfile'
		'-ExecutionPolicy'
		'Bypass'
		'-File'
		('"{0}"' -f $scriptPath)
	) + $argList

	try {
		Start-Process -FilePath $psExe -Verb RunAs -ArgumentList $fullArgString
		exit 0
	}
	catch {
		Write-Host "Elevation was cancelled or failed."
		Write-Host $_.Exception.Message
		exit 1
	}
}

$filename = $null
$url = $null
$policyname = $null

for ($i = 0; $i -lt $args.Count; $i++) {
	switch ($args[$i].ToLower()) {
		'--filename' {
			if ($i + 1 -ge $args.Count) {
				Write-Host "Missing value for --filename"
				exit 1
			}

			$filename = $args[$i + 1]
			$i++
		}

		'--url' {
			if ($i + 1 -ge $args.Count) {
				Write-Host "Missing value for --url"
				exit 1
			}

			$url = $args[$i + 1]
			$i++
		}

		'--policyname' {
			if ($i + 1 -ge $args.Count) {
				Write-Host "Missing value for --policyname"
				exit 1
			}

			$policyname = $args[$i + 1]
			$i++
		}

		default {
			Write-Host "Unknown argument: $($args[$i])"
			Write-Host "Usage:"
			Write-Host "  .\deploy.ps1 --filename <path-to-xml> --policyname <policy name>"
			Write-Host "  .\deploy.ps1 --url <xml-url> --policyname <policy name>"
			exit 1
		}
	}
}

if (($filename -and $url) -or (-not $filename -and -not $url)) {
	Write-Host "You must provide either --filename <path> or --url <url>, but not both."
	exit 1
}

if ([string]::IsNullOrWhiteSpace($policyname)) {
	Write-Host "You must provide a non-empty --policyname value."
	exit 1
}

$filepath = $null
$tempDownloadedFile = $null

if ($filename) {
	if ([string]::IsNullOrWhiteSpace($filename)) {
		Write-Host "--filename cannot be empty."
		exit 1
	}

	if (-not (Test-Path -LiteralPath $filename)) {
		Write-Host "File not found: $filename"
		exit 1
	}

	try {
		$filepath = (Resolve-Path -LiteralPath $filename).Path
	}
	catch {
		Write-Host "Failed to resolve file path: $filename"
		Write-Host $_.Exception.Message
		exit 1
	}
}
elseif ($url) {
	if ([string]::IsNullOrWhiteSpace($url)) {
		Write-Host "--url cannot be empty."
		exit 1
	}

	try {
		$uri = [System.Uri]$url
	}
	catch {
		Write-Host "Invalid URL: $url"
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
		$response = Invoke-WebRequest -Uri $url -OutFile $tempDownloadedFile -PassThru -UseBasicParsing
	}
	catch {
		Write-Host "Failed to download URL: $url"
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
Write-Host "Policy name: $policyname"
Write-Host "Disk name  : $diskname"
Write-Host "Temp CIP   : $tempCipPath"

try {
	Set-CIPolicyIdInfo -FilePath $filepath -PolicyName $policyname -ResetPolicyID
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
pause;