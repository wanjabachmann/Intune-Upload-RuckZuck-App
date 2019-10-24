<#
.Author
Wanja Bachmann 
https://tech.wanjabachmann.ch/

Adds a file name extension to a supplied name.

.DESCRIPTION
1. Search for RuckZuck app
2. You have to choose the app you want
3. Create needed files for Win32 App
4. Create Win32 App
5. Upload the app to Intune

.EXAMPLE

PS> .\Upload-RuckZuck-apps.ps1

.LINK
https://tech.wanjabachmann.ch/
#>

# Microsoft Graph Script
$Win32_Application_Add = "https://raw.githubusercontent.com/microsoftgraph/powershell-intune-samples/master/LOB_Application/Win32_Application_Add.ps1"
$PSWin32_Application_Add = "Win32_Application_Add.ps1"

# Download w32 app prep tool
$urlw32apptool = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/blob/master/IntuneWinAppUtil.exe?raw=true"
$applicationw32apptool  = "IntuneWinAppUtil.exe"
$IntuneWinAppUtil = "$PSScriptRoot\$applicationw32apptool"
$RuckZuckRestAPIURL = "https://ruckzuck.tools/rest/v2/geturl"
##########################################################################################
# Functions
##########################################################################################
function Get-RuckZuckUrl {
    [CmdletBinding()]
    param ()

    process{
        return (Invoke-RestMethod -Uri "$RuckZuckRestAPIURL")
    }
}

# Create Application Package
function New-IntuneWin32Package {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]$ApplicationShortname,
        [Parameter(Mandatory=$false)]
        [String]$ExecutableToWrap="RZUpdate.exe",
        [Parameter(Mandatory=$false)]
        [String]$RzDownload="https://github.com/rzander/ruckzuck/releases/latest/download/RZUpdate.exe"
    )

    begin{
        #download RzUpdate
        Invoke-WebRequest -Uri $RzDownload -OutFile "$PSScriptRoot\$ApplicationShortname\$ExecutableToWrap" 
    }
    process{
        #wrap package
        $uploadFolder = "$ApplicationShortname-upload"
        Start-Process -FilePath $IntuneWinAppUtil -ArgumentList @("-c `"$PSScriptRoot\$ApplicationShortname`"","-s `"$ExecutableToWrap`"","-o `"$PSScriptRoot\$uploadFolder`"","-q") -Wait
    }
    end{}
}

##########################################################################################
# Searching for the Software form RuckZuck Tools
function Get-Software {
    [CmdletBinding()]
    param ()

    process{

        $getReturnedRuckZuckSoftware = @()

        $returnRuckZuckSoftware = Invoke-RestMethod -Uri "$(Get-RuckZuckUrl)/rest/v2/getcatalog"

        $getReturnedRuckZuckSoftware = $returnRuckZuckSoftware | Select-Object Productname, ShortName, Downloads | Sort-Object ShortName | Out-GridView -Title "Select software to upload" -PassThru
        
        return $getReturnedRuckZuckSoftware.Shortname
    }
}

##########################################################################################

function Get-SoftwareDetails {  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]$ApplicationShortname
    )

    process{
        # Get Software from RuckZuck
        $returnRuckZuckSoftware = Invoke-RestMethod -Uri "$(Get-RuckZuckUrl)/rest/v2/getsoftwares?shortname=$ApplicationShortname"
        $getReturnedRuckZuckSoftware = $returnRuckZuckSoftware | Select-Object *

        return $getReturnedRuckZuckSoftware
    }
}

##########################################################################################

function New-DetectionFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]$ApplicationShortname
    )
    process{

        $DetectionContent = @()
        $DetectionContent =  '$RuckZuckRestAPIURL ='  + "`"$RuckZuckRestAPIURL`"" + ";"
        $DetectionContent += '$returnedSoftware =' + "`"$ApplicationShortname`"" + ";"
        $DetectionContent += '$getrzrestapiurl = Invoke-RestMethod -Uri "$RuckZuckRestAPIURL"' + ";"
        $DetectionContent += '$returnRuckZuckSoftware = Invoke-RestMethod -Uri "$($getrzrestapiurl)/rest/v2/getsoftwares?shortname=$returnedSoftware"' + ";"
        $DetectionContent += '$getReturnedRuckZuckSoftware = $returnRuckZuckSoftware.PSDetection' + ";"
        $DetectionContent += 'if((Invoke-Expression $getReturnedRuckZuckSoftware) -eq $true){' + "write-host `"App installed`"; exit 0}else{write-host `"App not installed`"; exit 1}"
    
        $DetectionFileContent = $DetectionContent | Out-String
        
        $null = New-Item -Path "$PSScriptRoot\$uploadfolder\detectionrule.ps1" -ItemType File -Value $DetectionFileContent -Force
    }
}

function New-UninstallCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]$ApplicationShortname
    )
    process{
        $UninstallContent = @()
        $UninstallContent = 'powershell.exe -executionpolicy Bypass -command {'
        $UninstallContent +=  '$RuckZuckRestAPIURL ='  + "`"$RuckZuckRestAPIURL`"" + ";"
        $UninstallContent += '$returnedSoftware =' + "`"$ApplicationShortname`"" + ";"
        $UninstallContent += '$getrzrestapiurl = Invoke-RestMethod -Uri "$RuckZuckRestAPIURL"' + ";"
        $UninstallContent += '$returnRuckZuckSoftware = Invoke-RestMethod -Uri "$($getrzrestapiurl)/rest/v2/getsoftwares?shortname=$returnedSoftware"' + ";"
        $UninstallContent += 'Invoke-Expression $returnRuckZuckSoftware.PSUninstall' + '}'
        
        return $($UninstallContent | Out-String)
    }
}

##########################################################################################
### Run W32_Applicatoin_Add.ps1 ###
function Add-Win32Application {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [Parameter(Mandatory=$true)]
        [String]$ApplicationShortname,
        [Parameter(Mandatory=$true)]
        [String]$UninstallCommand,
        [Parameter(Mandatory=$false)]
        [String]$RzUpdate= "RzUpdate.exe"
    )

    if ($WhatIfPreference){

        Write-Output "Creating and uploading win32 app"

    }else{

        # Get Software Details
        $RZSoftwareWithDetails = Get-SoftwareDetails -ApplicationShortname $ApplicationShortname

        #[string]$uninstallcommand = $null
        #$uninstallcommand = New-UninstallCommand

        [string]$installcommand = $null
        $InstallCommand = ".\$RzUpdate `"$ApplicationShortname`""

        #Import graph script
        Import-Module -Name "$PSScriptRoot\Win32_Application_Add.psm1" -Verbose -ErrorAction Stop
        
        $SourceFile = (Get-ChildItem -Path $PSScriptRoot\$uploadfolder\ -Filter *.intunewin -Recurse).FullName | Select-Object -First 1

        $Publisher = $RZSoftwareWithDetails.Manufacturer

        if (-not ($Publisher)){
            $Publisher = "not set"
        }

        if ($RZSoftwareWithDetails.Architecture -eq "x64"){
            $ifrunAs32Bit = $false
        }else{
            $ifrunAs32Bit = $true
        }

        $PowerShellRule = New-DetectionRule -PowerShell -ScriptFile "$PSScriptRoot\$uploadfolder\detectionrule.ps1" `
        -enforceSignatureCheck:$false -runAs32Bit:$ifrunAs32Bit

        # Creating Array for detection Rule
        $DetectionRule = @($PowerShellRule)

        $ReturnCodes = Get-DefaultReturnCodes

        #$ReturnCodes += New-ReturnCode -returnCode 302 -type softReboot
        #$ReturnCodes += New-ReturnCode -returnCode 145 -type hardReboot

        # Win32 Application Upload
        Upload-Win32Lob -displayName "$ApplicationShortname RZ" -SourceFile $SourceFile -publisher $Publisher `
        -description $RZSoftwareWithDetails.Description -detectionRules $DetectionRule `
        -returnCodes $ReturnCodes -installCmdLine $installcommand -uninstallCmdLine $UninstallCommand
    }
}

##########################################################################################
# Change content of Win32_Application_Add.ps1 Script
function Update-GraphScript {

    process{

        $PSWin32_Application_Add = "Win32_Application_Add"

        $currentScript = Get-Content -Path "$PSScriptRoot\original-$PSWin32_Application_Add.ps1"
        
        #select only script content without example
	    $updatedScript = $currentScript[(0) .. ($currentScript.IndexOf("# Sample Win32 Application") -1)]

        $updatedScript | Set-content -Path "$PSScriptRoot\$PSWin32_Application_Add.psm1" -Encoding UTF8 -Force
    }
}
##########################################################################################

##########################################################################################
# Call objects 
##########################################################################################

# Download W32 App tool
Write-Output "Downloading IntuneWinAppUtil..."
Invoke-WebRequest -Uri $urlw32apptool -OutFile $IntuneWinAppUtil

# Download Win32_Application_Add.ps1
Write-Output "Downloading Microsoft Graph script..."
Invoke-WebRequest -Uri $Win32_Application_Add -OutFile "$PSScriptRoot\original-$PSWin32_Application_Add"

# Shortname of the selected Software
$Software = Get-Software
Write-Output "Selected software: '$Software'"

# Create Files and Upload Software via Graph Rest API
foreach ($currentSoftware in  $Software){

    Write-Output "Processing app '$currentSoftware'"

    $uploadFolder = "$currentSoftware-upload"

    # Create Down-/Upload Folder
    $null = New-Item -ItemType Directory -Path "$PSScriptRoot\$currentSoftware" -Force
    $null = New-Item -ItemType Directory -Path "$PSScriptRoot\$uploadFolder" -Force

    # Create intunewin
    New-IntuneWin32Package -ApplicationShortname $currentSoftware

    # Create Uninstall Command
    $UninstallFilePar = New-UninstallCommand -ApplicationShortname $currentSoftware

    # Create Detection File
    New-DetectionFile -ApplicationShortname $currentSoftware
   
    # Change Content of Win32_Application_Add.ps1
    Update-GraphScript

    # Upload Software via Graph API
    Add-Win32Application -ApplicationShortname $currentSoftware -UninstallCommand $UninstallFilePar
}
