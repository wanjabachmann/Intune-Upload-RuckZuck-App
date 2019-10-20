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

PS> .\

.LINK
https://tech.wanjabachmann.ch/
#>

# RuckZuck Global
$detectionFileName = "detectionrule"
$installFileName = "install"
$uninstallFileName = "uninstall"
$PSInstallFileExtension = ".ps1"
$getrzrestapiurl = Invoke-RestMethod -Uri "https://ruckzuck.tools/rest/v2/geturl"
$rzrestapiurlstring = '$getrzrestapiurl = Invoke-RestMethod -Uri "https://ruckzuck.tools/rest/v2/geturl"'

$urlrz = "https://github.com/rzander/ruckzuck/releases/download/1.7.0.5/"
$applicationrz  = "RZUpdate.exe"
$applicationurlrz = $urlrz + $applicationrz


# Microsoft Graph Script
$Win32_Application_Add = "https://raw.githubusercontent.com/microsoftgraph/powershell-intune-samples/master/LOB_Application/Win32_Application_Add.ps1"
$PSWin32_Application_Add = "Win32_Application_Add.ps1"

# Download w32 app prep tool
$urlw32apptool = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/blob/master/IntuneWinAppUtil.exe?raw=true"
$applicationw32apptool  = "IntuneWinAppUtil.exe"
$IntuneWinAppUtil = "$PSScriptRoot\$applicationw32apptool"

##########################################################################################
# Functions
##########################################################################################
# Create Application Package
function New-IntuneWin32Package {
    [CmdletBinding()]
    param ()

    begin{
        #download intune content prep tool
        Invoke-WebRequest -Uri $applicationurlrz -OutFile "$PSScriptRoot\$returnedSoftware\$applicationrz" 
    }
    process{
        #wrap package
        Start-Process -FilePath $IntuneWinAppUtil -ArgumentList @("-c `"$PSScriptRoot\$returnedSoftware`"","-s `"$applicationrz`"","-o `"$PSScriptRoot\$uploadFolder`"","-q") -Wait
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

        $returnRuckZuckSoftware = Invoke-RestMethod -Uri "$getrzrestapiurl/rest/v2/getcatalog"

        $getReturnedRuckZuckSoftware = $returnRuckZuckSoftware | Select-Object Productname, ShortName, Downloads | Sort-Object ShortName | Out-GridView -Title "Select software to upload" -PassThru
        
        return $getReturnedRuckZuckSoftware.Shortname
        }
}

##########################################################################################

function Get-SoftwareDetails {  
    [CmdletBinding()]
    param ()

    process{
        # Get Software from RuckZuck
        $returnRuckZuckSoftware = Invoke-RestMethod -Uri "$getrzrestapiurl/rest/v2/getsoftwares?shortname=$returnedSoftware"
        $getReturnedRuckZuckSoftware = $returnRuckZuckSoftware | Select-Object *

        return $getReturnedRuckZuckSoftware
    }
}

##########################################################################################

function New-DetectionFile {
    [CmdletBinding()]
    param ()
    process{

        $DetectionContent = @()
        $DetectionContent = '$returnedSoftware =' + "`"$returnedSoftware`""
        $DetectionContent += $rzrestapiurlstring 
        $DetectionContent += '$returnRuckZuckSoftware = Invoke-RestMethod -Uri ' + '"$getrzrestapiurl/rest/v2/getsoftwares?shortname=$returnedSoftware"'
        $DetectionContent += '$getReturnedRuckZuckSoftware = $returnRuckZuckSoftware.PSDetection'
        $DetectionContent += 'if((Invoke-Expression $getReturnedRuckZuckSoftware) -eq $true){' + "write-host `"App installed`" `n exit 0}else{write-host `"App not installed`" `n exit 1}"
    
        $DetectionFileContent = $DetectionContent | Out-String
        
        $null = New-Item -Path "$PSScriptRoot\$uploadfolder\$detectionFileName$PSInstallFileExtension" -ItemType File -Value $DetectionFileContent -Force
    }
}

function New-UninstallCommand {
    [CmdletBinding()]
    param ()
    process{
        $UninstallContent = @()

        $UninstallContent = 'powershell.exe -executionpolicy Bypass -command {'
        $UninstallContent += '$returnedSoftware =' + "`"$returnedSoftware`"" + ";"
        $UninstallContent += $rzrestapiurlstring + ";"
        $UninstallContent += '$returnRuckZuckSoftware = Invoke-RestMethod -Uri ' + '"$getrzrestapiurl/rest/v2/getsoftwares?shortname=$returnedSoftware"' + ";"
        $UninstallContent += 'Invoke-Expression $returnRuckZuckSoftware.PSUninstall' + '}'
        
        return $($UninstallContent | Out-String)
    }
}

##########################################################################################
### Run W32_Applicatoin_Add.ps1 ###
function Add-Win32Application {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param ()

    if ($WhatIfPreference){

        Write-Output "Creating and uploading win32 app"

    }else{

        New-DetectionFile
   
        [string]$uninstallcommand = $null
        [string]$installcommand = $null

        $installcommand = ".\$applicationrz `"$returnedSoftware`""
        $uninstallcommand = New-UninstallCommand

        #Import graph script
        Import-Module ".\Win32_Application_Add.ps1"
        
        $SourceFile = (Get-ChildItem -Path $PSScriptRoot\$uploadfolder\ -Filter *.intunewin -Recurse).FullName

        $Publisher = $RZSoftwareWithDetails.Manufacturer

        if (-not ($Publisher)){
            $Publisher = "not set"
        }

        if ($RZSoftwareWithDetails.Architecture -eq "x64"){
            $ifrunAs32Bit = $false
        }else{
            $ifrunAs32Bit = $true
        }

        $PowerShellRule = New-DetectionRule -PowerShell -ScriptFile "$PSScriptRoot\$uploadfolder\$detectionFileName$PSInstallFileExtension" `
        -enforceSignatureCheck:$false -runAs32Bit:$ifrunAs32Bit

        # Creating Array for detection Rule
        $DetectionRule = @($PowerShellRule)

        $ReturnCodes = Get-DefaultReturnCodes

        #$ReturnCodes += New-ReturnCode -returnCode 302 -type softReboot
        #$ReturnCodes += New-ReturnCode -returnCode 145 -type hardReboot

        # Win32 Application Upload
        Upload-Win32Lob -displayName "$returnedSoftware RZ" -SourceFile $SourceFile -publisher $Publisher `
        -description $RZSoftwareWithDetails.Description -detectionRules $DetectionRule `
        -returnCodes $ReturnCodes -installCmdLine $installcommand -uninstallCmdLine $uninstallcommand
    }
}

##########################################################################################
# Change content of Win32_Application_Add.ps1 Script
function Update-GraphScript {

    process{

        $PSWin32_Application_Add = "Win32_Application_Add.ps1"

        $currentScript = Get-Content -Path "$PSScriptRoot\original-$PSWin32_Application_Add"
        
        #select only script content without example
	    $updatedScript = $currentScript[(0) .. ($currentScript.IndexOf("# Sample Win32 Application") -1)]

        $updatedScript | Set-content -Path "$PSScriptRoot\$PSWin32_Application_Add" -Encoding UTF8 -Force
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

# Name of the selected Software
$Software = Get-Software
Write-Output "Selected software: '$Software'"

# Create Files and Upload Software via Graph Rest API
foreach ($returnedSoftware in  $Software){

    Write-Output "Processing app '$returnedSoftware'"

    $uploadFolder = "$returnedSoftware-upload"

    # Create Down-/Upload Folder
    $null = New-Item -ItemType Directory -Path "$PSScriptRoot\$returnedSoftware" -Force
    $null = New-Item -ItemType Directory -Path "$PSScriptRoot\$uploadFolder" -Force
    
    # Get Software Details
    $RZSoftwareWithDetails = Get-SoftwareDetails

    # Create intunewin
    New-IntuneWin32Package

    # Change Content of Win32_Application_Add.ps1
    Update-GraphScript

    # Upload Software via Graph API
    Add-Win32Application
}
