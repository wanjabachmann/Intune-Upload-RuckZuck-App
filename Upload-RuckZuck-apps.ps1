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

PS> .\intune-Upload-RuckZuck-App

.LINK
https://tech.wanjabachmann.ch/
#>

# RuckZuck Global
$detectionFileName = "detectionrule"
$installFileName = "install"
$uninstallFileName = "uninstall"
$PSInstallFileExtension = ".ps1"
$getrzrestapiurl = Invoke-RestMethod -Uri "https://ruckzuck.tools/rest/v2/geturl"
$Detectiongetrzrestapiurl = '$getrzrestapiurl = Invoke-RestMethod -Uri "https://ruckzuck.tools/rest/v2/geturl"'

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
function create-package {
    
    Invoke-WebRequest -Uri $applicationurlrz -OutFile "$PSScriptRoot\$returnedSoftware\$applicationrz" 
    
    # IntuneWinAppUtil -c <source_folder> -s <source_setup_file> -o <output_folder> <-q>
    &$IntuneWinAppUtil -c "$PSScriptRoot\$returnedSoftware" -s "$applicationrz" -o "$PSScriptRoot\$uploadFolder" -q
}

##########################################################################################
# Searching for the Software form RuckZuck Tools
function get-Software {
    $getReturnedRuckZuckSoftware = @()
    $returnRuckZuckSoftware = Invoke-RestMethod -Uri "$getrzrestapiurl/rest/v2/getcatalog"
    $getReturnedRuckZuckSoftware = $returnRuckZuckSoftware | Select-Object Productname, ShortName, Downloads `
    | Sort-Object ShortName | Out-GridView -Title "Select software to upload" -PassThru
    $selection = $getReturnedRuckZuckSoftware.Shortname

    return $selection
}

##########################################################################################

function get-SoftwareDetails {
    # Get Software from RuckZuck
    $returnRuckZuckSoftware = Invoke-RestMethod -Uri "$getrzrestapiurl/rest/v2/getsoftwares?shortname=$returnedSoftware"
    $getReturnedRuckZuckSoftware = $returnRuckZuckSoftware | Select-Object *

    #$getReturnedRuckZuckSoftware
    return $getReturnedRuckZuckSoftware
}

##########################################################################################

function Create_Detection_File {
    [array]$DetectionContent = $null
    $DetectionContent = '$returnedSoftware =' + "`"$returnedSoftware`""
    $DetectionContent += $Detectiongetrzrestapiurl 
    $DetectionContent += '$returnRuckZuckSoftware = Invoke-RestMethod -Uri ' + '"$getrzrestapiurl/rest/v2/getsoftwares?shortname=$returnedSoftware"'
    $DetectionContent += '$getReturnedRuckZuckSoftware = $returnRuckZuckSoftware.PSDetection'
    $DetectionContent += 'if((Invoke-Expression $getReturnedRuckZuckSoftware) -eq $true){' + "write-host `"App installed`" `n exit 0}else{write-host `"App not installed`" `n exit 1}"

    $DetectionFileContent = $DetectionContent | Out-String
    # test only
    $DetectionFileContent
    New-Item -Path "$PSScriptRoot\$uploadfolder\$detectionFileName$PSInstallFileExtension" -ItemType File -Value $DetectionFileContent -Force
}


##########################################################################################
### Run W32_Applicatoin_Add.ps1 ###
function W32_Application_Add {
    
    Create_Detection_File

    $installcommand = "powershell.exe -executionpolicy Bypass -file `".\$installFileName$PSInstallFileExtension`""
    $uninstallcommand = "powershell.exe -executionpolicy bypass -file `".\$uninstallFileName$PSInstallFileExtension`""

    . "$PSScriptRoot\$PSWin32_Application_Add"

    $SourceFile = (Get-ChildItem -Path $PSScriptRoot\$uploadfolder\ -Filter *.intunewin -Recurse).FullName

    $Publisher = $RZSoftwareWithDetails.Manufacturer

    if ($Publisher -eq $null){
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

##########################################################################################
# Change content of Win32_Application_Add.ps1 Script
function content-change {
    $PSWin32_Application_Add = "Win32_Application_Add.ps1"
    $filecontent = Get-Content -Path "$PSScriptRoot\original-$PSWin32_Application_Add"
    [array]$newcontent = $null

    foreach ($string in $filecontent){
        $newcontent += $string
        if ($string -match "# Sample"){
            break
        }
    }
    $newcontent | set-content -Path .\$PSWin32_Application_Add
}
##########################################################################################

##########################################################################################
# Call objects 
##########################################################################################

# Download W32 App tool
Invoke-WebRequest -Uri $urlw32apptool -OutFile $IntuneWinAppUtil

# Download Win32_Application_Add.ps1
Invoke-WebRequest -Uri $Win32_Application_Add -OutFile "$PSScriptRoot\original-$PSWin32_Application_Add"

# Name of the selected Software
$Software = get-Software

# Create Files and Upload Software via Graph Rest API
foreach ($returnedSoftware in  $Software){
    $uploadFolder = "$returnedSoftware-upload"

    # Create Down-/Upload Folder
    New-Item -ItemType Directory -Path "$PSScriptRoot\$returnedSoftware" -Force
    New-Item -ItemType Directory -Path "$PSScriptRoot\$uploadFolder" -Force

    # Create Install PowerShell File
    New-Item -Path "$PSScriptRoot\$returnedSoftware\$installFileName$PSInstallFileExtension" `
    -ItemType File -Value ".\$applicationrz `"$returnedSoftware`"" -Force

    # Get Software Details
    $RZSoftwareWithDetails = get-SoftwareDetails

    # Create Uninstall PowerShell File
    # $uninstallString = "Start-Transcript -Path `"C:\temp\logent.log`";" + $RZSoftwareWithDetails.PSUninstall + ";stop-transcript"
    $uninstallString = $RZSoftwareWithDetails.PSUninstall
    New-Item -Path "$PSScriptRoot\$returnedSoftware\$uninstallFileName$PSInstallFileExtension" `
    -ItemType File -Value "$uninstallString" -Force

    # Create intunewin
    create-package

    # Change Content of Win32_Application_Add.ps1
    content-change

    # Upload Software via Graph API
    W32_Application_Add
}


##### Report App Selected Apps######
Write-host "-----------------------------------------------------------------"
"Uploaded Software: " + $Software
Write-host "-----------------------------------------------------------------"
