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

PS> extension -name "File"
File.txt

.LINK
https://tech.wanjabachmann.ch/
#>

# RuckZuck Global
$detectionFileName = "detectionrule"
$installFileName = "install"
$uninstallFileName = "uninstall"
$PSInstallFileExtension = ".ps1"
$getrzrestapiurl = Invoke-RestMethod -Uri "https://ruckzuck.tools/rest/v2/geturl"
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

# Create Application Package
function create-package {
    
    Invoke-WebRequest -Uri $applicationurlrz -OutFile "$PSScriptRoot\$returnedSoftware\$applicationrz" 
    
    # IntuneWinAppUtil -c <source_folder> -s <source_setup_file> -o <output_folder> <-q>
    &$IntuneWinAppUtil -c "$PSScriptRoot\$returnedSoftware" -s "$applicationrz" -o "$PSScriptRoot\$uploadFolder" -q
}


# Searching for the Software form RuckZuck Tools
function get-Software {
    # Get Software from RuckZuck
    $getSoftwareFromRuckZuck = Read-Host -Prompt "Input Software Name to upload "
    $returnRuckZuckSoftware = Invoke-RestMethod -Uri "$getrzrestapiurl/rest/v2/getcatalog"
    $getReturnedRuckZuckSoftware = $returnRuckZuckSoftware | Select-Object Productname, ShortName, Downloads `
    | Sort-Object ShortName | Where-Object {$_.ShortName -match "$getSoftwareFromRuckZuck"}

    # Add Elements to Hash Table
    $menu = $null
    $menu = @{}
    if ($getReturnedRuckZuckSoftware.count -eq $null){
        $j = 1
    }else{
        $j = $getReturnedRuckZuckSoftware.count
    }

    for ($i=1;$i -le $j; $i++) {
        Write-Host "$i. $($getReturnedRuckZuckSoftware[$i-1].Shortname)"
        $menu.Add($i,($getReturnedRuckZuckSoftware[$i-1].Shortname))
    }

    [int]$ans = Read-Host "`n Enter selection"
    $selection = $menu.Item($ans)

    Write-Host "`n Selected:" $selection

    return $selection
}


function get-SoftwareDetails {
    # Get Software from RuckZuck
    $returnRuckZuckSoftware = Invoke-RestMethod -Uri "$getrzrestapiurl/rest/v2/getsoftwares?shortname=$returnedSoftware"
    $getReturnedRuckZuckSoftware = $returnRuckZuckSoftware | Select-Object *

    #$getReturnedRuckZuckSoftware
    return $getReturnedRuckZuckSoftware
}


### Run W32_Applicatoin_Add.ps1 ###
function W32_Application_Add {
    # Create Detection PowerShell File
    $psdetection = $RZSoftwareWithDetails.PSDetection
    $detectionString = '[bool]$psdetectionout =' + "$psdetection `n" + 'if($psdetectionout -eq $true){' + "write-host `"Dynamic Version`" `n exit 0}else{exit 1}"

    New-Item -Path "$PSScriptRoot\$uploadfolder\$detectionFileName$PSInstallFileExtension" `
    -ItemType File -Value $detectionString -Force

    $installcommand = "powershell.exe -executionpolicy Bypass -file `".\$installFileName$PSInstallFileExtension`""
    $uninstallcommand = "powershell.exe -executionpolicy bypass -file `".\$uninstallFileName$PSInstallFileExtension`""

    . "$PSScriptRoot\$PSWin32_Application_Add"

    $SourceFile = (Get-ChildItem -Path $PSScriptRoot\$uploadfolder\ -Filter *.intunewin -Recurse).FullName

    $Publisher = $RZSoftwareWithDetails.Manufacturer

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

################
# Call objects #
################

# Download W32 App tool
Invoke-WebRequest -Uri $urlw32apptool -OutFile $IntuneWinAppUtil

# Download Win32_Application_Add.ps1
Invoke-WebRequest -Uri $Win32_Application_Add -OutFile "$PSScriptRoot\original-$PSWin32_Application_Add"

# Name of the selected Software
$returnedSoftware = get-Software
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

##### Report App ######
Write-host "-----------------------------------------------------------------"
"Uploaded Software: " + $returnedSoftware
Write-host "-----------------------------------------------------------------"