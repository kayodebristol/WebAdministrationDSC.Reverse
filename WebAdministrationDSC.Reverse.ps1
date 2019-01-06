<#PSScriptInfo

.VERSION 1.0.0.0

.GUID 8e576300-141f-4381-96ea-a59d1f2837d2

.AUTHOR Microsoft Corporation

.COMPANYNAME Microsoft

.EXTERNALMODULEDEPENDENCIES

.TAGS IIS,ReverseDSC

.RELEASENOTES

* Initial Release;
#>

#Requires -Modules @{ModuleName="ReverseDSC";ModuleVersion="1.9.2.0"},@{ModuleName="xWebAdministration";ModuleVersion="1.18.0.0"}

<# 
.DESCRIPTION 
 Extracts the DSC Configuration of an existing IIS environment, allowing you to analyze it or to replicate it.

#> 

param()

<## Script Settings #>
$VerbosePreference = "SilentlyContinue"

<## Scripts Variables #>
$Script:dscConfigContent = "" # Core Variable that will contain the content of your DSC output script. Leave empty;
$Script:DSCPath = Get-Module -Name xWebAdministration -ListAvailable | Select-Object -ExpandProperty modulebase # Dynamic path to include the version number as a folder;
$Script:configName = "IISConfiguration" # Name of the output configuration. This will be the name that follows the Configuration keyword in the output script;

<# Retrieves Information about the current script from the PSScriptInfo section above #>
try {
    $currentScript = Test-ScriptFileInfo $SCRIPT:MyInvocation.MyCommand.Path
    $Script:version = $currentScript.Version.ToString()
}
catch {
    $Script:version = "N/A"
}

<## This is the main function for this script. It acts as a call dispatcher, calling the various functions required in the proper order to 
    get the full picture of the environment; #>
function Orchestrator
{        
    <# Import the ReverseDSC Core Engine #>
    $module = "ReverseDSC"
    Import-Module -Name $module -Force
        
    $Script:dscConfigContent += "<# Generated with WebAdministrationDSC.Reverse " + $script:version + " #>`r`n"   
    $Script:dscConfigContent += "Configuration $Script:configName`r`n"
    $Script:dscConfigContent += "{`r`n"

    Write-Host "Configuring Dependencies..." -BackgroundColor DarkGreen -ForegroundColor White
    Set-Imports

    $Script:dscConfigContent += "    Node `$Allnodes.nodename`r`n"
    $Script:dscConfigContent += "    {`r`n"

    Write-Host "Scanning xWebAppPool..." -BackgroundColor DarkGreen -ForegroundColor White
    Read-xWebAppPool
    
    Write-Host "Scanning xWebsite..." -BackgroundColor DarkGreen -ForegroundColor White
    Read-xWebsite

    Write-Host "Scanning xWebVirtualDirectory..." -BackgroundColor DarkGreen -ForegroundColor White
    Read-xWebVirtualDirectory

    Write-Host "Scanning xWebApplication..." -BackgroundColor DarkGreen -ForegroundColor White
    Read-xWebApplication

    Write-Host "Configuring Local Configuration Manager (LCM)..." -BackgroundColor DarkGreen -ForegroundColor White
    Set-LCM

    $Script:dscConfigContent += "`r`n    }`r`n"           
    $Script:dscConfigContent += "}`r`n"

    Write-Host "Setting Configuration Data..." -BackgroundColor DarkGreen -ForegroundColor White
    Set-ConfigurationData

    $Script:dscConfigContent += "$Script:configName -ConfigurationData `$ConfigData"
}

#region Reverse Functions
function Read-xWebsite()
{    
    $module = Resolve-Path ($Script:DSCPath + "\DSCResources\MSFT_xWebsite\MSFT_xWebsite.psm1")
    Import-Module $module
    $params = Get-DSCFakeParameters -ModulePath $module
    
    $webSites = Get-WebSite

    foreach($website in $webSites)
    {
        <# Setting Primary Keys #>
        $params.Name = $website.Name

        $results = Get-TargetResource @params
        $results.BindingInfo = @();

        foreach($binding in $website.Bindings.Collection)
        {
            $currentBinding = "`r`n                MSFT_xWebBindingInformation`r`n" `
                + "                {`r`n" `
                + "                    Protocol = `"" + $binding.Protocol + "`";`r`n"
            $port = $binding.BindingInformation.Replace(":", "").Replace("*", "").Replace("localhost","")
            if($null -ne $port -and "" -ne $port)
            {
                $currentBinding += "                    Port = " + $binding.BindingInformation.Replace(":", "").Replace("*", "") + ";`r`n"
            }

            if($binding.CertificateStoreName -eq "My" -or $binding.CertificateStoreName -eq "WebHosting")
            {
                if($null -ne $binding.CertificateHash -and "" -ne $binding.CertificateHash)
                {
                    $currentBinding += "                    CertificateThumbprint = `"" + $binding.CertificateHash + "`";`r`n"
                }
                $currentBinding += "                    CertificateStoreName  = `"" + $binding.CertificateStoreName + "`";`r`n"     
            }       
            $currentBinding += "                }"

            $results.BindingInfo += $currentBinding
        }

        $AuthenticationInfo = "`r`n                MSFT_xWebAuthenticationInformation`r`n                {`r`n"
        
        $prop = Get-WebConfigurationProperty `
        -Filter /system.WebServer/security/authentication/BasicAuthentication `
        -Name enabled `
        -Location $website.Name

        $AuthenticationInfo += "                    Basic = `$" + $prop.Value + ";`r`n"

        $prop = Get-WebConfigurationProperty `
        -Filter /system.WebServer/security/authentication/AnonymousAuthentication `
        -Name enabled `
        -Location $website.Name

        $AuthenticationInfo += "                    Anonymous = `$" + $prop.Value + ";`r`n"

        $prop = Get-WebConfigurationProperty `
        -Filter /system.WebServer/security/authentication/DigestAuthentication `
        -Name enabled `
        -Location $website.Name

        $AuthenticationInfo += "                    Digest = `$" + $prop.Value + ";`r`n"

        $prop = Get-WebConfigurationProperty `
        -Filter /system.WebServer/security/authentication/WindowsAuthentication `
        -Name enabled `
        -Location $website.Name

        $AuthenticationInfo += "                    Windows = `$" + $prop.Value + ";`r`n                }`r`n"

        $results.AuthenticationInfo = $AuthenticationInfo
        $results.LogFlags = $results.LogFlags.Split(",")

        $Script:dscConfigContent += "        xWebSite " + '"' + $website.Name + '"' + "`r`n"
        $Script:dscConfigContent += "        {`r`n"
        $Script:dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
        $Script:dscConfigContent += "        }`r`n"
    }
}

function Read-xWebVirtualDirectory()
{    
    $module = Resolve-Path ($Script:DSCPath + "\DSCResources\MSFT_xWebVirtualDirectory\MSFT_xWebVirtualDirectory.psm1")
    Import-Module $module

    $webSites = Get-WebSite

    foreach($website in $webSites)
    {
        $webVirtualDirectories = Get-WebVirtualDirectory -Site $website.name
        
        if($webVirtualDirectories)
        {
            foreach($webvirtualdirectory in $webVirtualDirectories)
            {
                $params = Get-DSCFakeParameters -ModulePath $module

                <# Setting Primary Keys #>
                $params.Name = $webvirtualdirectory.Path
                $params.WebApplication = ""
                $params.Website = $website.Name

                $results = Get-TargetResource @params

                $Script:dscConfigContent += "        xWebVirtualDirectory " + '"' + $website.Name + " " + $webvirtualdirectory.Path + '"' + "`r`n"
                $Script:dscConfigContent += "        {`r`n"
                $Script:dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                $Script:dscConfigContent += "        }`r`n"
            }
        }
    }
}

function Read-xWebApplication()
{    
    $module = Resolve-Path ($Script:DSCPath + "\DSCResources\MSFT_xWebApplication\MSFT_xWebApplication.psm1")
    Import-Module $module

    $webSites = Get-WebSite

    foreach($website in $webSites)
    {
        $webApplications = Get-WebApplication -Site $website.name
        
        if($webApplications)
        {
            foreach($webapplication in $webApplications)
            {
                $params = Get-DSCFakeParameters -ModulePath $module

                <# Setting Primary Keys #>
                $params.Name = $webapplication.Path
                $params.Website = $website.Name

                $results = Get-TargetResource @params

                $AuthenticationInfo = "`r`n                MSFT_xWebApplicationAuthenticationInformation`r`n                {`r`n"
        
                $prop = Get-WebConfigurationProperty `
                -Filter /system.WebServer/security/authentication/BasicAuthentication `
                -Name enabled `
                -Location $website.Name

                $AuthenticationInfo += "                    Basic = `$" + $prop.Value + ";`r`n"

                $prop = Get-WebConfigurationProperty `
                -Filter /system.WebServer/security/authentication/AnonymousAuthentication `
                -Name enabled `
                -Location $website.Name

                $AuthenticationInfo += "                    Anonymous = `$" + $prop.Value + ";`r`n"

                $prop = Get-WebConfigurationProperty `
                -Filter /system.WebServer/security/authentication/DigestAuthentication `
                -Name enabled `
                -Location $website.Name

                $AuthenticationInfo += "                    Digest = `$" + $prop.Value + ";`r`n"

                $prop = Get-WebConfigurationProperty `
                -Filter /system.WebServer/security/authentication/WindowsAuthentication `
                -Name enabled `
                -Location $website.Name

                $AuthenticationInfo += "                    Windows = `$" + $prop.Value + ";`r`n                }`r`n"

                $results.AuthenticationInfo = $AuthenticationInfo
                
                $Script:dscConfigContent += "        xWebApplication " + '"' + $website.Name + " " + $webapplication.Path + '"' + "`r`n"
                $Script:dscConfigContent += "        {`r`n"
                $Script:dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                $Script:dscConfigContent += "        }`r`n"
            }
        }
    }
}

function Read-xWebAppPool()
{    
    $module = Resolve-Path ($Script:DSCPath + "\DSCResources\MSFT_xWebAppPool\MSFT_xWebAppPool.psm1")
    Import-Module $module
    $params = Get-DSCFakeParameters -ModulePath $module
    
    $appPools = Get-WebConfiguration -Filter '/system.applicationHost/applicationPools/add'

    foreach($appPool in $appPools)
    {
        <# Setting Primary Keys #>
        $params.Name = $appPool.Name
        $results = Get-TargetResource @params
        if($appPool.ProcessModel -eq "SpecificUser")
        {
            $securePassword = ConvertTo-SecureString $appPool.ProcessModel.password -AsPlainText
            $creds = New-Object System.Automation.PSCredential($appPool.ProcessModel.username, $securePassword)
            $results.Credential = "`$Creds" + $appPool.ProcessModel.username
        }
        else
        {
            $results.Remove("Credential")
        }

        $Script:dscConfigContent += "        xWebAppPool " + '"' + $appPool.Name + '"' + "`r`n"
        $Script:dscConfigContent += "        {`r`n"
        $Script:dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
        $Script:dscConfigContent += "        }`r`n"
    }
}
#endregion

# Sets the DSC Configuration Data for the current server;
function Set-ConfigurationData
{
    $Script:dscConfigContent += "`$ConfigData = @{`r`n"
    $Script:dscConfigContent += "    AllNodes = @(`r`n"

    $tempConfigDataContent += "    @{`r`n"
    $tempConfigDataContent += "        NodeName = `"$env:COMPUTERNAME`";`r`n"
    $tempConfigDataContent += "        PSDscAllowPlainTextPassword = `$true;`r`n"
    $tempConfigDataContent += "        PSDscAllowDomainUser = `$true;`r`n"
    $tempConfigDataContent += "    }`r`n"    

    $Script:dscConfigContent += $tempConfigDataContent
    $Script:dscConfigContent += ")}`r`n"
}

<## This function ensures all required DSC Modules are properly loaded into the current PowerShell session. #>
function Set-Imports
{
    $Script:dscConfigContent += "    Import-DscResource -ModuleName PSDesiredStateConfiguration`r`n"
    $Script:dscConfigContent += "    Import-DscResource -ModuleName xWebAdministration -ModuleVersion `"" + $DSCVersion  + "`"`r`n"
}

<## This function sets the settings for the Local Configuration Manager (LCM) component on the server we will be configuring using our resulting DSC Configuration script. The LCM component is the one responsible for orchestrating all DSC configuration related activities and processes on a server. This method specifies settings telling the LCM to not hesitate rebooting the server we are configurating automatically if it requires a reboot (i.e. During the SharePoint Prerequisites installation). Setting this value helps reduce the amount of manual interaction that is required to automate the configuration of our SharePoint farm using our resulting DSC Configuration script. #>
function Set-LCM
{
    $Script:dscConfigContent += "        LocalConfigurationManager"  + "`r`n"
    $Script:dscConfigContent += "        {`r`n"
    $Script:dscConfigContent += "            RebootNodeIfNeeded = `$True`r`n"
    $Script:dscConfigContent += "        }`r`n"
}


<# This function is responsible for saving the output file onto disk. #>
function Get-ReverseDSC()
{
    <## Call into our main function that is responsible for extracting all the information about our environment; #>
    Orchestrator

    <## Prompts the user to specify the FOLDER path where the resulting PowerShell DSC Configuration Script will be saved. #>
    $fileName = "WebAdministrationDSC.ps1"
    $OutputDSCPath = Read-Host "Please enter the full path of the output folder for DSC Configuration (will be created as necessary)"
    
    <## Ensures the specified output folder path actually exists; if not, tries to create it and throws an exception if we can't. ##>
    while (!(Test-Path -Path $OutputDSCPath -PathType Container -ErrorAction SilentlyContinue))
    {
        try
        {
            Write-Output "Directory `"$OutputDSCPath`" doesn't exist; creating..."
            New-Item -Path $OutputDSCPath -ItemType Directory | Out-Null
            if ($?) {break}
        }
        catch
        {
            Write-Warning "$($_.Exception.Message)"
            Write-Warning "Could not create folder $OutputDSCPath!"
        }
        $OutputDSCPath = Read-Host "Please Enter Output Folder for DSC Configuration (Will be Created as Necessary)"
    }
    <## Ensures the path we specify ends with a Slash, in order to make sure the resulting file path is properly structured. #>
    if(!$OutputDSCPath.EndsWith("\") -and !$OutputDSCPath.EndsWith("/"))
    {
        $OutputDSCPath += "\"
    }

     <## Save the content of the resulting DSC Configuration file into a file at the specified path. #>
     $outputDSCFile = $OutputDSCPath + $fileName
     $Script:dscConfigContent | Out-File $outputDSCFile
     #Prevent known-issues creating additional DSC Configuration file with modifications, this version removes some known-values with empty array
     Get-Content $outputDSCFile | Where-Object {$_ -notmatch "LogCustomFields|LogtruncateSize|SslFlags = \@\(\)"} | Out-File $outputDSCFile.Replace(".ps1",".modified.ps1")
     Write-Output "Done."
     
     <## Wait a couple of seconds, then open our $outputDSCPath in Windows Explorer so we can review the glorious output. ##>
     Start-Sleep 2
     Invoke-Item -Path $OutputDSCPath
}

Get-ReverseDSC