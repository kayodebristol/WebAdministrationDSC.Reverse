<#PSScriptInfo

.VERSION 1.2.0.0

.GUID 8e576300-141f-4381-96ea-a59d1f2837d2

.AUTHOR Microsoft Corporation

.COMPANYNAME Microsoft

.EXTERNALMODULEDEPENDENCIES

.TAGS IIS,ReverseDSC,DesiredStateConfiguration,DSC,DSCResourceKit,DSCResource

.RELEASENOTES

Verbose outputs for all functions
All functions updated to use new Get-DSCBlock parameters introduced in reverseDSC module with 1.9.3.0
Simplified binding information
Added LogCustomFields extraction support 

#>

#Requires -Modules @{ModuleName="ReverseDSC";ModuleVersion="1.9.3.0"},@{ModuleName="xWebAdministration";ModuleVersion="2.3.0.0"}

<# 
.DESCRIPTION 
 Extracts the DSC Configuration of an existing IIS environment, allowing you to analyze it or to replicate it.

#> 

param()

<## Script Settings #>
$VerbosePreference = "Continue"

<## Scripts Variables #>
$Script:dscConfigContent = "" # Core Variable that will contain the content of your DSC output script. Leave empty;
$DSCModule = Get-Module -Name xWebAdministration -ListAvailable
$Script:DSCPath = $DSCModule | Select-Object -ExpandProperty modulebase # Dynamic path to include the version number as a folder;
$Script:DSCVersion = ($DSCModule | Select-Object -ExpandProperty version).ToString() # Version of the DSC module for the technology (e.g. 1.0.0.0);
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
function Read-xWebsite($depth = 2)
{    
    $module = Resolve-Path ($Script:DSCPath + "\DSCResources\MSFT_xWebsite\MSFT_xWebsite.psm1")
    Import-Module $module
    $params = Get-DSCFakeParameters -ModulePath $module
    
    $webSites = Get-WebSite

    foreach($website in $webSites)
    {
        Write-Verbose "WebSite: $($website.name)"
        <# Setting Primary Keys #>
        $params.Name = $website.Name
        Write-Verbose "Key parameters as follows"
        $params | ConvertTo-Json | Write-Verbose

        $results = Get-TargetResource @params
        Write-Verbose "All Parameters as follows"
        $results | ConvertTo-Json | Write-Verbose

        $results.BindingInfo = @();

        foreach($binding in $website.Bindings.Collection)
        {
            $currentBinding = "`r`n" + "`t" * ($depth + 2) + "MSFT_xWebBindingInformation`r`n" + "`t" * ($depth + 2) + "{`r`n"
            $currentBinding += "`t" * ($depth + 3) + "Protocol = `"$($binding.Protocol)`"" + ";`r`n"
            $currentBinding += "`t" * ($depth + 3) + "SslFlags = $($binding.sslFlags)" + ";`r`n"

            if ($binding.protocol -match "^http")
            {
                $bindingInfo = $binding.bindingInformation.split(":")
                $ipAddress = $bindingInfo[0]
                $port = $bindingInfo[1]
                $hostName = $bindingInfo[2]
                $currentBinding += "`t" * ($depth + 3) + "IPAddress = `"$ipAddress`"" + ";`r`n"
                $currentBinding += "`t" * ($depth + 3) + "Port = $port" + ";`r`n"
                $currentBinding += "`t" * ($depth + 3) + "Hostname = `"$hostName`"" + ";`r`n"
                if($binding.CertificateStoreName -eq "My" -or $binding.CertificateStoreName -eq "WebHosting")
                {
                    if($null -ne $binding.CertificateHash -and "" -ne $binding.CertificateHash)
                    {
                        $currentBinding += "`t" * ($depth + 3) + "CertificateThumbprint = `"$($binding.CertificateHash)`";`r`n"
                    }
                    $currentBinding += "`t" * ($depth + 3) + "CertificateStoreName = `"$($binding.CertificateStoreName)`";`r`n"     
                }       
            }
            else
            {
                $currentBinding += "`t" * ($depth + 3) + "BindingInformation = `"$($binding.bindingInformation)`"" + ";`r`n"
            }

            $currentBinding += "`t" * ($depth + 2) + "}"

            $results.BindingInfo += $currentBinding
        }

        $results.LogCustomFields = @();

        [string]$LogCustomFields = $null
        foreach ($customfield in $webSite.logfile.customFields.Collection)
        {   
            $LogCustomFields += "`r`n" + "`t" * ($depth + 2) + "MSFT_xLogCustomFieldInformation`r`n" + "`t" * ($depth + 2) + "{`r`n"
            $LogCustomFields += "`t" * ($depth + 3) + "logFieldName = `"$($customfield.logFieldName)`";`r`n"
            $LogCustomFields += "`t" * ($depth + 3) + "sourceName = `"$($customfield.sourceName)`";`r`n"
            $LogCustomFields += "`t" * ($depth + 3) + "sourceType = `"$($customfield.sourceType)`";`r`n"
            $LogCustomFields += "`t" * ($depth + 2) + "}"
        }

        $results.LogCustomFields = $LogCustomFields

        $AuthenticationInfo = "`r`n" + "`t" * ($depth + 2) + "MSFT_xWebAuthenticationInformation`r`n" + "`t" * ($depth + 2) + "{`r`n"
                
        $AuthenticationTypes = @("BasicAuthentication","AnonymousAuthentication","DigestAuthentication","WindowsAuthentication")

        foreach ($authenticationtype in $AuthenticationTypes)
        {
            Remove-Variable -Name location -ErrorAction SilentlyContinue
            Remove-Variable -Name prop -ErrorAction SilentlyContinue
            $location = $website.Name
            $prop = Get-WebConfigurationProperty `
                -Filter /system.WebServer/security/authentication/$authenticationtype `
                -Name enabled `
                -Location $location
            Write-Verbose "$authenticationtype : $($prop.Value)"
            $AuthenticationInfo += "`t" * ($depth + 3) + "$($authenticationtype.Replace('Authentication','')) = `$" + $prop.Value + ";`r`n"
        }
        $AuthenticationInfo += "`t" * ($depth + 2) + "}"

        $results.AuthenticationInfo = $AuthenticationInfo
        $results.LogFlags = $results.LogFlags.Split(",")

        Write-Verbose "All Parameters with values"
        $results | ConvertTo-Json | Write-Verbose

        $Script:dscConfigContent += "`r`n"
        $Script:dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource `
            -Indent $depth -AsFullConfigurationBlock -FriendlyBlockName "$($website.name)"
    }
}

function Read-xWebVirtualDirectory($depth = 2)
{    
    $module = Resolve-Path ($Script:DSCPath + "\DSCResources\MSFT_xWebVirtualDirectory\MSFT_xWebVirtualDirectory.psm1")
    Import-Module $module

    $webSites = Get-WebSite

    foreach($website in $webSites)
    {
        Write-Verbose "WebSite: $($website.name)"
        $webVirtualDirectories = Get-WebVirtualDirectory -Site $website.name
        
        if($webVirtualDirectories)
        {
            foreach($webvirtualdirectory in $webVirtualDirectories)
            {
                Write-Verbose "WebSite/VirtualDirectory: $($website.name)$($webvirtualdirectory.path)"
                $params = Get-DSCFakeParameters -ModulePath $module

                <# Setting Primary Keys #>
                $params.Name = $webvirtualdirectory.Path
                $params.WebApplication = ""
                $params.Website = $website.Name
                <# Setting Required Keys #>
                #$params.PhysicalPath  = $webapplication.PhysicalPath
                Write-Verbose "Key parameters as follows"
                $params | ConvertTo-Json | Write-Verbose
                
                $results = Get-TargetResource @params

                Write-Verbose "All Parameters with values"
                $results | ConvertTo-Json | Write-Verbose

                $Script:dscConfigContent += "`r`n"
                $Script:dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource `
                    -Indent $depth -AsFullConfigurationBlock -FriendlyBlockName "$($website.name)$($webvirtualdirectory.path)" `
                    -DependsOnClause "[xWebSite]$($website.name)" 
            }
        }
    }
}

function Read-xWebApplication($depth = 2)
{    
    $module = Resolve-Path ($Script:DSCPath + "\DSCResources\MSFT_xWebApplication\MSFT_xWebApplication.psm1")
    Import-Module $module

    $webSites = Get-WebSite

    foreach($website in $webSites)
    {
        Write-Verbose "WebSite: $($website.name)"
        $webApplications = Get-WebApplication -Site $website.name
        
        if($webApplications)
        {
            foreach($webapplication in $webApplications)
            {
                Write-Verbose "WebSite/Application: $($website.name)$($webapplication.path)"
                $params = Get-DSCFakeParameters -ModulePath $module

                <# Setting Primary Keys #>
                $params.Name = $webapplication.Path
                $params.Website = $website.Name
                <# Setting Required Keys #>
                #$params.WebAppPool = $webapplication.applicationpool
                #$params.PhysicalPath  = $webapplication.PhysicalPath
                Write-Verbose "Key parameters as follows"
                $params | ConvertTo-Json | Write-Verbose

                $results = Get-TargetResource @params
                Write-Verbose "All Parameters as follows"
                $results | ConvertTo-Json | Write-Verbose

                $AuthenticationInfo = "`r`n" + "`t" * ($depth + 2) + "MSFT_xWebApplicationAuthenticationInformation`r`n" + "`t" * ($depth + 2) + "{`r`n"
                
                $AuthenticationTypes = @("BasicAuthentication","AnonymousAuthentication","DigestAuthentication","WindowsAuthentication")

                foreach ($authenticationtype in $AuthenticationTypes)
                {
                    Remove-Variable -Name location -ErrorAction SilentlyContinue
                    Remove-Variable -Name prop -ErrorAction SilentlyContinue
                    $location = "$($website.Name)" + "$($webapplication.Path)"
                    $prop = Get-WebConfigurationProperty `
                    -Filter /system.WebServer/security/authentication/$authenticationtype `
                    -Name enabled `
                    -PSPath "IIS:\Sites\$location"
                    Write-Verbose "$authenticationtype : $($prop.Value)"
                    $AuthenticationInfo += "`t" * ($depth + 3) + "$($authenticationtype.Replace('Authentication','')) = `$" + $prop.Value + ";`r`n"
                }
                $AuthenticationInfo += "`t" * ($depth + 2) + "}"

                $results.AuthenticationInfo = $AuthenticationInfo
                $results.SslFlags = $results.SslFlags.Split(",")
                
                Write-Verbose "All Parameters with values"
                $results | ConvertTo-Json | Write-Verbose

                $Script:dscConfigContent += "`r`n"
                $Script:dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource `
                    -Indent $depth -AsFullConfigurationBlock -FriendlyBlockName "$($website.name)$($webapplication.path)" `
                    -DependsOnClause "[xWebSite]$($website.name)"
            }
        }
    }
}

function Read-xWebAppPool($depth = 2)
{    
    $module = Resolve-Path ($Script:DSCPath + "\DSCResources\MSFT_xWebAppPool\MSFT_xWebAppPool.psm1")
    Import-Module $module
    $params = Get-DSCFakeParameters -ModulePath $module
    
    $appPools = Get-WebConfiguration -Filter '/system.applicationHost/applicationPools/add'

    foreach($appPool in $appPools)
    {
        Write-Verbose "Application Pool: $($appPool.name)"
        <# Setting Primary Keys #>
        $params.Name = $appPool.Name
        Write-Verbose "Key parameters as follows"
        $params | ConvertTo-Json | Write-Verbose

        $results = Get-TargetResource @params

        Write-Verbose "All Parameters as follows"
        $results | ConvertTo-Json | Write-Verbose

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

        Write-Verbose "All Parameters with values"
        $results | ConvertTo-Json | Write-Verbose

        $Script:dscConfigContent += "`r`n"
        $Script:dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource `
            -Indent $depth -AsFullConfigurationBlock -FriendlyBlockName "$($appPool.Name)"
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
    $Script:dscConfigContent += "    Import-DscResource -ModuleName xWebAdministration -ModuleVersion `"" + $Script:DSCVersion  + "`"`r`n"
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
     #Prevent known-issues creating additional DSC Configuration file with modifications, this version removes some known-values with empty array or so.
     Get-Content $outputDSCFile | Where-Object {$_ -notmatch "LogtruncateSize"} | Out-File $outputDSCFile.Replace(".ps1",".modified.ps1")
     Write-Output "Done."
     
     <## Wait a couple of seconds, then open our $outputDSCPath in Windows Explorer so we can review the glorious output. ##>
     Start-Sleep 2
     Invoke-Item -Path $OutputDSCPath
}

Get-ReverseDSC
