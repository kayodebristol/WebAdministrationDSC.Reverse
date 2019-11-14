<## Script Settings #>
#$VerbosePreference = "Continue"

function Export-WebAdministrationDSC
{
    param(
        <## Prompts the user to specify the FOLDER path where the resulting PowerShell DSC Configuration Script will be saved. #>
        [Parameter(
            Mandatory=$false, 
            HelpMessage = "Specify the FOLDER path where the resulting PowerShell DSC Configuration Script will be saved."
        )][string]$OutputDSCPath = $(Read-Host "Please Enter Output Folder for DSC Configuration (Will be Created as Necessary)"),
        [Parameter(
            Mandatory=$false, 
            HelpMessage = "Target Computer Name; if blank, assume localhost"
        )][string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(
            Mandatory=$false,
            HelpMessage = "Administratative Credentials for remote systems"
        )][System.Management.Automation.PSCredential]$Credentials # = $(Get-Credential -Message "Administrative Account")    

    )
    <## Scripts Variables #>
    $DSCModule = Get-Module -Name xWebAdministration -ListAvailable
    $ReverseDSCModule = Get-Module -Name ReverseDSC -ListAvailable
    
    $DSCPath = $DSCModule | Select-Object -ExpandProperty modulebase # Dynamic path to include the version number as a folder; 
    $DSCPath = $DSCPath -replace '(^\w)(:)', "\\$($env:computername)\$('$1')$"
    
    $ReverseDSCPath = $ReverseDSCModule | Select-Object -ExpandProperty modulebase # Dynamic path to include the version number as a folder; 
    $ReverseDSCPath = $ReverseDSCPath -replace '(^\w)(:)', "\\$($env:computername)\$('$1')$"
    
    $OutputDSCPath = $OutputDSCPath -replace '(^\w)(:)', "\\$($env:computername)\$('$1')$"
    $DSCVersion = ($DSCModule | Select-Object -ExpandProperty version).ToString() # Version of the DSC module for the technology (e.g. 1.0.0.0);
    $configName = "IISConfiguration" # Name of the output configuration. This will be the name that follows the Configuration keyword in the output script;
    
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
        
    }
    <## Ensures the path we specify ends with a Slash, in order to make sure the resulting file path is properly structured. #>
    if(!$OutputDSCPath.EndsWith("\") -and !$OutputDSCPath.EndsWith("/"))
    {
        $OutputDSCPath += "\"
    }

   
    <## This is the main function for this script. It acts as a call dispatcher, calling the various functions required in the proper order to 
    get the full picture of the environment; #>
    $Orchestrator = {
        
        $args[0].getEnumerator() | ForEach-Object{
            New-Variable -name $_.name -value $_.value -Force -ErrorAction:SilentlyContinue | Out-Null
        }

        write-host $DSCPath
        Write-Host $ReverseDSCPath
        
        <# Import the ReverseDSC Core Engine #>
        Import-Module -Name $ReverseDSCPath -Force
        
        $dscConfigContent = ""    
        $dscConfigContent += "<# Generated with WebAdministrationDSC.Reverse " + $version + " #>`r`n"   
        $dscConfigContent += "Configuration $configName`r`n"
        $dscConfigContent += "{`r`n"

        Write-Host "$($ComputerName): Configuring Dependencies..." -BackgroundColor DarkGreen -ForegroundColor White
        
        $dscConfigContent += "    Import-DscResource -ModuleName PSDesiredStateConfiguration`r`n"
        $dscConfigContent += "    Import-DscResource -ModuleName xWebAdministration -ModuleVersion `"" + $Script:DSCVersion  + "`"`r`n"

        $dscConfigContent += "    Node `$Allnodes.nodename`r`n"
        $dscConfigContent += "    {`r`n"

        Write-Host "$($ComputerName): Scanning WebAppPool..." -BackgroundColor DarkGreen -ForegroundColor White
        $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xWebAppPool\MSFT_xWebAppPool.psm1")
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

            $dscConfigContent += "`r`n"
            $dscConfigContent += "        xWebAppPool " + (New-Guid).ToString() + "`r`n        {`r`n"
            $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
            $dscConfigContent += "        }`r`n"
        }
        
        Write-Host "$($ComputerName): Scanning Website..." -BackgroundColor DarkGreen -ForegroundColor White
        $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xWebsite\MSFT_xWebsite.psm1")
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
                    $currentBinding = "MSFT_xWebBindingInformation`r`n            {`r`n"
                    $currentBinding += "                Protocol = `"$($binding.Protocol)`"" + "`r`n"
                    $currentBinding += "                SslFlags = $($binding.sslFlags)" + "`r`n"

                    if ($binding.protocol -match "^http")
                    {
                        $bindingInfo = $binding.bindingInformation.split(":")
                        $ipAddress = $bindingInfo[0]
                        $port = $bindingInfo[1]
                        $hostName = $bindingInfo[2]
                        $currentBinding += "                IPAddress = `"$ipAddress`"" + ";`r`n"
                        $currentBinding += "                Port = $port" + ";`r`n"
                        $currentBinding += "                Hostname = `"$hostName`"" + ";`r`n"
                        if ($binding.CertificateStoreName -eq "My" -or $binding.CertificateStoreName -eq "WebHosting")
                        {
                            if ($null -ne $binding.CertificateHash -and "" -ne $binding.CertificateHash)
                            {
                                $currentBinding += "                CertificateThumbprint = `"$($binding.CertificateHash)`"`r`n"
                            }
                            $currentBinding += "                CertificateStoreName = `"$($binding.CertificateStoreName)`"`r`n"     
                        }       
                    }
                    else
                    {
                        $currentBinding += "                BindingInformation = `"$($binding.bindingInformation)`"" + ";`r`n"
                    }

                    $currentBinding += "            }"

                    $results.BindingInfo += $currentBinding
                }

                $results.LogCustomFields = @();

                [string]$LogCustomFields = $null
                foreach ($customfield in $webSite.logfile.customFields.Collection)
                {   
                    $LogCustomFields += "MSFT_LogCustomFieldInformation`r`n{`r`n"
                    $LogCustomFields += "    logFieldName = `"$($customfield.logFieldName)`"`r`n"
                    $LogCustomFields += "    sourceName = `"$($customfield.sourceName)`"`r`n"
                    $LogCustomFields += "`    sourceType = `"$($customfield.sourceType)`"`r`n"
                    $LogCustomFields += "}"
                }

                $results.LogCustomFields = $LogCustomFields

                $AuthenticationInfo = "MSFT_xWebAuthenticationInformation`r`n            {`r`n"
                        
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
                    $AuthenticationInfo += "                $($authenticationtype.Replace('Authentication','')) = `$" + $prop.Value + "`r`n"
                }

                $results.AuthenticationInfo = $AuthenticationInfo
                $results.LogFlags = $results.LogFlags.Split(",")

                Write-Verbose "All Parameters with values"
                $results | ConvertTo-Json | Write-Verbose

                $dscConfigContent += "        xWebSite " + (New-Guid).ToString() + "`r`n        {`r`n"
                $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                $dscConfigContent += "        }`r`n"
            }

        Write-Host "$($ComputerName): Scanning WebVirtualDirectory..." -BackgroundColor DarkGreen -ForegroundColor White
        $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xWebVirtualDirectory\MSFT_xWebVirtualDirectory.psm1")
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

                        $dscConfigContent += "            xWebVirtualDirectory " + (New-Guid).ToString() + "`r`n            {`r`n"
                        $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                        $dscConfigContent += "            }`r`n"
                    }
                }
            }

        Write-Host "$($ComputerName): Scanning WebApplication..." -BackgroundColor DarkGreen -ForegroundColor White
        $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xWebApplication\MSFT_xWebApplication.psm1")
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

                    $AuthenticationInfo = "MSFT_xWebApplicationAuthenticationInformation`r`n            {`r`n"
                    
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
                        $AuthenticationInfo += "                $($authenticationtype.Replace('Authentication','')) = `$" + $prop.Value + ";`r`n"
                    }

                    $results.AuthenticationInfo = $AuthenticationInfo
                    $results.SslFlags = $results.SslFlags.Split(",")
                    $results.EnabledProtocols = $results.EnabledProtocols.Split(",")

                    Write-Verbose "All Parameters with values"
                    $results | ConvertTo-Json | Write-Verbose

                    $dscConfigContent += "        xWebApplication " + (New-GUID).ToString() + "`r`n        {`r`n"
                    $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                    $dscConfigContent += "        }`r`n"
                }
            }
        }


        Write-Host "$($ComputerName): Scanning WebApplicationHandler..." -BackgroundColor DarkGreen -ForegroundColor White
        $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_WebApplicationHandler\MSFT_WebApplicationHandler.psm1")
            Import-Module $module
            $params = Get-DSCFakeParameters -ModulePath $module
            write-host "$($computerName): Read-WebApplicationHandler DSCPath = $($DSCPath) Module = $($module) "
            $handlers = Get-WebConfigurationProperty -Filter "system.webServer/handlers/Add" -Name '.'

            foreach ($handler in $handlers)
            {
                $params.Name = $handler.name
                $params.Path = "IIS://"
                $params.Location = $handler.location
                $results = Get-TargetResource @params
                $dscConfigContent += "        WebApplicationHandler " + (New-Guid).ToString() + "`r`n        {`r`n"
                $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                $dscConfigContent += "        }`r`n"
            }

        Write-Host "$($ComputerName): Scanning IISFeatureDelegation..." -BackgroundColor DarkGreen -ForegroundColor White
        $path = "system.webServer/*"
        $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xIisFeatureDelegation\MSFT_xIisFeatureDelegation.psm1")
            Import-Module $module
            $ConfigSections = Get-WebConfiguration -Filter $Path -Metadata -Recurse

            foreach ($section in $ConfigSections)
            {
                $params = Get-DSCFakeParameters -ModulePath $module
                $params.Filter = $section.SectionPath.Remove(0,1)
                $params.Path = "MACHINE/WEBROOT/APPHOST"

                try
                {
                    $results = Get-TargetResource @params
                    $dscConfigContent += "        xIISFeatureDelegation " + (New-Guid).ToString() + "`r`n        {`r`n"
                    $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                    $dscConfigContent += "        }`r`n"

            
                    $ChildPath = $section.SectionPath.Remove(0,1) + "/*"
                    $ConfigSections = Get-WebConfiguration -Filter $ChildPath -Metadata -Recurse
                    if ($null -ne $ConfigSections)
                    {
                        Get-IISFeatureDelegation -Path $ChildPath
                    }
                }
                catch{}
            }

        Write-Host "$($ComputerName): Scanning IISLogging..." -BackgroundColor DarkGreen -ForegroundColor White
        $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xIISLogging\MSFT_xIISLogging.psm1")
        Import-Module $module
        $params = Get-DSCFakeParameters -ModulePath $module

        $LogSettings = Get-WebConfiguration -Filter '/system.applicationHost/sites/siteDefaults/Logfile'

        $params.LogPath = $LogSettings.directory
        $results = Get-TargetResource @params
        $results.LogFlags = $results.LogFlags.Split(',')
        $dscConfigContent += "        xIISLogging " + (New-Guid).ToString() + "`r`n        {`r`n"
        $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
        $dscConfigContent += "        }`r`n"

        $dscConfigContent += "`r`n    }`r`n"           
        $dscConfigContent += "}`r`n"

        Write-Host "$($ComputerName): Setting Configuration Data..." -BackgroundColor DarkGreen -ForegroundColor White
        #Sets the DSC Configuration Data for the current server;
        $dscConfigContent += "`$ConfigData = @{`r`n"
        $dscConfigContent += "    AllNodes = @(`r`n"

        $tempConfigDataContent = "    @{`r`n"
        $tempConfigDataContent += "        NodeName = `"$env:COMPUTERNAME`";`r`n"
        $tempConfigDataContent += "        PSDscAllowPlainTextPassword = `$true;`r`n"
        $tempConfigDataContent += "        PSDscAllowDomainUser = `$true;`r`n"
        $tempConfigDataContent += "    }`r`n"    

        $dscConfigContent += $tempConfigDataContent
        $dscConfigContent += ")}`r`n"

        $dscConfigContent += "$configName -ConfigurationData `$ConfigData"
        
        #Prevent known-issues creating additional DSC Configuration file with modifications, this version removes some known-values with empty array or so.
        $dscConfigContent.replace("LogCustomFields = @()","#LogCustomFields = @()").replace("LogtruncateSize","#LogtruncateSize").replace("SslFlags = @()","#SslFlags = @()").Replace("$;", "$false;") | Out-File $outputDSCFile
        

        #region Reverse Functions

        function Read-WebApplicationHandler
        {
            $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_WebApplicationHandler\MSFT_WebApplicationHandler.psm1")
            Import-Module $module
            $params = Get-DSCFakeParameters -ModulePath $module
            write-host "$($computerName): Read-WebApplicationHandler DSCPath = $($DSCPath) Module = $($module) "
            $handlers = Get-WebConfigurationProperty -Filter "system.webServer/handlers/Add" -Name '.'

            foreach ($handler in $handlers)
            {
                $params.Name = $handler.name
                $params.Path = "IIS://"
                $params.Location = $handler.location
                $results = Get-TargetResource @params
                $dscConfigContent += "        WebApplicationHandler " + (New-Guid).ToString() + "`r`n        {`r`n"
                $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                $dscConfigContent += "        }`r`n"
            }
        }

        function Read-IISLogging
        {
            $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xIISLogging\MSFT_xIISLogging.psm1")
            Import-Module $module
            $params = Get-DSCFakeParameters -ModulePath $module

            $LogSettings = Get-WebConfiguration -Filter '/system.applicationHost/sites/siteDefaults/Logfile'

            $params.LogPath = $LogSettings.directory
            $results = Get-TargetResource @params
            $results.LogFlags = $results.LogFlags.Split(',')
            $dscConfigContent += "        xIISLogging " + (New-Guid).ToString() + "`r`n        {`r`n"
            $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
            $dscConfigContent += "        }`r`n"
        }

        function Read-IISFeatureDelegation
        {
            Get-IISFeatureDelegation -Path "system.webServer/*"
        }

        function Get-IISFeatureDelegation($Path)
        {
            $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xIisFeatureDelegation\MSFT_xIisFeatureDelegation.psm1")
            Import-Module $module
            $ConfigSections = Get-WebConfiguration -Filter $Path -Metadata -Recurse

            foreach ($section in $ConfigSections)
            {
                $params = Get-DSCFakeParameters -ModulePath $module
                $params.Filter = $section.SectionPath.Remove(0,1)
                $params.Path = "MACHINE/WEBROOT/APPHOST"

                try
                {
                    $results = Get-TargetResource @params
                    $dscConfigContent += "        xIISFeatureDelegation " + (New-Guid).ToString() + "`r`n        {`r`n"
                    $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                    $dscConfigContent += "        }`r`n"

            
                    $ChildPath = $section.SectionPath.Remove(0,1) + "/*"
                    $ConfigSections = Get-WebConfiguration -Filter $ChildPath -Metadata -Recurse
                    if ($null -ne $ConfigSections)
                    {
                        Get-IISFeatureDelegation -Path $ChildPath
                    }
                }
                catch{}
            }
        }

        function Read-Website()
        {    
            $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xWebsite\MSFT_xWebsite.psm1")
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
                    $currentBinding = "MSFT_xWebBindingInformation`r`n            {`r`n"
                    $currentBinding += "                Protocol = `"$($binding.Protocol)`"" + "`r`n"
                    $currentBinding += "                SslFlags = $($binding.sslFlags)" + "`r`n"

                    if ($binding.protocol -match "^http")
                    {
                        $bindingInfo = $binding.bindingInformation.split(":")
                        $ipAddress = $bindingInfo[0]
                        $port = $bindingInfo[1]
                        $hostName = $bindingInfo[2]
                        $currentBinding += "                IPAddress = `"$ipAddress`"" + ";`r`n"
                        $currentBinding += "                Port = $port" + ";`r`n"
                        $currentBinding += "                Hostname = `"$hostName`"" + ";`r`n"
                        if ($binding.CertificateStoreName -eq "My" -or $binding.CertificateStoreName -eq "WebHosting")
                        {
                            if ($null -ne $binding.CertificateHash -and "" -ne $binding.CertificateHash)
                            {
                                $currentBinding += "                CertificateThumbprint = `"$($binding.CertificateHash)`"`r`n"
                            }
                            $currentBinding += "                CertificateStoreName = `"$($binding.CertificateStoreName)`"`r`n"     
                        }       
                    }
                    else
                    {
                        $currentBinding += "                BindingInformation = `"$($binding.bindingInformation)`"" + ";`r`n"
                    }

                    $currentBinding += "            }"

                    $results.BindingInfo += $currentBinding
                }

                $results.LogCustomFields = @();

                [string]$LogCustomFields = $null
                foreach ($customfield in $webSite.logfile.customFields.Collection)
                {   
                    $LogCustomFields += "MSFT_LogCustomFieldInformation`r`n{`r`n"
                    $LogCustomFields += "    logFieldName = `"$($customfield.logFieldName)`"`r`n"
                    $LogCustomFields += "    sourceName = `"$($customfield.sourceName)`"`r`n"
                    $LogCustomFields += "`    sourceType = `"$($customfield.sourceType)`"`r`n"
                    $LogCustomFields += "}"
                }

                $results.LogCustomFields = $LogCustomFields

                $AuthenticationInfo = "MSFT_xWebAuthenticationInformation`r`n            {`r`n"
                        
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
                    $AuthenticationInfo += "                $($authenticationtype.Replace('Authentication','')) = `$" + $prop.Value + "`r`n"
                }

                $results.AuthenticationInfo = $AuthenticationInfo
                $results.LogFlags = $results.LogFlags.Split(",")

                Write-Verbose "All Parameters with values"
                $results | ConvertTo-Json | Write-Verbose

                $dscConfigContent += "        xWebSite " + (New-Guid).ToString() + "`r`n        {`r`n"
                $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                $dscConfigContent += "        }`r`n"
            }
        }

        function Read-WebVirtualDirectory()
        {    
            $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xWebVirtualDirectory\MSFT_xWebVirtualDirectory.psm1")
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

                        $dscConfigContent += "            xWebVirtualDirectory " + (New-Guid).ToString() + "`r`n            {`r`n"
                        $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                        $dscConfigContent += "            }`r`n"
                    }
                }
            }
        }

        function Read-WebApplication()
        {    
            $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xWebApplication\MSFT_xWebApplication.psm1")
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

                        $AuthenticationInfo = "MSFT_xWebApplicationAuthenticationInformation`r`n            {`r`n"
                        
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
                            $AuthenticationInfo += "                $($authenticationtype.Replace('Authentication','')) = `$" + $prop.Value + ";`r`n"
                        }

                        $results.AuthenticationInfo = $AuthenticationInfo
                        $results.SslFlags = $results.SslFlags.Split(",")
                        $results.EnabledProtocols = $results.EnabledProtocols.Split(",")

                        Write-Verbose "All Parameters with values"
                        $results | ConvertTo-Json | Write-Verbose

                        $dscConfigContent += "        xWebApplication " + (New-GUID).ToString() + "`r`n        {`r`n"
                        $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                        $dscConfigContent += "        }`r`n"
                    }
                }
            }
        }

        function Read-WebAppPool()
        {    
            $module = Resolve-Path ($DSCPath + "\DSCResources\MSFT_xWebAppPool\MSFT_xWebAppPool.psm1")
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

                $dscConfigContent += "`r`n"
                $dscConfigContent += "        xWebAppPool " + (New-Guid).ToString() + "`r`n        {`r`n"
                $dscConfigContent += Get-DSCBlock -Params $results -ModulePath $module -UseGetTargetResource
                $dscConfigContent += "        }`r`n"
            }
        }
        #endregion



    }
    <## Call into our main function that is responsible for extracting all the information about our environment; #>
    foreach($Computer in $computerName){
        $argList = @{
            ComputerName = $Computer
            Version = $DSCVersion
            configName = $configName
            DSCPath = $DSCPath
            ReverseDSCPath = $ReverseDSCPath
            Credentials = $Credentials
            OutputDSCFile =  $OutputDSCPath + $Computer + "WebAdministrationDSC.ps1"
        }
        $session = New-PSSession -ComputerName $Computer -EnableNetworkAccess 
        Invoke-Command -ScriptBlock $Orchestrator -Session $session -AsJob -JobName $Computer -ArgumentList $argList
    }
        
    do{
        Start-Sleep -Seconds 5
        $jobsRunning = (Get-Job | Where-Object{$_.state -eq "Running" } ).count
        $jobsCompleted = (Get-Job | Where-Object{$_.state -eq "Completed" } ).count
        $jobsTotal = (Get-Job).count
        
        $prct = [math]::Round( (($jobsCompleted / $jobsTotal) * 100), 2)
        Write-Progress -Activity "Collecting Data $(get-date)" -Status "Working on $jobsRunning machines" -PercentComplete $prct
        if(get-job){Receive-Job (get-job) -ErrorAction SilentlyContinue}

    }while($jobsCompleted -ne $jobsTotal)        
        
        
        Write-Output "Done."
        
        <## Wait a couple of seconds, then open our $outputDSCPath in Windows Explorer so we can review the glorious output. ##>
        Start-Sleep 2
        Invoke-Item -Path $OutputDSCPath
    
}


