. $PSScriptRoot\HelperFunctions.ps1

$Platform = [System.Environment]::OSVersion.Platform # Win32NT / MacOSX / Unix

function Initialize-Provider
{
    Write-Verbose "Initializing provider $ProviderName"
    # does not execute!
}

function Get-PackageProviderName
{
    # actual initialization
    if (-not $Initialized)
    {
        [System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        $ConfigFolder = if ($Platform -eq 'Win32NT')
        {
            'C:\ProgramData\GitLabProvider'
        }
        else
        {
            "$PSHome\GitLabProvider"
        }
        if (-not (Test-Path $ConfigFolder)) { New-Item -Type Directory -Path $ConfigFolder }
        $script:RegisteredPackageSourcesPath = "$ConfigFolder\PackageSources.json"
        [array]$script:RegisteredPackageSources = if (Test-Path $RegisteredPackageSourcesPath)
        {
            Get-Content $RegisteredPackageSourcesPath | ConvertFrom-Json | ForEach-Object {
                Add-PackageSource -Name $_.Name -Location $_.Location -Trusted $_.IsTrusted
            }
        }
        else { @() }

        $script:InstalledPackagesPath = "$ConfigFolder\InstalledPackages.json"
        $script:Initialized = $true
    }

    return 'GitLab'
}

function Get-Feature
{
    New-Feature -Name 'supports-powershell-modules'
}

function Get-DynamicOptions
{
    param(
        [Parameter(Mandatory)]
        [Microsoft.PackageManagement.MetaProvider.PowerShell.OptionCategory] $Category
    )
    switch ($Category)
    {
        Package { } # for Find-Package
        Source { } # for Add/Remove-PackageSource
        Provider { } # not used
        # for Install/Uninstall/Get-InstalledPackage
        Install
        {
            New-DynamicOption -Category $Category -Name Location -ExpectedType String -IsRequired $false
            New-DynamicOption -Category $Category -Name User -ExpectedType String -IsRequired $false
            #New-DynamicOption -Category $Category -Name System -ExpectedType String -IsRequired $false
        }
    }
}

function Add-PackageSource
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,
        [Parameter(Mandatory)]
        [string] $Location,
        [Parameter(Mandatory)]
        [bool] $Trusted
    )
    $PSBoundParameters.Registered = $true
    $PackageSource = New-PackageSource @PSBoundParameters
    $script:RegisteredPackageSources += $PackageSource
    Dump-RegisteredPackageSources
    $PackageSource
}

function Remove-PackageSource
{
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )
    $PackageSource = $script:RegisteredPackageSources | Where-Object Name -eq $Name
    if (-not $PackageSource)
    {
        $msg = 'Package source matching the specified name is not registered'
        Write-Error -Message $msg -ErrorId PackageSourceNotFound -Category InvalidOperation -TargetObject $Name
    }
    else
    {
        $script:RegisteredPackageSources = @($script:RegisteredPackageSources) -ne $PackageSource
        Dump-RegisteredPackageSources
    }
}

function Resolve-PackageSources
{
    $SourceName = $request.PackageSources
    if (-not $SourceName)
    {
        return $script:RegisteredPackageSources
    }

    $SourceName | ForEach-Object {
        if ($request.IsCanceled) { return }
        $PackageSource = $script:RegisteredPackageSources | Where-Object Name -like $_
        if (-not $PackageSource)
        {
            $msg = "Package source matching the name $_ not registered"
            Write-Error -Message $msg -ErrorId PackageSourceNotFound -Category InvalidOperation -TargetObject $_
        }
        else { $PackageSource }
    }
}

function Find-Package
{
    param(
        #[Parameter(Mandatory)
        [string[]] $Name,
        [string] $RequiredVersion,
        [string] $MinimumVersion,
        [string] $MaximumVersion = "$([int]::MaxValue).0"
    )
    if (-not $MinimumVersion)
    {
        $MinimumVersion = '0.0'
    }
    if (-not $MaximumVersion)
    {
        $MaximumVersion = "$([int]::MaxValue).0"
    }
    $request | Export-Clixml -Path "c:\sysadmin\request.xml"
    $Options = $request.Options
    $Sources = Get-PackageSources $request
    foreach ($Source in $Sources)
    {
        if ($request.IsCanceled) { return }
        $h = @{Headers = $Source.Headers }
        if (-not $Name) { $Name = '*' }
        $Name | ForEach-Object {
            if ($_ -eq '*')
            {
                $Projects = Invoke-RestMethod @h ($Source.Location + '/search?scope=projects&search=')
            }
            else
            {
                $Projects = Invoke-RestMethod @h ($Source.Location + "/search?scope=projects&search=$_")
            }

            foreach ($Project in $Projects)
            {
                $ProjectId = $Project.id
                $Tags = Invoke-RestMethod @h ($Source.Location + "/projects/$ProjectId/repository/tags")
                $Tags | Sort-Object name -Descending | Where-Object { [System.Version]($_.name) -ge $MinimumVersion -and
                    [System.Version]($_.name) -le $MaximumVersion -and
                    (-not $RequiredVersion -or $_.name -eq $RequiredVersion)
                } -pv Tag | ForEach-Object {
                    $TagName = $Tag.name
                    $CommitId = $Tag.commit.id

                    # retrieve dependencies
                    $RepositoryTree = Invoke-RestMethod @h ($Source.Location + "/projects/$ProjectId/repository/tree?ref_name=$CommitId")

                    $ManifestFileBlobId = ($RepositoryTree | Where-Object Name -like *.psd1).id
                    $ManifestFilePath = [System.IO.Path]::GetTempFileName()
                    Invoke-WebRequest @h ($Source.Location + "/projects/$ProjectId/repository/blobs/$ManifestFileBlobId/raw") -OutFile $ManifestFilePath
                    $ModuleManifest = Invoke-Expression (Get-Content $ManifestFilePath -Raw)
                    Remove-Item $ManifestFilePath

                    $SubmodulesFileBlobId = ($RepositoryTree | Where-Object Name -eq .gitmodules).id
                    if ($SubmodulesFileBlobId)
                    {
                        $SubmodulesFilePath = [System.IO.Path]::GetTempFileName()
                        Invoke-WebRequest @h ($Source.Location + "/projects/$ProjectId/repository/blobs/$SubmodulesFileBlobId/raw") -OutFile $SubmodulesFilePath
                        $Submodules = Get-GitSubmodules $SubmodulesFilePath
                        Remove-Item $SubmodulesFilePath
                    }

                    # GitLab / PSGallery / chocolatey / nuget
                    $Dependencies = New-Object System.Collections.ArrayList
                    @($ModuleManifest.PrivateData.RequiredPackages) -ne $null | ForEach-Object {
                        $Dependency = $_.CanonicalId.Split(':/#') # 'nuget:Microsoft.Exchange.WebServices/2.2#nuget.org'
                        [void]$Dependencies.Add((New-Dependency @Dependency))
                    }
                    $Swid = @{
                        Name              = $Project.name
                        Version           = $TagName #[System.Version]$Tag
                        VersionScheme     = 'MultiPartNumeric'
                        Source            = $Source.Name
                        Summary           = $Project.description
                        FullPath          = $Source.Location + "/projects/$ProjectId/repository/archive.zip?sha=$TagName" # zip download link
                        FromTrustedSource = $true
                        Filename          = ''
                        SearchKey         = ''
                        Details           = @{
                            CommitId   = $CommitId
                            Submodules = @($Submodules)
                        }
                        Entities          = @()
                        Links             = @()
                        Dependencies      = $Dependencies # array of json
                        #TagId <string>
                    }
                    $Swid.FastPackageReference = $Swid | ConvertTo-Json -Depth 3
                    New-SoftwareIdentity @Swid
                    if (-not $Options.AllVersions) { continue }
                }
}
}
}
}

function Download-Package
{
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $FastPackageReference,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Location
    )
    $Options = $request.Options
    $Sources = Get-PackageSources $request
    $PackageInfo = $FastPackageReference | ConvertFrom-Json
    $Source = $Sources | Where-Object Name -eq $PackageInfo.Source
    $h = @{Headers = $Source.Headers }

    if (-not (Test-Path $Location)) { New-Item -Type Directory -Path $Location }
    Push-Location $Location
    New-Item -Type Directory -Path $PackageInfo.Name -ea SilentlyContinue
    Invoke-WebRequest @h -Uri $PackageInfo.FullPath -OutFile package.zip
    Expand-Archive -Path package.zip -DestinationPath .
    $UncompressedPath = "$($PackageInfo.Name)-$($PackageInfo.Version)-$($PackageInfo.Details.CommitId)"
    # Submodule handling (from the same source)
    $PackageInfo.Details.Submodules -ne $null | ForEach-Object {
        $RepositoryTreeUrl = $PackageInfo.FullPath -replace [regex]::Escape("/archive.zip?sha=$($PackageInfo.Version)"), "/tree?ref=$($PackageInfo.Details.CommitId)"
        $RepositoryTree = Invoke-RestMethod @h -Uri $RepositoryTreeUrl
        $SubmoduleCommitId = ($RepositoryTree | Where-Object name -eq $_.path).id
        Invoke-WebRequest @h -Uri ($_.url + "/repository/archive.zip?ref=$SubmoduleCommitId") -OutFile submodule.zip
        Expand-Archive -Path submodule.zip -DestinationPath .
        $UncompressedSubmodulePath = (Resolve-Path "*$SubmoduleCommitId").Path
        Move-Item -Path ($UncompressedSubmodulePath + '\*') -Destination (Join-Path $UncompressedPath $_.path)
        Remove-Item submodule.zip
        Remove-Item $UncompressedSubmodulePath
    }
    Rename-Item -Path $UncompressedPath -NewName $PackageInfo.Version -PassThru |
        Move-Item -Destination $PackageInfo.Name
    Remove-Item package.zip
    Pop-Location

    $Swid = $PackageInfo | ConvertTo-Hashtable
    $Swid.FastPackageReference = $FastPackageReference
    New-SoftwareIdentity @Swid
}

function Install-Package
{
    param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )
    if ($request.Options.ContainsKey('Location'))
    {
        $Location = $request.Options.Location
    }
    elseif ($request.Options.User)
    {
        if ($Platform -eq 'Win32NT')
        {
            if ($PSVersionTable.PSVersion.Major -lt 6)
                {
                    $Location = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
                }
                else
                {
                    $Location = "$env:USERPROFILE\Documents\PowerShell\Modules"
                }
        }
        else
        {
            $Location = "$env:HOME/.local/share/powershell"
        }
    }
    else
    {
        if ($Platform -eq 'Win32NT')
        {
                        if ($PSVersionTable.PSVersion.Major -lt 6)
                {
                    $Location = 'C:\Program Files\WindowsPowerShell\Modules'
                }
                else
                {
                    $Location =  'C:\Program Files\PowerShell\Modules'
                }            
        }
        else
        {
            $Location = '/usr/local/share/powershell/Modules'
        }
    }
    if (-not (Test-Path $Location)) { New-Item -Type Directory -Path $Location }
    Download-Package @PSBoundParameters -Location $Location
    $Swid = $FastPackageReference | ConvertFrom-Json
    $Param = @{
        MemberType = 'NoteProperty'
        Name       = 'Location'
        Value      = $Location
        TypeName   = 'string'
    }
    [array]$script:InstalledPackages = if (Test-Path $script:InstalledPackagesPath)
    {
        Get-Content $script:InstalledPackagesPath | ConvertFrom-Json
    }
    else { @() }
    $InstalledPackages += $Swid | Add-Member @Param -PassThru
    Dump-InstalledPackages $InstalledPackages
}

function Uninstall-Package
{
    param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )
    $Swid = $FastPackageReference | ConvertFrom-Json
    #[array]$InstalledPackages = Get-Content $InstalledPackagesPath | ConvertFrom-Json
    $Package = $script:InstalledPackages | Where-Object { $_.Name -eq $Swid.Name -and $_.Version -eq $Swid.Version }
    $Location = Join-Path $Package.Location $Swid.Name
    Remove-Item "$Location\$($Swid.Version)" -Recurse -Force
    if (-not (Test-Path "$Location\*"))
    {
        Remove-Item $Location
    }
    $InstalledPackages = $InstalledPackages -ne $Package
    Dump-InstalledPackages $InstalledPackages
}

function Get-InstalledPackage
{
    param(
        [string] $Name,
        [string] $RequiredVersion,
        [string] $MinimumVersion,
        [string] $MaximumVersion = "$([int]::MaxValue).0"
    )
    if (-not $MinimumVersion)
    {
        $MinimumVersion = '0.0'
    }
    if (-not $MaximumVersion)
    {
        $MaximumVersion = "$([int]::MaxValue).0"
    }


    [array]$script:InstalledPackages = if (Test-Path $script:InstalledPackagesPath)
    {
        Get-Content $script:InstalledPackagesPath | ConvertFrom-Json
    }
    else { @() }
    $InstalledPackages | Where-Object Name -match $Name | Sort-Object Version -Descending | Where-Object {
        [System.Version]($_.Version) -ge $MinimumVersion -and
        [System.Version]($_.Version) -le $MaximumVersion -and
        (-not $RequiredVersion -or $_.Version -eq $RequiredVersion)
    } | Where-Object Location -match ([regex]::Escape($request.Options.Location)) |
        Select-Object * -ExcludeProperty Location | ForEach-Object {
            $Swid = ConvertTo-Hashtable $_
            $Swid.FastPackageReference = $_ | ConvertTo-Json -Depth 3
            New-SoftwareIdentity @Swid
        }
}

function Get-PackageDependencies
{
    param(
        [Parameter(Mandatory)]
        [string] $FastPackageReference
    )
    $Swid = $FastPackageReference | ConvertFrom-Json
    $Swid.Dependencies | ForEach-Object {
        Find-Package -Name $_.PackageName -RequiredVersion $_.Version
        #ProviderName,Source
    }
}