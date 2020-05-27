function Dump-InstalledPackages
{
    param($InstalledPackages)
    $InstalledPackages | ConvertTo-Json |
        Out-File $script:InstalledPackagesPath -Force
}

function Dump-RegisteredPackageSources
{
    $script:RegisteredPackageSources | Select-Object * -ExcludeProperty Headers | ConvertTo-Json |
        Out-File $script:RegisteredPackageSourcesPath -Force
}

function Get-PackageSources
{
    param(
        [Parameter(Mandatory)]
        $request
    )
    $Sources = if ($request.PackageSources)
    {
        $script:RegisteredPackageSources | Where-Object Name -in $request.PackageSources
    }
    else { $script:RegisteredPackageSources }
    $Sources | Where-Object { -not $_.Headers } | ForEach-Object {
        if ($request.Credential)
        {
            Set-PackageSourcePrivateToken -Source $_.Name -Credential $request.Credential
        }
        else
        {
            $msg = "Credentials are required for source $($_.Name)"
            Write-Error -Message $msg -ErrorId CredentialsNotSpecified -Category InvalidOperation -TargetObject $_.Name
        }
    }
    $Sources
}

function isURI($Address)
{
    # Small function to check if given string is a URL
    $uri = $address -as [System.URI]
    if ($null -ne $uri.AbsoluteURI)
    {
        return $uri
    }
    else
    {
        return $false
    }
}

function Set-PackageSourcePrivateToken
{
    param(
        [Parameter(Mandatory)]
        [string[]] $Source,
        [Parameter(Mandatory)]
        [pscredential] $Credential
    )
    $Source | ForEach-Object {
        $PackageSource = $script:RegisteredPackageSources | Where-Object Name -eq $_
        if (-not $PackageSource.Headers)
        {
            if ($Credential.UserName -eq 'AuthToken')
            {
                $PrivateToken = $Credential.GetNetworkCredential().Password
                $Headers = @{
                    'PRIVATE-TOKEN' = $PrivateToken
                }
                $uri = $PackageSource.Location.TrimEnd('/')
            }
            else
            {
                $Auth = @{
                    grant_type = "password"
                    username   = $Credential.UserName
                    password   = $Credential.GetNetworkCredential().Password
                }
                # Check if given URL is really a url
                $Location = $PackageSource.Location.TrimEnd('/')
                if ($Location)
                {
                    $UriLocation = isURI -Address $Location
                }
                if ($UriLocation)
                {
                    $Location = $UriLocation.Scheme + "://" + $UriLocation.Host
                    if ($Auth)
                    {
                        if ($Location)
                        {
                            $uri = ($Location + "/oauth/token")
                        }
                        if ($uri)
                        {
                            try
                            {
                                $Response_PrivateToken = Invoke-RestMethod -Uri $uri -body $Auth -Method Post -ErrorAction Stop
                            }
                            catch
                            {
                                throw $_.Exception
                            }
                            if ($Response_PrivateToken.token_type -eq "Bearer")
                            {
                                $PrivateToken = $Response_PrivateToken.access_token
                            }
                        }
                        if ($PrivateToken)
                        {
                            $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                            $Headers.Add("Authorization", "Bearer $PrivateToken")
                        }
                    }
                }
            }
            if ($Headers)
            {
                if ($Headers.Authorization)
                {
                    # Test OAUTH2 access_token
                    $uri = $uri + "/info"
                    try
                    {
                        $null = Invoke-RestMethod -Method Get -Headers $Headers -Uri $uri -ErrorAction Stop
                    }
                    catch
                    {
                        throw $_.Exception
                    }
                }
                if ($Headers.'PRIVATE-TOKEN')
                {
                    $uri = $uri + "/version"
                    try
                    {
                        $null = Invoke-RestMethod -Method Get -Headers $Headers -Uri $uri -ErrorAction Stop
                    }
                    catch
                    {
                        throw $_.Exception
                    }
                }
                $PackageSource | Add-Member -MemberType NoteProperty -Name Headers -Value $Headers -TypeName hashtable
            }
        }
    }
}

function ConvertTo-Hashtable
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [array] $Object,
        [int] $Depth = 3
    )
    Process
    {
        foreach ($obj in $Object)
        {
            if (!$Depth) { return $obj }
            $ht = [ordered]@{ }
            if ($obj -as [hashtable])
            {
                ($obj -as [hashtable]).GetEnumerator() | ForEach-Object {
                    if ($_.Value -is [PSCustomObject])
                    {
                        $ht[$_.Key] = ConvertTo-Hashtable ($_.Value) ($Depth - 1)
                    }
                    else
                    {
                        $ht[$_.Key] = $_.Value
                    }
                }
                return $ht
            }
            elseif ($obj.GetType().Name -eq 'PSCustomObject')
            {
                $obj | Get-Member -MemberType Properties | ForEach-Object {
                    $ht[$_.Name] = ConvertTo-Hashtable (, $obj.($_.Name)) ($Depth - 1)
                }
                return $ht
            }
            elseif ($obj -as [array])
            {
                return , $obj
            }
            else
            {
                return $obj
            }
        }
    }
}

function Get-GitSubmodules
{
    param(
        [Parameter(Mandatory)]
        [ValidateScript( { Test-Path $_ })]
        $Path
    )
    (Get-Content $Path -Raw).Split('[]') -ne '' | ForEach-Object -Begin { $i = 0 } {
        if ($i++ % 2) { [PSCustomObject](ConvertFrom-StringData $_) }
    }
}