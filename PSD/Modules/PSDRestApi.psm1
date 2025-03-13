<#
.SYNOPSIS
    PSD RestAPI communication module

.DESCRIPTION
    This module provides additional functions to allow PSD to
    communicate with a RestAPI server

.LINK

.NOTES
    FileName: PSDRestApi.psm1
    Solution: PowerShell Deployment for MDT
    Purpose:  Module for communicating with a RestAPI (eg. RestPS)
    Author:   Malte Hohmann
    Contact:  @daooze 
    Primary:  @daooze
    Created:  2025-01-29
    Modified: 2025-02-27
    License:  MIT License (https://opensource.org/licenses/MIT)

    Version - 0.0.1 - (@daooze) - Finalized functional version 1.

    This file includes Test-Tls function, (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>

.Example
#>

# Some variables used in functions.
$script:MaxQueryLength = 2048 # The maximum length of the query string sent by a GET request.
$script:BlacklistedParameters = @('_SMS*', '*USERPASSWORD')  # The names of parameters that shall not be submitted to the RestAPI server, compared using -like.

function Test-Tls {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .LINK
    https://gist.github.com/jborean93/52a56d28cb658000b64d82d900b5e882

    .NOTES
    Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
    MIT License (see LICENSE or https://opensource.org/licenses/MIT)

    .Example
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $HostName,

        [Parameter()]
        [int]
        $Port = 443,

        [Parameter()]
        [System.Security.Authentication.SslProtocols[]]
        $TlsVersion = [System.Security.Authentication.SslProtocols]::Default,
        
        [Parameter()]
        [string]
        $SNIName
    )

    $tcp = [System.Net.Sockets.TcpClient]::new()
    $tcp.SendTimeout = 2000
    $ssl = $null
    try {
        $tcp.Connect($HostName, $port)
        $validationState = @{}
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, {
            param($SslSender, $Certificate, $Chain, $SslPolicyErrors)

            $validationState.PolicyErrors = $SslPolicyErrors

            $true
        })
        
        $sslHost = $HostName
        if ($SNIName) {
            $sslHost = $SNIName
        }
        $ssl.AuthenticateAsClient($sslHost, $null, $TlsVersion, $true)

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)

        [PSCustomObject]@{
            SslProtocol = $ssl.SslProtocol
            NegotiatedCipherSuite = $ssl.NegotiatedCipherSuite  # Only works with pwsh 7+
            Certificate = $cert
            ValidationErrors = $validationState.PolicyErrors
        }
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        $tcp.Dispose()
    }
}

function Get-BasicAuthString {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .LINK

    .NOTES
    Copyright: (c) 2025, Malte Hohmann (@daooze)
    MIT License (see LICENSE or https://opensource.org/licenses/MIT)

    .Example
    #>
    param(
    [PSCredential]$Credential = $null
    )

    process {
        return "Basic " + [Convert]::ToBase64String([Text.Encoding]::Default.GetBytes($Credential.UserName + ':' + $Credential.GetNetworkCredential().Password))
    }
}

function Convert-IniSectionToRestApiParam {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .LINK

    .NOTES
    Copyright: (c) 2025, Malte Hohmann (@daooze)
    MIT License (see LICENSE or https://opensource.org/licenses/MIT)

    .Example
    #>
    param(
    [Parameter(Mandatory)]
    [hashtable]$Section
    )

    process {
        [hashtable]$param = @{}
        $TSEnv = Get-ChildItem tsenv:

        # RestURI is mandatory!
        if (-not [string]::IsNullOrWhiteSpace($Section['RestURI'])) {
            try {
                $uri = Expand-Variables -String $Section['RestURI'].Trim('"') -Variables $TSEnv
                $param['RestURI'] = [Uri]::new($uri)
            }
            catch { throw }
        }
        else {
            throw "The section does not contain the key 'RestURI' which is mandatory for Rest processing"
        }

        # User credentials need to be passed as [PSCredential] type.
        if (-not ([string]::IsNullOrWhiteSpace($Section['AuthUser']))) {
            if ([string]::IsNullOrWhiteSpace($Section['AuthPassword'])) {
                throw "User for access to RestAPI is defined but password is missing"
            }
            else {
                # 
                $username = Expand-Variables -String $Section['AuthUser'].Trim('"') -Variables $TSEnv
                $userpwd = Expand-Variables -String $Section['AuthPassword'] -Variables $TSEnv

                # If the password is enclosed in double quotes, remove those quotes.
                if ($userpwd[0] -eq $userpwd[-1] -eq '"') {$userpwd = $userpwd.Substring(1, $userpwd.Length -2)}

                $param['Credential'] = [pscredential]::new($username, (ConvertTo-SecureString -String $userpwd -AsPlainText -Force))
            }
        }

        :rest_params foreach ($item in $section.GetEnumerator()) {
            # Skip comments.
            if ($item.Name[0] -in ';','#' -or $item.Name.ToUpper().StartsWith('COMMENT')) { continue }

            # Only process well known named keys, skip processing
            # of all others.
            Remove-Variable np -ErrorAction SilentlyContinue
            switch ($item.Name) {
                "Parameters" {
                    # We cannot use a hashtable for the parameters as hashtables
                    # are unsorted, which may result in a wrong order of parameters.
                    # As we want parameters to be checkable "in order of appearance",
                    # we use an array of PSCustomObject´s instead.
                    $np = [ordered]@{}

                    foreach ($p in ($item.Value -split ',').Trim('" ')) {
                        # Skip empty parameter names.
                        if ([string]::IsNullOrEmpty($p)) { continue }

                        # Retrieve the current value. If it is unset or empty
                        # we skip that parameter.
                        :param_loop foreach ($v in (Get-ChildItem tsenv:$p -ErrorAction SilentlyContinue)) {
                            # Skip blacklisted parameters.
                            foreach ($b in $script:BlacklistedParameters) {
                                ##Write-Host "Compare '$($v.Name)' and '$b'" -ForegroundColor Yellow
                                if ($v.Name -like $b) { continue param_loop }
                            }

                            # Every parameter may only be added once. First one wins.
                            if ($np.Contains($v.Name)) { continue }

                            # Skip parameters with empty or whitespace value.
                            if ([string]::IsNullOrWhiteSpace($v.Value)) { continue }

                            # Add parameter and value to the list of parameters.
                            $np.Add($v.Name, $v.Value)
                        }
                    }

                    # Do not add parameters when the list is empty.
                    if ($np.Count -eq 0) { continue rest_params }
                    $item.Value = $np
                    break
                }

                "ParameterCondition" {
                    $item.Value = $item.Value.Trim('" ')
                    # Do not add parameter if the value is empty.
                    if ([string]::IsNullOrWhiteSpace($item.Value)) { continue rest_params }
                    break
                }

                "RestMethod" {
                    $item.Value = $item.Value.Trim('" ').ToUpper()
                    # Do not add parameter if the value is empty.
                    if ([string]::IsNullOrWhiteSpace($item.Value)) { continue rest_params }
                    break
                }

                "SslProtocol" {
                    [string[]]$np = $null
                    foreach ($p in ($item.Value -split ',').Trim('" ')) {
                        # Skip empty values.
                        if ([string]::IsNullOrEmpty($p)) { continue }

                        # Skip double values.
                        if ($np.Where({$_ -eq $p})) { continue }

                        try {
                            $np += [enum]::Parse([System.Security.Authentication.SslProtocols], $p, $true)
                        } catch {
                            throw "Parameter 'SslProtocol' defines SSL protocol '$p' which is not in the list of supported SSL protocols. See https://learn.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols?view=netframework-4.8.1 for supported values."
                        }
                    }

                    # Do not add an empty array.
                    if ($np.Count -eq 0) { continue rest_params }
                    $item.Value = $np
                    break
                }

                "ServerCertificateThumbprint" {
                    [string[]]$np = $null
                    foreach ($p in ($item.Value -split ',').Trim('" ')) {
                        $p = Expand-Variables -String $p -Variables $TSEnv

                        # Skip empty values.
                        if ([string]::IsNullOrEmpty($p)) { continue }

                        # Skip double values.
                        if ($np.Where({$_ -eq $p})) { continue }

                        $np += $p
                    }

                    # Do not add an empty array.
                    if ($np.Count -eq 0) { continue rest_params }
                    $item.Value = $np
                    break
                }

                "ClientCertificate" {
                    [string]$np = Expand-Variables -String $item.Value.Trim('" ') -Variables $TSEnv

                    # If the definition of the client certificates ends with .pfx or .p12 we
                    # consider it being a certificate file, so we need to find it.
                    if ($np -match '\.(pfx|p12)$') {
                        $found = $false

                        # Find certificate in the usual certificate paths.
                        foreach ($CertificateLocation in "$($env:SYSTEMDRIVE)\Deploy\Certificates", "$($env:SYSTEMDRIVE)\MININT\Certificates") {
                            $CertFilepath = Join-Path -Path $CertificateLocation -ChildPath $np
                            
                            if (Test-Path -Path $CertFilepath -PathType Leaf) {
                                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): Found certificate file $CertFilepath"
                                $np = $CertFilepath
                                $found = $true
                                break
                            }
                        }

                        # If still no certificate is available, try to find it in the deployment share.
                        # Get-PSDContent() always throws a fatal error if the specified content
                        # could not be retrieved !!
                        if (-not $found) {
                            $item.Value = Get-PSDContent -content $np
                        }
                        else {
                            $item.Value = $np
                        }
                    }
                    else {
                        $item.Value = $np
                    }

                    # Do not add parameter if the value is empty.
                    if ([string]::IsNullOrWhiteSpace($item.Value)) { continue rest_params }
                    break
                }

                "ClientCertificatePassword" {
                    $np = Expand-Variables -String $item.Value -Variables $TSEnv
                    # If the given password is enclosed in double quotes, remove those quotes.
                    if ($item.Value[0] -eq $item.Value[-1] -eq '"') {$item.Value = $item.Value.Substring(1, $item.Value.Length -2)}

                    # Do not add parameter if the value is empty.
                    if ([string]::IsNullOrWhiteSpace($item.Value)) { continue rest_params }
                    break
                }

                "SendCredentialsOverInsecureConnection" {
                    if ($item.Value.Trim('"'' ') -eq 'I know what I am doing') {
                        $item.Name = 'Force'
                        $item.Value = $true
                    }
                    else {
                        continue rest_params
                    }
                    break
                }

                default { continue rest_params}
            }

            # Add parameters
            if ($param.ContainsKey($item.Name)) {
                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): Changing value of parameter '$($item.Name)'"
                $param[$item.Name] = $item.Value
            }
            else {
                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): Setting value of parameter '$($item.Name)'"
                $param.Add($item.Name, $item.Value)
            }
        }

        return $param
    }
}

function Convert-RestApiResult {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .LINK

    .NOTES
    Copyright: (c) 2025, Malte Hohmann (@daooze)
    MIT License (see LICENSE or https://opensource.org/licenses/MIT)

    .Example
    #>
    [CmdletBinding()]
    param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [PSCustomObject]$Result,

    [string]$MetadataVariable = ''
    )

    begin {
        if ($MetadataVariable -ne '') {
            $metadata = New-Variable -Name $MetadataVariable -Scope 2 -Value ([hashtable]@{}) -Force -PassThru
        }
        else {
            $metadata = $null
        }
    }

    process {
        $section = [ordered]@{}

        ##foreach ($key in ($restapi_result | Get-Member -MemberType NoteProperty).Name) {
        foreach ($r in $Result.PSObject.Properties.Where({$_.MemberType -eq 'NoteProperty'})) {
            # Write debugging info about retrieved data.
            Write-PSDDebugLog -Message "$($MyInvocation.MyCommand.Name): RestAPI sent parameter '$($r.Name)' with value '$($r.Value)'"

            # Ignore all keys beginning with the string '_RestAPI_Metadata'
            if ($r.Name -like '_RestAPI_Metadata*') {
                if ($metadata -ne $null) {
                    # Do not overwrite existing values.
                    if (-not $metadata.Value.ContainsKey($r.Name)) {
                        $metadata.Value.Add($r.Name, $r.Value)
                    }
                }
                continue
            }

            if ($section.Contains($r.Name)) {
                $section.Item($r.Name) = $r.Value
            }
            else {
                $section.Add($r.Name, $r.Value)
            }
        }

        if ($section.Count -gt 0) {
            Write-Output $section
        }
    }
}

function Expand-Variables {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .LINK

    .NOTES
    Copyright: (c) 2025, Malte Hohmann (@daooze)
    MIT License (see LICENSE or https://opensource.org/licenses/MIT)

    .Example
    #>
    [CmdletBinding()]
    param(
    [AllowEmptyString()]
    [Parameter(Mandatory, ValueFromPipeline)]
    [string]$String,

    [Parameter(Mandatory)]
    $Variables,

    [bool]$Recursive = $true,

    [int]$MaxDepth = $null
    )

    begin {
        # Initalize loop detection for recursive calls to this function.
        if ($Recursive) {
            if ((Get-PSCallStack | Select-Object -First 2)[1].Command -eq $MyInvocation.MyCommand.Name) {
                # Recursive function call
                if ($varname -ne $null) { $RecursedVars += $varname.ToUpper() }
            }
            else {
                # None-recursive function call
                New-Variable -Name RecursedVars -Value ([string[]]@()) -Scope private
            }
        }

        # Build hashtable of provided $Variables
        [hashtable]$vars = @{}
        try {
            if ($Variables -is [hashtable]) {
                $vars = $Variables
            }
            elseif ($Variables -is [object]) {
                foreach ($o in $Variables.GetEnumerator()) {
                    $vars.Add($o.Name, $o.Value)
                }
            }
        }
        catch {}
    }

    process {
        $pos = 0
        $p1  = -1
        $p2  = -1

        do {
            if (($p1 = $String.IndexOf('%', $pos)) -ge $pos -and ($p2 = $String.IndexOf('%', $p1+1)) -ge $p1) {
                $varname = $String.Substring($p1+1, $p2-$p1-1).ToUpper()

                if ($varname -match '^[a-z0-9-_]+$') {
                    if ($vars.ContainsKey($varname)) {
                        if ($Recursive) {
                            # Check if the current variable name has already been used
                            # in the recursive variable chain. We do not recurse into
                            # the same variable again as that would cause an infinite loop.
                            if ($Recursive -and $RecursedVars.Contains($varname)) {
                                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): Infinite loop detected while replacing content of variable '$varname'. The variable name is repeatedly used after $($RecursedVars.Count - $RecursedVars.IndexOf($varname)) replacements." -LogLevel 3
                                throw "Infinite loop detected while replacing content of variable '$varname'. The variable name is repeatedly used after $($RecursedVars.Count - $RecursedVars.IndexOf($varname)) replacements."
                                $pos = $p2
                                continue
                            }
                
                            $replacement = Expand-Variables -String $vars[$varname] -Variables $vars
                        }
                        else {
                            $replacement = $vars[$varname]
                        }
                    }
                    else {
                        $replacement = $null
                        throw "Unable to find a replacement string for '$varname'."
                    }

                    if ($replacement -ne $null) {
                        $String = $String.Substring(0, $p1) + $replacement + $String.Substring($p2+1)
                        $pos = $p1 + $replacement.Length + 1
                    }
                    else {
                        $pos = $p2 + 1
                    }
                }
                else {
                    $pos = $p2
                    continue
                }
            }
            else {
                $pos = $String.Length
            }
        } until ($pos -ge $String.Length)

        Write-Output $String
    }
}

function Invoke-PSDGatherRestApi {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .LINK

    .NOTES
    Copyright: (c) 2025, Malte Hohmann (@daooze)
    MIT License (see LICENSE or https://opensource.org/licenses/MIT)

    .Example
    #>
    param(
        [Parameter(Mandatory)]
        [ValidatePattern("^https?://[a-z0-9\._-]+")]
        [Uri]$RestURI,

        [ValidateSet('GET', 'POST')]
        [string]$RestMethod = 'GET',

        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary]$Parameters = $null,

        [ValidateSet('OR', 'AND')]
        [string]$ParameterCondition = 'OR',

        [ValidatePattern('^[a-f0-9]{40}$')]
        [string[]]$ServerCertificateThumbprint = $null,

        [string]$ClientCertificate = '',

        [string]$ClientCertificatePassword = '',

        [pscredential]$Credential = $null,

        [System.Security.Authentication.SslProtocols[]]$SslProtocols = ([System.Security.Authentication.SslProtocols]::Tls12, [System.Security.Authentication.SslProtocols]::Tls13),

        [switch]$Force = $false
    )

    begin {
        if ($RestURI.Scheme -eq 'https') {
            [Net.ServicePointManager]::SecurityProtocol = $SslProtocols
        }
    }

    process {
        Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): Gather from RestAPI"

        # Build a hashtable of parameters for easier access.
        $param = @{}

        # Try to get a client certificate to use if a thumbprint or filename
        # is provided and the remote connection shall be established using HTTPS.
        if ($RestURI.Scheme -eq 'https') {
            if (-not [string]::IsNullOrWhiteSpace($ClientCertificate)) {
                # Try to find client certificate by its thumbprint.
                if ($ClientCertificate -match '^[a-f0-9]{40}$') {
                    try {
                        $cert = Get-ChildItem -Path cert: -Recurse | Where-Object Thumbprint -EQ $ClientCertificate
                        if ($cert -eq $null) {
                            throw "The certificate with thumbprint $ClientCertificate cannot be found"
                        }
                    } catch {
                        throw
                    }
                }
                else {
                    if (Test-Path -Path $ClientCertificate -PathType Leaf) {
                        # Open certificate file with the provided password.
                        if (-not [string]::IsNullOrWhiteSpace($ClientCertificatePassword)) {
                            try {
                                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ($ClientCertificate, $ClientCertificatePassword)
                            }
                            catch {
                                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): Failed opening the certificate file at '$ClientCertificate' using the provided passphrase. The error is: $($_.Exceptione.Message)"
                            }
                        }
                        # Try opening the file without password
                        if (-not $cert) {
                            try {
                                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ($ClientCertificate)
                            }
                            catch {
                                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): Failed opening the certificate file at '$ClientCertificate': $($_.Exceptione.Message)"
                                throw
                            }
                        }
                    }
                }
            }
            if ($cert) {
                Write-PSDLog "$($MyInvocation.MyCommand.Name): Using client certificate for authentication: Subject = '$($cert.Subject)', thumbprint = '$($cert.Thumbprint)'"
                $param['Certificate'] = $cert
            }
        }

        # Add credential if available.
        if ($Credential -ne $null) {
            $param['Credential'] = $Credential
            if ($param['Headers'] -eq $null) {$param['Headers'] = [hashtable]@{}}
            # Adding the 'Authorization' header directly should prevent the server from sending a
            # 401 http error on the first call.
            # This does only work with servers that allow basic authentication.
            $param['Headers'].Add('Authorization', (Get-BasicAuthString -Credential $param['Credential']))
        }

        # Build parameters for POST request:
        # Build the body of the API request. We send JSON content if a POST request
        # shall be submitted.
        if ($RestMethod -eq 'POST') {
            $param['Method'] = 'POST'
            $param['Uri'] = $RestURI
            $param['Body'] = [pscustomobject]@{"Parameters" = $Parameters; "Condition" = $ParameterCondition} | ConvertTo-Json -Compress
            $param['ContentType'] = "application/json"
        }

        # Build parameters for GET request:
        # Add all required parameters to the query string of the URI.
        # We do not check for duplicates here!
        else {
            $param['Method'] = 'GET'

            $uri = $RestURI.GetLeftPart([System.UriPartial]::Path)
            $query = $RestURI.Query + $(if ($RestURI.Query.Length -eq 0) {'?'} else {'&'}) + "condition=$ParameterCondition"

            if ($Parameters -ne $null) {
                foreach ($p in $Parameters.GetEnumerator()) {
                    $query += '&' + $p.Name.ToLower() + "=" + $p.Value
                }
            }
            $param['Uri'] = [uri]::new($uri + $query)
            $param['ContentType'] = "text/plain"
        }

        # Cancel if the length of the query string is longer than allowed.
        if ($param['Uri'].Query.Length -gt $script:MaxQueryLength) {
            Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): The length of the query string is longer than allowed ($($param['Uri'].Query.Length) > $script:MaxQueryLength)"
            throw "Query string is too long"
        }

        # If the remote server does not use a secure connection (https) and
        # user credentials shall be passed to it, we throw an error
        # unless -Force is specified.
        # A log entry will always be written to inform about a potential
        # security issue.
        if ($param['Uri'].Scheme -eq 'http' -and $param['Credential'] -ne $null) {
            if ($Force) {
                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): User credentials are submitted over an insecure connection. Please consider using HTTPS to connect to $($param['Uri'].Authority)" -LogLevel 3
            }
            else {
                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): Submitting user credentials over an insecure connection to $($param['Uri'].Authority) has been prevented."
                throw "Sending user credentials over an insecure connection is not allowed"
            }
        }

        # Before we start sending data to the remote server, make sure
        # that the certificate of the server has a known thumbprint.
        if ($param['Uri'].Scheme -eq 'https' -and $ServerCertificateThumbprint) {
            try {
                if (($cert = (Test-Tls -HostName $RestURI.Host -Port $RestURI.Port -TlsVersion $SslProtocols).Certificate).Thumbprint -in $ServerCertificateThumbprint) {
                    Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): The certificate of the remote server is trusted. Certificate thumbprint is $($cert.Thumbprint)"
                }
                else {
                    Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): The certificate with thumbprint $($cert.Thumbprint) is not trusted"
                    throw "Certificate untrusted"
                }
            }
            catch {
                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): The certificate of the remote server could not be verified"
                throw
            }
        }

        # Request data from the RestAPI and return the result.
        try {
            Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): Sending $($param['Method']) request to $($param['Uri'])"
            if ($param['Method'] -eq 'POST') {
                Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): POST data: '$($param['Body'])'"
            }
            $result = Invoke-RestMethod @param -UseBasicParsing -DisableKeepAlive -TimeoutSec 5 -WebSession $global:WebSession
        }
        catch {
            Write-PSDLog -Message "$($MyInvocation.MyCommand.Name): $($_.Exception.Message)"
            throw
        }

        return $result
    }
}

Export-ModuleMember -Function Invoke-PSDGatherRestApi, Convert-IniSectionToRestApiParam, Convert-RestApiResult