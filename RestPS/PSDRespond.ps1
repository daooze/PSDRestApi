param(
    [AllowEmptyString()]
    [string]$RequestArgs,

    $Body
)

# Uncomment for debug output. Output is written to the
# RestPS command window, so if RestPS is running as a
# service you might not see anything unless stdout redirection
# is somehow configured.
$script:DebugPreference = 'Continue'
$script:VerbosePreference = 'Continue'
$script:InformationPreference = 'Continue'

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
    [AllowNull()]
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

function Import-ScriptConfig {
    [CmdletBinding()]
    param(
    [string]$Filename = $null
    )

    process {
        $config_root = $PSScriptRoot + '\config' # The default config path.
        [hashtable]$vars = @{}
        $count = 0

        # Define the folder where all configuration files (*.json)
        # are stored.
        # The path of that folder is read from the initial
        # configuration file ($Filename), or defaults to
        # the folder "config" in the same folder where this script
        # is stored, if $Filename is not provided.
        if (-not [string]::IsNullOrWhiteSpace($Filename)) {
            $s_cfg = Get-Content -Path $Filename | ConvertFrom-Json

            if ($s_cfg.config_root -ne $null) {
                # Create a list of variables for use with the settings
                # in the configuration file.
                $vars.Add('SCRIPT_ROOT', $PSScriptRoot)
                if (-not [string]::IsNullOrWhiteSpace($script:request.Url.LocalPath)) {
                    $vars.Add('HTTP_REQUEST_PATH', $script:request.Url.LocalPath.TrimStart('/'))
                }

                $config_root = (Expand-Variables -String $s_cfg.config_root -Variables $vars -Recursive $false).Replace('/', '\')
                if (-not [system.io.path]::IsPathRooted($config_root)) {
                    $config_root = Join-Path -Path $PSScriptRoot -ChildPath $config_root -Resolve
                }
            }
        }

        Write-Verbose "$($MyInvocation.MyCommand.Name): Importing configuration from folder '$config_root'"

        # Read all JSON files from the folder $config_root.
        Get-ChildItem -Path $config_root -Filter '*.json' -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            $file = $_.FullName
            try {
                Write-Debug "$($MyInvocation.MyCommand.Name): Config file $($count+1) = '$file'"
                Write-Output (Get-Content $file | ConvertFrom-Json)
            }
            catch {
                Write-Verbose "$($MyInvocation.MyCommand.Name): Error parsing JSON content of file '$file'. $($_.Exception.Message)"
                throw
            }
            $count++
        }

        Write-Verbose "$($MyInvocation.MyCommand.Name): Imported configuration from $count files"
    }
}

function Get-IdentifiersFromPostData {
    param(
    [Parameter(Mandatory)]
    [string]$PostData,

    [Parameter(Mandatory)]
    [string]$ContentType
    )

    process {
        switch ($ContentType) {
            'application/json' {
                Write-Debug "$($MyInvocation.MyCommand.Name): Getting comparators from JSON string"
                return (Get-IdentifiersFromJson -Json ($PostData | ConvertFrom-Json))
            }

            default {
                Write-Verbose "$($MyInvocation.MyCommand.Name): Unhandled content type $_"
            }
        }
    }
}

function Get-ConditionFromPostData {
    param(
    [Parameter(Mandatory)]
    [string]$PostData,

    [Parameter(Mandatory)]
    [string]$ContentType
    )

    process {
        switch ($ContentType) {
            'application/json' {
                return Get-ConditionFromJson -Json ($PostData | ConvertFrom-Json)
            }

            default {
                Write-Verbose "$($MyInvocation.MyCommand.Name): Unhandled content type $_"
            }
        }
    }
}

function Get-IdentifiersFromGetArgs {
    param(
    [Parameter(Mandatory)]
    [string]$Args
    )

    process {
        $begin = $false
        $ret = [ordered]@{}

        foreach ($a in ($Args -split '&')) {
            $key, $value = [Uri]::UnescapeDataString($a) -split '='

            if ($key -eq 'condition') {
                $begin = $true
                continue
            }
            elseif ($begin) {
                if ($ret.Contains($key)) { continue }
                $ret.Add($key, $value)
            }
        }

        if ($ret.Count -gt 0) { return $ret }
    }
}

function Get-ConditionFromGetArgs {
    param(
    [Parameter(Mandatory)]
    [string]$Args
    )

    process {
        foreach ($a in ($Args -split '&')) {
            $key, $value = [Uri]::UnescapeDataString($a) -split '='

            if ($key -eq 'condition') {
                return $value
            }
        }
    }
}

function Get-IdentifiersFromJson {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .LINK

    .NOTES

    .Example
    #>
    param(
    [Parameter(Mandatory)]
    [PSCustomObject]$Json
    )

    process {
        $ret = [ordered]@{}

        if ((Measure-ConfigNodes -Node $Json.Parameters) -gt 0) {
            foreach ($p in $Json.Parameters.PSObject.Properties.Where({$_.MemberType -eq 'NoteProperty'})) {
                # Skip duplicates. First value wins.
                if ($ret.Contains($p.Name)) { continue }
                $ret.Add($p.Name, $p.Value)                    
            }
        }

        return $ret
    }
}

function Get-ConditionFromJson {
    param(
    [PSCustomObject]$Json
    )

    process {
        if ($Json.Condition -ne $null) {
            return [string]$Json.Condition
        }
    }
}

function Get-ExtendedIdentifiers {
    param(
    [Parameter(Mandatory)]
    [AllowNull()]
    [System.Net.HttpListenerRequest]$HttpListenerRequest = $null
    )

    process {
        $ret = [ordered]@{}

        try {
            if ($HttpListenerRequest -ne $null) {
                $ret.Add('HTTP_REQUEST_IPADDRESS', $HttpListenerRequest.RemoteEndPoint.Address.IPAddressToString)
                $ret.Add('HTTP_REQUEST_METHOD', $HttpListenerRequest.HttpMethod)

                if ($HttpListenerRequest.UserAgent -ne $null) {
                    $ret.Add('HTTP_REQUEST_USERAGENT', $HttpListenerRequest.UserAgent)
                }

                if (-not [string]::IsNullOrWhiteSpace($HttpListenerRequest.UserHostName)) {
                    $ret.Add('HTTP_REQUEST_HOST', $HttpListenerRequest.UserHostName)
                }

                if (-not [string]::IsNullOrWhiteSpace($HttpListenerRequest.Url.LocalPath)) {
                    $ret.Add('HTTP_REQUEST_PATH', $HttpListenerRequest.Url.LocalPath)
                }

                if ($cert = $HttpListenerRequest.GetClientCertificate()) {
                    if (-not [string]::IsNullOrWhiteSpace($cert.Thumbprint)) {
                        $ret.Add('HTTP_REQUEST_CLIENTCERT_THUMBPRINT', $cert.Thumbprint)
                    }

                    if (-not [string]::IsNullOrWhiteSpace($cert.Subject)) {
                        $ret.Add('HTTP_REQUEST_CLIENTCERT_SUBJECT', $cert.Subject)
                    }

                    if (-not [string]::IsNullOrWhiteSpace($cert.FriendlyName)) {
                        $ret.Add('HTTP_REQUEST_CLIENTCERT_FRIENDLYNAME', $cert.FriendlyName)
                    }

                    if ($cert.Extensions.Item('2.5.29.35') -ne $null) {
                        $ret.Add('HTTP_REQUEST_CLIENTCERT_AUTHORITYKEYID', $cert.Extensions.Item('2.5.29.35').Format($false) -replace '^[^=]*=')
                    }
                }

                if ($HttpListenerRequest.Headers.GetValues('Authorization') -ne $null) {
                    $ret.Add('HTTP_REQUEST_AUTHORIZATION_USERNAME', ([text.encoding]::Default.GetString([Convert]::FromBase64String($HttpListenerRequest.Headers.GetValues('Authorization') -replace '^.*? ')) -replace ':.*$'))
                }
            }
            else {
                Write-Verbose "HttpListenerRequest is null"
            }
        }
        catch {
            Write-Debug "$($MyInvocation.MyCommand.Name): $($_.Exception.Message)"
        }

        if ($ret.Count -gt 0) {
            foreach ($o in $ret.GetEnumerator()) {
                Write-Debug "$($MyInvocation.MyCommand.Name): '$($o.Name)' = '$($o.Value)'"
            }
            return $ret
        }
    }
}

function Invoke-ExtendedDataMatch {
    param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [string]$InputString,

    [Parameter(Mandatory)]
    [string]$MatchString
    )

    process {
        if ($MatchString -match '^(?<matching>(c?like|c?regex|case|c?begin|c?end|c?contain|c?set)):') {
            $matching = $Matches['matching']
            $string = $MatchString.Substring($matching.Length+1)
        }
        else {
            $matching = $null
            $string = $MatchString
        }

        switch ($matching) {
            'like'  { return ($InputString -like $string) }
            'clike'  { return ($InputString -clike $string) }
            'regex' { return ($InputString -match $string) }
            'cregex' { return ($InputString -cmatch $string) }
            'case' { return ($InputString -ceq $string) }
            'begin' { return $InputString.StartsWith($string, $true, [cultureinfo]::InvariantCulture) }
            'cbegin' { return $InputString.StartsWith($string, $false, [cultureinfo]::InvariantCulture) }
            'end' { return $InputString.EndsWith($string, $true, [cultureinfo]::InvariantCulture) }
            'cend' { return $InputString.EndsWith($string, $false, [cultureinfo]::InvariantCulture) }
            'contain' { return ($InputString.IndexOf($string, [System.StringComparison]::InvariantCultureIgnoreCase) -ge 0) }
            'ccontain' { return ($InputString.IndexOf($string, [System.StringComparison]::InvariantCulture) -ge 0) }
            'set' { return ($InputString -in ($string -split '\|')) }
            'cset' { return ($InputString -cin ($string -split '\|')) }
            default { return ($InputString -eq $string) }
        }
    }
}

function Compare-ConfigCondition {
    param(
    [Parameter(Mandatory)]
    [psobject]$Condition,

    [Parameter(Mandatory)]
    [System.Collections.Specialized.OrderedDictionary]$Identifier,

    [ValidateSet('AND', 'OR')]
    [string]$Method = 'AND'
    )

    process {
        switch ($Method) {
            'OR' {
                foreach ($cnd in $Condition.PSObject.Properties.Where({$_.MemberType -eq 'NoteProperty'})) {
                    if ($Identifier.Contains($cnd.Name)) {
                        if (Invoke-ExtendedDataMatch -InputString $Identifier.Item($cnd.Name) -MatchString $cnd.Value) {
                            Write-Verbose "$($MyInvocation.MyCommand.Name): Identifier '$($cnd.Name.ToUpper())' with value '$($Identifier.Item($cnd.Name))' matches '$($cnd.Value)'"
                            return $true
                        }
                        else {
                            Write-Verbose "$($MyInvocation.MyCommand.Name): Identifier '$($cnd.Name.ToUpper())' with value '$($Identifier.Item($cnd.Name))' does not match value '$($cnd.Value)'"
                        }
                    }
                }
                break
            }

            'AND' {
                foreach ($cnd in $Condition.PSObject.Properties.Where({$_.MemberType -eq 'NoteProperty'})) {
                    if ($Identifier.Contains($cnd.Name)) {
                        if (-not (Invoke-ExtendedDataMatch -InputString $Identifier.Item($cnd.Name) -MatchString $cnd.Value)) {
                            Write-Verbose "$($MyInvocation.MyCommand.Name): Identifier '$($cnd.Name.ToUpper())' with value '$($Identifier.Item($cnd.Name))' does not match value '$($cnd.Value)'"
                            return $false
                        }
                        else {
                            Write-Verbose "$($MyInvocation.MyCommand.Name): Identifier '$($cnd.Name.ToUpper())' with value '$($Identifier.Item($cnd.Name))' matches '$($cnd.Value)'"
                        }
                    }
                    else {
                        Write-Verbose "$($MyInvocation.MyCommand.Name): Identifier '$($cnd.Name.ToUpper())' is not provided"
                        return $false
                    }
                }
                return $true
            }

            default {
                return $false
            }
        }
    }
}

function Measure-ConfigNodes {
    param(
    [Parameter(Mandatory)]
    [AllowNull()]
    [psobject]$Node
    )

    process {
        if ($Node -ne $null) {
            if ($Node -isnot [array]) {
                if (($Node | Get-Member -MemberType NoteProperty).Count -gt 0) {
                    return 1
                } 
            }
            else {
                return $Node.Count
            }
        }
        return 0
    }
}

function Get-NamedConfig {
    param(
    [Parameter(Mandatory)]
    [psobject[]]$Config,

    [Parameter(Mandatory)]
    [string]$Name
    )

    process {
        foreach ($cfg in $Config) {
            if ($cfg.name -eq $Name) {
                Write-Output $cfg
            }
        }
    }
}

function Merge-ConfigurationSettings {
    param(
    [AllowNull()]
    [psobject]$First = $null,

    [psobject]$Second = $null,

    [ValidateSet('Replace', 'FirstValueWins')]
    [string]$Method = 'FirstValueWins'
    )

    process {
        $ret = New-Object PSCustomObject
        foreach ($s in $First.PSObject.Properties) {
            #~ Write-Debug "$($MyInvocation.MyCommand.Name): Settings property '$($s.Name)' to '$($s.Value)'"
            Add-Member -InputObject $ret -MemberType NoteProperty -Name $s.Name -Value $s.Value
        }

        switch ($Method) {
            'Replace' {
                # Method: Replace = Second value overwrites first value
                if ($Second.PSObject.Properties -ne $null) {
                    foreach ($s in $Second.PSObject.Properties.Where({$_.MemberType -eq 'NoteProperty'})) {
                        if ($ret.$($s.Name) -ne $null) {
                            #~ Write-Debug "$($MyInvocation.MyCommand.Name): Replacing value of property '$($s.Name)' with new value '$($s.Value)'"
                            $ret.$($s.Name) = $s.Value
                        }
                        else {
                            #~ Write-Debug "$($MyInvocation.MyCommand.Name): Settings property '$($s.Name)' to '$($s.Value)'"
                            Add-Member -InputObject $ret -MemberType NoteProperty -Name $s.Name -Value $s.Value
                        }
                    }
                }
            }

            'FirstValueWins' {
                # Method: Default = First value wins
                if ($Second.PSObject.Properties -ne $null) {
                    foreach ($s in $Second.PSObject.Properties) {
                        if ($ret.$($s.Name) -ne $null) {
                            #~ Write-Debug "$($MyInvocation.MyCommand.Name): Not replacing value of property '$($s.Name)'"
                            continue
                        }
                        #~ Write-Debug "$($MyInvocation.MyCommand.Name): Settings property '$($s.Name)' to '$($s.Value)'"
                        Add-Member -InputObject $ret -MemberType NoteProperty -Name $s.Name -Value $s.Value
                    }
                }
            }

            default {
                Write-Verbose "$($MyInvocation.MyCommand.Name): Unsupported merge method '$_'"
                throw "Unsupported merge method"
            }
        }

        return $ret
    }
}

function Find-MatchingConfig {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory)]
    [psobject[]]$Config,

    [Parameter(Mandatory)]
    [System.Collections.Specialized.OrderedDictionary]$Identifiers
    )

    begin {
        # Add identifiers from the HTTP request.
        try {
            if ($script:request -is [System.Net.HttpListenerRequest] -and $script:request -ne $null) {
                Write-Verbose "$($MyInvocation.MyCommand.Name): Adding identifiers from HTTP request"
                $Identifiers += Get-ExtendedIdentifiers -HttpListenerRequest $script:request
            }
        } catch {
            Write-Error $_.Exception.Message
        }
    }

    process {
        Write-Information "$($MyInvocation.MyCommand.Name): Trying to find configurations that match provided identifiers"
        Write-Verbose "$($MyInvocation.MyCommand.Name): Number of identifiers: $($Identifiers.Count), number of configurations: $($Config.Count)"

        Write-Debug "$($MyInvocation.MyCommand.Name): The calling system provided the following identifiers:"
        foreach ($i in $Identifiers.GetEnumerator()) {
            Write-Debug "$($MyInvocation.MyCommand.Name): '$($i.Name.ToUpper())' = '$($i.Value)'"
        }

        $cfg_index = 0
        foreach ($cfg in $config) {
            $cfg_index++
            $output = $null

            # Get/set the name of the currently processed configuration.
            # This is for logging purpose only.
            if ($cfg.name -ne $null) {
                $ConfigName = $cfg.name
            }
            else {
                $ConfigName = $cfg_index
            }

            # Skip configs with empty or missing conditions. Those configs may only be
            # included in other configs using 'prepend_configs' but will not be set automatically.
            if ($cfg.conditions -eq $null -or -not ($cfg.conditions.PSObject.Properties.Where({$_.MemberType -eq 'NoteProperty'}))) {
                Write-Verbose "$($MyInvocation.MyCommand.Name): Skipping '$ConfigName' as no conditions are defined"
                continue
            }

            # Skip configs with empty or missing 'settings' as they are useless.
            if ($cfg.settings -eq $null -or -not ($cfg.settings.PSObject.Properties.Where({$_.MemberType -eq 'NoteProperty'}))) {
                Write-Verbose "$($MyInvocation.MyCommand.Name): Skipping '$ConfigName' as no settings are defined"
                continue
            }

            # Define how the conditions get compared against
            # the provided identifiers.
            if ($cfg.compare_method -ne $null -and $cfg.compare_method -in 'AND','OR') {
                $CompareMethod = $cfg.compare_method.ToUpper()
            }
            else {
                $CompareMethod = 'AND'
            }

            Write-Verbose "$($MyInvocation.MyCommand.Name): Working on configuration '$ConfigName'. Compare method is $CompareMethod"

            # Compare identifiers against conditions.
            if (Compare-ConfigCondition -Condition $cfg.conditions -Identifier $Identifiers -Method $CompareMethod) {
                Write-Information "$($MyInvocation.MyCommand.Name): Configuration '$ConfigName' matches provided identifiers, $($CompareMethod)-compared"
                $output = $cfg.settings
            }
            else {
                continue
            }

            # Prepend other configurations.
            if ((Measure-ConfigNodes -Node $cfg.prepend_configs) -gt 0) {
                Write-Verbose "$($MyInvocation.MyCommand.Name): '$ConfigName' defines $(Measure-ConfigNodes -Node $cfg.prepend_configs) configurations that might be prepended"
                $prepend_config = $null

                foreach ($r in $cfg.prepend_configs) {
                    # Validate conditions, if defined.
                    # We skip prepending the configuration if conditions are not met.
                    if ($r.conditions -ne $null) {
                        # Get the compare method to use.
                        if ($r.compare_method -ne $null) {
                            $PrependCompareMethod = $r.compare_method.ToUpper()
                        }
                        else {
                            $PrependCompareMethod = 'AND'
                        }

                        # If condition don´t match, continue with the next configuration to prepend.
                        if (-not (Compare-ConfigCondition -Condition $r.conditions -Identifier $Identifiers -Method $PrependCompareMethod)) {
                            Write-Verbose "$($MyInvocation.MyCommand.Name): Configuration '$($r.name)' will not be prepended as conditions do not match"
                            continue
                        }
                    }
                    else {
                        Write-Verbose "$($MyInvocation.MyCommand.Name): No prepend conditions for configuration '$($r.name)'"
                    }

                    # Get the configuration to include or throw
                    # an error if it does not exist.
                    if ($temp_config = Get-NamedConfig -Config $config -Name $r.name) {
                        Write-Verbose "$($MyInvocation.MyCommand.Name): Prepending configuration '$($temp_config.name)'"
                    }
                    else {
                        Write-Verbose "$($MyInvocation.MyCommand.Name): Cannot prepend configuration '$r', it does not exist"
                        throw "Configuration named '$r' does not exist"
                    }

                    # Define merge method.
                    if ($r.merge_method -ne $null) {
                        $MergeMethod = $r.merge_method
                    }
                    else {
                        $MergeMethod = 'FirstValueWins'
                    }

                    # Finally, prepend the configuration.
                    if ($temp_config -ne $null) {
                        $prepend_config = Merge-ConfigurationSettings -First $prepend_config -Second $temp_config.settings -Method $MergeMethod
                    }
                }

                # Merge all prepend configurations and the current configuration. Values of prepended
                # configurations always override values from the current configuration.
                if ($prepend_config -ne $null) {
                    $output = Merge-ConfigurationSettings -First $prepend_config -Second $output -Method Replace
                }
            }

            if ($output -ne $null) {
                Write-Output $output
            }
        }
    }
}


# Get configuration from files.
[object[]]$config = $null
try {
    $config_file = $PSCommandPath -replace '\.[a-z0-9]+$', '.json'
    if (Test-Path -Path $config_file) {
        Write-Verbose "$($MyInvocation.MyCommand.Name): Using base config from '$config_file'"
        $config = Import-ScriptConfig -Filename $config_file -ErrorAction Stop
    }
    else {
        Write-Verbose "$($MyInvocation.MyCommand.Name): Using default base config"
        $config = Import-ScriptConfig -ErrorAction Stop
    }
#    Import-ScriptConfig -Filename ($PSCommandPath -replace '\.[a-z0-9]+$', '.json') -ErrorAction Stop
}
catch {
    Write-Debug "$($MyInvocation.MyCommand.Name): $($_.Exception.Message)"
    $script:StatusDescription = "Internal Server Error"
    $script:StatusCode = 500
    exit $script:StatusCode
}

if ($script:request.HttpMethod -eq 'GET') {
    $Parameters = Get-IdentifiersFromGetArgs -Args $RequestArgs
}
else {
    $Parameters = Get-IdentifiersFromPostData -PostData $Body -ContentType $script:request.ContentType
}

if ($config -ne $null -and ($result = Find-MatchingConfig -Config $config -Identifiers $Parameters | Select-Object -First 1)) {
    $result | Add-Member -MemberType NoteProperty -Name '_RestAPI_Metadata' -Value @{'Status'='Ok'} -PassThru
}
else {
    [pscustomobject]@{'_RestAPI_Metadata'=@{'Status'='no_result'}}
}
