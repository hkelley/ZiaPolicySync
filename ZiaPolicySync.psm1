
$script:ZiaApiSession = [ordered]@{
    ApiRoot             = $null
    SessionVariable     = $null
}

[datetime] $script:UnixEpoch = '1970-01-01 00:00:00Z'


function ObfuscateApiKey {
    param (
          [string]  $ApiKey
        , [string]  $Timestamp 
    )

    $high = $timestamp.substring($timestamp.length - 6)
    $low = ([int]$high -shr 1).toString()
    $obfuscatedApiKey = ''

    while ($low.length -lt 6) {
        $low = '0' + $low
    }

    for ($i = 0; $i -lt $high.length; $i++) {
        $obfuscatedApiKey += $apiKey[[int64]($high[$i].toString())]
    }

    for ($j = 0; $j -lt $low.length; $j++) {
        $obfuscatedApiKey += $apiKey[[int64]$low[$j].ToString() + 2]
    }

    return $obfuscatedApiKey
}


function Connect-ZscalerAPI {
    param (
          [Parameter(Mandatory = $true)] [string] $CloudName 
        , [Parameter(Mandatory = $true)] [string] $ApiKey
        , [Parameter(Mandatory = $true)] [pscredential] $ZscalerAdminCred
        , [switch] $PassThru
    )

    $script:ZiaApiSession.ApiRoot =   "https://zsapi.{0}.net" -f $CloudName

    #$loginTs = [Math]::Round((New-TimeSpan -Start $UnixEpoch -End (Get-Date)).TotalMilliseconds,0)
    [Int64] $loginTs = (New-TimeSpan -Start $UnixEpoch -End (Get-Date)).TotalMilliseconds
    $obfuscatedApiKey = ObfuscateApiKey -ApiKey $ApiKey -Timestamp $loginTs

    $body = [pscustomobject] @{
        apiKey = $obfuscatedApiKey
        username = $ZscalerAdminCred.UserName
        password = $ZscalerAdminCred.GetNetworkCredential().Password
        timestamp = $loginTs
    } | ConvertTo-Json

    if($ret = Invoke-RestMethod -URI ("{0}/api/v1/authenticatedSession" -f $script:ZiaApiSession.ApiRoot) -Method Post -Body $body -ContentType 'application/json' -UseBasicParsing -SessionVariable sv ) {
        Write-Verbose $ret
        $script:ZiaApiSession.SessionVariable = $sv
        if($PassThru) {
            # Pass the sessions variable so that the user can make API calls not yet supported by this module
            $sv
        }
    }
}


Function Disconnect-ZscalerAPI {
    Invoke-RestMethod -URI ("{0}/api/v1/authenticatedSession" -f $script:ZiaApiSession.ApiRoot) -Method Delete  -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
}

Function Get-ZscalerAtpDenyList {
    Invoke-RestMethod -URI ("{0}/api/v1/security/advanced" -f $script:ZiaApiSession.ApiRoot) -Method Get -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
}

Function Set-ZscalerChangeActivation {
    if($status = Invoke-RestMethod -URI ("{0}/api/v1/status/activate" -f $script:ZiaApiSession.ApiRoot) -Method Post -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable)
    {
        Write-Host "Activation: $status"
    }
}

Function Set-ZscalerAtpDenyList {
    param (
        [Parameter(Mandatory = $true)] [string[]] $UrlList
    )

    $uri = "{0}/api/v1/security/advanced" -f $script:ZiaApiSession.ApiRoot
    $body = [PSCustomObject] @{
        blacklistUrls = $UrlList
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -URI $uri -Method Put -ContentType 'application/json' -UseBasicParsing -Body $body  -WebSession $script:ZiaApiSession.SessionVariable
    } catch [System.Net.WebException] {

        if (    $_.Exception.Response.StatusCode -ne 400 ) {
            throw $_
        }

        # If we received  {"code":"INVALID_INPUT_ARGUMENT"}   then pass along as a warning

        if($_.Exception.Response) {
            $s = $_.Exception.Response.GetResponseStream()
            $s.Position = 0;
            $sr = New-Object System.IO.StreamReader($s)
            $err = $sr.ReadToEnd()
            $sr.Close()
            $s.Close()
        }

        Write-Warning ("Invoked {0},  received HTTP status {1}, {2} {3}" -f $uri,$_.Exception.Response.StatusCode,$_.Exception.Code,$err)
    }
}


Function Get-ZscalerIPv4DestGroups {
    Invoke-RestMethod -URI ("{0}/api/v1/ipDestinationGroups/lite" -f $script:ZiaApiSession.ApiRoot) -Method Get -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
}

Function Get-ZscalerIPv4DestGroup {
    param (
        [Parameter(Mandatory = $true)] [string] $GroupName
    )

    if($group = Get-ZscalerIPv4DestGroups | ?{$_.name -eq $GroupName}) {
        Invoke-RestMethod -URI ("{0}/api/v1/ipDestinationGroups/{1}" -f $script:ZiaApiSession.ApiRoot,$group.id) -Method Get -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable
    } else  {
        Throw "Group not found:  $GroupName"
    }
}

Function Set-ZscalerIPv4DestGroup {
    param  (
          [Parameter(Mandatory = $true)] [PSCustomObject] $Group
        , [Parameter(Mandatory = $true)] [string[]] $IpList
    )

    Invoke-RestMethod -URI ("{0}/api/v1/status" -f $script:ZiaApiSession.ApiRoot) -Method Get -ContentType 'application/json' -UseBasicParsing  -WebSession $script:ZiaApiSession.SessionVariable

    $Group.addresses = $IpList | ?{$_ -notlike "*:*"} | Select-Object -Unique
    $body = $Group | ConvertTo-Json

    Invoke-RestMethod -URI ("{0}/api/v1/ipDestinationGroups/{1}" -f $script:ZiaApiSession.ApiRoot,$Group.Id) -Method Put -ContentType 'application/json' -UseBasicParsing -Body $body -WebSession $script:ZiaApiSession.SessionVariable

    Invoke-RestMethod -URI ("{0}/api/v1/status/activate" -f $script:ZiaApiSession.ApiRoot) -Method Post -ContentType 'application/json' -UseBasicParsing  -WebSession $script:ZiaApiSession.SessionVariable
}


Function Get-ZscalerFirewallFilteringRules {
    if($result = Invoke-RestMethod -URI ("{0}/api/v1/firewallFilteringRules" -f $script:ZiaApiSession.ApiRoot) -Method Get -ContentType 'application/json' -UseBasicParsing -WebSession $script:ZiaApiSession.SessionVariable) {
        $result
    }
}

Function Output-RulesetObjects( $ConfigObject, $ListField) {
    foreach($item in $ConfigObject."$ListField") {
        if(-not ($name = $ConfigObject.configuredName)) {
            $name = $ConfigObject.name
        }
        
        [pscustomobject] @{
            Item = $name
            ItemType = $ConfigObject.type
            Identifier = $item
        }
    } 
}

Function Get-ZscalerUrlAndFqdnXref {

    $categories = @()

    # Custom
    if(!($categories += Invoke-RestMethod -URI ("{0}/api/v1/urlCategories?customOnly=true" -f $script:ZiaApiSession.ApiRoot) -Method Get -WebSession $script:ZiaApiSession.SessionVariable )) { 
    
        Throw "no data for custom URL categories"
    }

    foreach($cat in $categories) {
        # Export both "modes" of category setting
        Output-RulesetObjects -ConfigObject $cat -ListField "urls"
        Output-RulesetObjects -ConfigObject $cat -ListField "dbCategorizedUrls"
    }

    $destGroups = Get-ZscalerIPv4DestGroups 

    foreach($group in $destGroups) {

        $g = Invoke-RestMethod -URI ("{0}/api/v1/ipDestinationGroups/{1}" -f $script:ZiaApiSession.ApiRoot,$group.id) -Method Get -WebSession $script:ZiaApiSession.SessionVariable

        Output-RulesetObjects -ConfigObject $g -ListField "addresses"

        Start-Sleep -Seconds 1
    }
}

<#

Export-ModuleMember -Function Connect-ZscalerAPI
Export-ModuleMember -Function Disconnect-ZscalerAPI
Export-ModuleMember -Function Get-ZscalerAtpDenyList
Export-ModuleMember -Function Set-ZscalerAtpDenyList
Export-ModuleMember -Function Get-ZscalerIPv4DestGroup
Export-ModuleMember -Function Set-ZscalerIPv4DestGroup
Export-ModuleMember -Function Set-ZscalerChangeActivation
Export-ModuleMember -Function Get-ZscalerFirewallFilteringRules
Export-ModuleMember -Function Get-ZscalerUrlAndFqdnXref

#>