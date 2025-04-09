function Get-SecretServerSecretDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$SecretID,
        [Parameter(Mandatory=$false)]
        [string]$SecretServerName = 'creds.gianteagle.com',
        [switch]$TLS12,
        [switch]$oAuth
    )

    if ($TLS12) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    $BaseURL = "https://$SecretServerName/SecretServer"
    $Arglist = @{}

    if ($oAuth) {
        # Add your OAuth token retrieval here as in your original script.
        $TokenResponse = Invoke-RestMethod "$BaseURL/oauth2/token" `
            -Method Post `
            -Body @{ username = $Credentials.UserName; password = $Credentials.GetNetworkCredential().Password; grant_type = 'password' }
        $Arglist['Headers'] = @{ Authorization = "Bearer $($TokenResponse.access_token)" }
        $BaseURL += '/api/v1/secrets'
    }
    else {
        $BaseURL += '/winauthwebservices/api/v1/secrets'
        $Arglist['UseDefaultCredentials'] = $true
    }

    $Arglist['Uri'] = "$BaseURL/$SecretID"
    Write-Verbose "Retrieving secret details from: $($Arglist['Uri'])"
    $SecretDetails = Invoke-RestMethod @Arglist
    return $SecretDetails
}

# Example usage:
$SecretDetails = Get-SecretServerSecretDetails -SecretID 42606 -TLS12
$SecretDetails | Format-List *

$SecretDetails.items | ForEach-Object { 
    Write-Output "Slug: $($_.slug) - Value: $($_.itemValue)" 
}
