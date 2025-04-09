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

# Retrieve the secret details.
$SecretDetails = Get-SecretServerSecretDetails -SecretID 42606 -TLS12

# Extract username and password values from the items (assuming these slugs exist).
$username = ($SecretDetails.items | Where-Object { $_.slug -eq 'username' }).itemValue
$password = ($SecretDetails.items | Where-Object { $_.slug -eq 'password' }).itemValue

# Convert the plain text password to a secure string.
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

# Build the PSCredential object.
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

Write-Output "Retrieved credentials for $username"

function Get-SecretServerOTP {
    [CmdletBinding()]
    param(
        # The ID of the secret for which you want to retrieve the TOTP.
        [Parameter(Mandatory = $true)]
        [int]$SecretID,

        # The PSCredential containing the username and password extracted from the secret.
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credentials,

        # Use TLS 1.2.
        [switch]$TLS12,

        # The Secret Server hostname (e.g., creds.gianteagle.com)
        [Parameter(Mandatory = $true)]
        [string]$SecretServerName
    )

    if ($TLS12) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    
    # Step 1: Build the token endpoint using your tenant's host.
    $tokenUri = "https://$SecretServerName/SecretServer/oauth2/token"
    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method Post -Body @{
            username   = $Credentials.UserName
            password   = $Credentials.GetNetworkCredential().Password
            grant_type = 'password'
        } -ErrorAction Stop
    }
    catch {
        throw "Error retrieving OAuth token: $_"
    }

    if (-not $tokenResponse.access_token) {
        throw "OAuth token not retrieved. Check your credentials and API settings."
    }
    
    # Step 2: Build the OTP endpoint using your tenant's host.
    $otpUri = "https://$SecretServerName/SecretServer/api/v1/one-time-password-code/$SecretID"
    $headers = @{
        Authorization = "Bearer $($tokenResponse.access_token)"
        Accept        = "application/json"
    }

    Write-Verbose "Calling OTP endpoint: $otpUri"

    try {
        $otpResponse = Invoke-RestMethod -Uri $otpUri -Method Get -Headers $headers -ErrorAction Stop
    }
    catch {
        throw "Error calling OTP endpoint: $_"
    }
    
    # Step 3: Return the OTP.
    if ($otpResponse.oneTimePassword) {
        return $otpResponse.oneTimePassword
    }
    else {
        return $otpResponse
    }
}

# --- Example usage ---

# Assuming you previously retrieved your secret details (username and password)
# and built a PSCredential object called $credential.
$SecretServerName = 'creds.gianteagle.com'
$SecretID = 42606

try {
    $OTPCode = Get-SecretServerOTP -SecretID $SecretID -Credentials $credential -TLS12 -SecretServerName $SecretServerName
    Write-Output "Your TOTP code is: $OTPCode"
}
catch {
    Write-Error "Failed to retrieve TOTP code: $_"
}
