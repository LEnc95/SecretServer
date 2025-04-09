# Delinea Secret Server TOTP Retriever

This project provides a set of PowerShell scripts that enable you to retrieve secret credentials and TOTP (Time-based One-Time Password) codes from Delinea (formerly Thycotic) Secret Server. The solution demonstrates how to combine two authentication methods—Windows Integrated Authentication for retrieving secret details and OAuth token-based authentication for obtaining one-time passwords.

## Overview

- **Retrieve Secret Details:**  
  The `Get-SecretServerSecretDetails` function queries your Secret Server instance to obtain secret details (such as the username and password) for a specified secret ID. It supports both Windows Integrated Authentication and OAuth.

- **Extract Credentials:**  
  The script extracts the `username` and `password` fields from the secret details and constructs a PSCredential object. This object securely encapsulates the user's credentials for further API interactions.

- **Obtain TOTP Code:**  
  The `Get-SecretServerOTP` function leverages the PSCredential object to perform token-based (OAuth) authentication. It retrieves an access token from the `/oauth2/token` endpoint and then calls the `/api/v1/one-time-password-code/{SecretID}` endpoint to fetch the current TOTP code.

## Key Features

- **Dual Authentication Modes:**  
  - **Windows Integrated Authentication:** Uses your current Windows credentials automatically via `UseDefaultCredentials`.
  - **OAuth Token-Based Authentication:** Uses explicit credentials (a PSCredential object) to obtain an access token needed for the OTP endpoint.

- **Secure Credential Handling:**  
  Extracts credentials stored in Secret Server, converts the password to a secure string, and creates a PSCredential object for secure API interactions.

- **Flexible Endpoint Configuration:**  
  Easily configure your Secret Server domain by specifying the server name (e.g., `creds.gianteagle.com`).

- **Robust Error Handling and Verbose Logging:**  
  Provides detailed error messages if any step fails, ensuring easier troubleshooting.

## Getting Started

### Prerequisites

- **PowerShell:** Version 5.1 or later (or PowerShell Core)
- **Access to a Delinea Secret Server instance:** With API credentials enabled
- **API Credentials:** An account that has the necessary permissions to retrieve secrets and obtain OTP codes
- **TLS 1.2 Enabled:** Required for secure communication

### Installation

Clone this repository to your local machine:

```bash
git clone https://github.com/LEnc95/SecretServer.git

