#####
##
## Script below is an AzureAutomation Runbook. Its goal is to create new LetsEncrypt (or any other ACME supported provider) certificate with DNS challenge, using Azure DNS. 
## Output Certificate will be saved into KeyVault. 
## Requirements: 
##    - AzureAutomation Account Assigned Identity needs to have access to Create and Remove TXT records in Azure DNS Zone. 
##    - AzureAutomation Account Assigned Identity needs to have access to Create and Update certificates in Azure Keyvault. 
##    - Domain needs to be managed by Azure DNS Zone.
##    - ACME-PS module needs to be installed in AzureAutomation Account
##
## Scripts uses examples from ACME-PS module repository with additional elements, responsible for dns-01 challenge and keyvault upload.
#####
[OutputType([string])]

param(
    [Parameter()]
    [String] $AutomationConnectionName = "AzureRunAsConnection",

    # Azure DNS Zone name
    [Parameter()]
    [String] $dnsZone,

    # Azure DNS Zone resource group name
    [Parameter()]
    [String] $ResourceGroupName,

    [Parameter()]
    [String] $subdomain = "*",

    # Email for registation in ACME service
    [Parameter()]
    [String] $RegistrationEmail,

    # Keyvault Name 
    [Parameter()]
    [String] $keyVault,

    # ACME Service Name
    [Parameter()]
    [String] $acmeServiceName = "LetsEncrypt-Staging"
)


# Your email addresses, where acme services will send informations.
$contactMailAddresses = @($RegistrationEmail);

# This directory is used to store account key and service directory urls as well as orders and related data
$acmeStateDir = "C:\Temp\AcmeState";

# This path will be used to export certificate file.
$certExportPath = "certificate.pfx";

# Full domain name for ACME challenge and certificate order
$domain = "$subdomain.$dnsZone"

# DNS record name for TXT record
$dnsRecordName = $subdomain -eq "*" ? "_acme-challenge" : "_acme-challenge." + $subdomain

# Certificate name for KeyVault
$certificateName = $($subdomain -eq "*" ? $dnsZone : $domain) -replace "\.", "-"

try
{
    "Logging in to Azure..."
    Connect-AzAccount -Identity
}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}
"*** STARTING with Service Name: $acmeServiceName"

# see https://github.com/PKISharp/ACMESharpCore-PowerShell/tree/master/samples

Import-Module 'ACME-PS';

try
{
    ###
    ### 1. Create an new account
    ### https://github.com/PKISharp/ACMESharpCore-PowerShell/blob/master/samples/CreateAccount.ps1
    ###

    "*** 1. Create an new account"

    # Create the state object - will be saved to disk
    New-ACMEState -Path $acmeStateDir;

    # Load URLs from service directory
    Get-ACMEServiceDirectory -State $acmeStateDir -ServiceName $acmeServiceName;

    # Retrieve the first anti-replay nonce
    New-ACMENonce -State $acmeStateDir;

    # Create an account key and store it to the state
    New-ACMEAccountKey -State $acmeStateDir;

    # Register account key with acme service
    New-ACMEAccount -State $acmeStateDir -EmailAddresses $contactMailAddresses -AcceptTOS;


    ###
    ### 2. Create a new order
    ### https://github.com/PKISharp/ACMESharpCore-PowerShell/blob/master/samples/CreateOrderS.ps1
    ###

    "*** 2. Create a new order..."

    # This dns names will be used as identifier
    $dnsIdentifiers = New-ACMEIdentifier $domain;
    "*** 2.1 Identifier created..."
    # Create a new order
    $order = New-ACMEOrder -State $acmeStateDir -Identifiers $dnsIdentifiers;
    "*** 2.2 Order created..."
    Write-Host ($order | Format-List | Out-String)


    ###
    ### 3. Fullfill challenge
    ### https://github.com/PKISharp/ACMESharpCore-PowerShell/blob/master/samples/CreateOrderS.ps1
    ###

    "*** 3. Fullfill challenge..."

    # Fetch the authorizations for that order
    $authz = Get-ACMEAuthorization -State $acmeStateDir -Order $order



    # Select a challenge to fullfill
    $challenge = Get-ACMEChallenge -State $acmeStateDir -Authorization $authZ -Type "dns-01";

    "Challenge Data:"
    $challenge.Data;
    $challengeContent = $challenge.Data.Content


    $recordSet = Get-AzDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $dnsZone -RecordType "TXT" | where-object { $_.Name -eq $dnsRecordName }           
    if ($recordSet) {
        $recordSet.Records.Clear()
        "*** 3.1 Clearing old TXT record..."
        $recordSet.Records.Add((New-AzDnsRecordConfig -Value $challengeContent))
        "*** 3.2 Updating TXT record..."
        Set-AzDnsRecordSet -RecordSet $recordSet
    }
    else {
        "*** 3.1 Creating New TXT record..."
        New-AzDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $dnsZone -Name $dnsRecordName -RecordType "TXT" -Ttl 60 -DnsRecords (New-AzDnsRecordConfig -Value $challengeContent)
    }

    Start-Sleep -Seconds 60
    # Signal the ACME server that the challenge is ready
    $challenge | Complete-ACMEChallenge -State $acmeStateDir;
    
    ###
    ### 4. Issue certificate
    ### https://github.com/PKISharp/ACMESharpCore-PowerShell/blob/master/samples/IssueCertificateA.ps1
    ###

    "*** 4. Issue certificate..."

    # Wait a little bit and update the order, until we see the status 'ready' or 'invalid'
    while($order.Status -notin ("ready","invalid")) {
        Start-Sleep -Seconds 5;
        $order | Update-ACMEOrder -State $acmeStateDir -PassThru;
    }

    if($order.Status -eq "invalid") {
        throw "Your order has been marked as invalid - certificate cannot be issued."
    }

    # Complete the order - this will issue a certificate singing request
    Complete-ACMEOrder -State $acmeStateDir -Order $order -GenerateCertificateKey;

    # Now we wait until the ACME service provides the certificate url
    while(-not $order.CertificateUrl) {
        Start-Sleep -Seconds 15
        $order | Update-ACMEOrder -State $acmeStateDir -PassThru
    }

    # Randomness of password doesn't matter here as certificate will be exported into pfx and pushed into KeyVault where it effectively loose password protection
    $securePassword = ConvertTo-SecureString "RandomPassword" -asplaintext -force

    "Exporting..."
    # As soon as the url shows up we can create the PFX
    Export-ACMECertificate -State $acmeStateDir `
        -Order $order `
        -Path $certExportPath `
        -Password $securePassword

    $Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=$domain" -IssuerName "Self" -ValidityInMonths 3 -ReuseKeyOnRenewal
    Add-AzKeyVaultCertificate -VaultName $keyVault -Name $certificateName -CertificatePolicy $Policy

}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}
finally {
    # Need to remove TXT record after process (doesn't matter if successfull or not)
    Remove-AzDnsRecordSet -ResourceGroupName $ResourceGroupName -ZoneName $dnsZone -Name $dnsRecordName -RecordType "TXT"
}

