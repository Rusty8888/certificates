# Certificate Management Repo

This repo is to manage the Delinian certificates and contains numerous actions to maintain them

## Table of Contents

- Updating the README.md
- Certificate Expiry Action
- Complete Certificate Action
- Sync Key Vault and Octopus Certificate Stores
- Retrieve a Certificate

## Updating the README

Any modifications to the readme need to be done to the readme_template.md found under the scripts dir
The sync_octopus workflow will read this template and update the repo README with certificate information and template changes.
Due to security restrictions it can't be completed on the main branch.
Please use the readme_update branch and use it solely for updates to the readme template to avoid conflicts!

## Complete a certificate

When the pem is recieved from csc it has to be placed on the pem file share for the process to complete it and store it in key vault

To connect to the file share please go to the Azure portal and follow the connection instructions:
(https://portal.azure.com/#view/Microsoft_Azure_FileStorage/FileShareMenuBlade/~/overview/storageAccountId/%2Fsubscriptions%2F09cde214-980e-43ad-9622-fa2599439898%2FresourceGroups%2Frg-certificates%2Fproviders%2FMicrosoft.Storage%2FstorageAccounts%2Fdeliniancsr/path/pem/protocol/SMB)

## Retrieve a certificate

This action is to retrieve a certificate that is stored in Azure Key Vault
It will retrieve all the certificates that match the cert name that is entered. This includes partial matches (min 3 characters).
e.g. entering 'global' will return the certificates wc-globalcapital-com and wc-globalinvestorgroup-com

Retrieved certificates are in the Artifacts section after the job has run and can be downloaded.

List of certificates in Key Vault:
```
{{ << CERT_LIST >> }}
```

## Cert Naming Convention

In Azure Key Vault there are a lot characters that are not allowed. Therefore the following naming convention has to be followed for coherency:
- wc-* = Wildcard certificate e.g. wc.delinian.com
- www-* = Single subdomain certficate. Use the name of the single subdomain e.g. accounts.delinian.com
- san-* = SAN certificate. Use the name of the main subdomain.domain in the cert. e.g. events.delinian.com but all the other events domains are on the SAN too.