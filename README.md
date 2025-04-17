## Let's Encrypt Certificate Deployment Script for Windows Hosts

This script automates the deployment of Let's Encrypt certificates on Windows hosts using [Posh-ACME](https://poshac.me/docs/latest/) and the Cloudflare plugin. In addition to generating the Let's Encrypt certificate, it also installs the new certificate in **Remote Desktop Services** and **Work Folders**.

## Features

- **Automates the certificate renewal process** on Windows hosts.
- Supports **Windows Server 2016** and above.
- Works with **Cloudflare API** to generate certificates.
- Installs certificates into **Remote Desktop Services** and **Work Folders**.

## Prerequisites

- PowerShell 5.1 or higher.
- Ability to create Cloudflare API token.

## Actions Performed by the Script

The script performs the following actions:

1. Ensures TLS 1.2 is enabled on Windows Server 2016 or lower within .NET framework.
2. Installs Posh-ACME module.
3. Imports Cloudflare API token as a secure string.
4. Sets Let's Encrypt environment (staging/production).
5. Generates Let's Encrypt certificate.
6. Creates a scheduled task to renew certificate automatically.
7. Checks if Remote Desktop Services is installed. If yes, updates the certificate.
8. Checks if Work Folders is installed. If yes, updates the certificate.
9. Deletes replaced certificates from the certificate store.

## Setup Instructions

For a full walk-through on how to implement this script in your environment, please refer to my [blog post](https://twobyte.blog/docs/installing_lets_encrypt/installing_posh-acme/).