# Lets Encrypt for Windows

This script automates the deployment of Let's Encrypt certificates on Windows hosts using Posh-ACME and the Cloudflare plugin. In addition to generating the Let's Encrypt certificate, it also installs the new certificate in Remote Desktop Services and Work Folders.

The script performs the following actions:

1. If running on Windows Server 2016 or lower, ensure TLS 1.2 is enabled within .NET.
2. Install Posh-ACME module.
3. Import Cloudflare API token as a secure string.
4. Set Let's Encrypt environment (staging/production).
5. Generate certificate.
6. Create scheduled task to check daily if renewal is required.
7. Check if Remote Desktop Services is installed. If yes, update certificate.
8. Check if Work Folders is installed. If yes, update certificate.
9. Delete replaced certificate from Certificate Store.

For a full walk-through on how to implement this script in your environment, please check out my [blog post](https://twobyte.blog/docs/installing_lets_encrypt/installing_posh-acme/).