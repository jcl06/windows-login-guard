# Security and Sensitive-Data Handling

## Public source-release rule

A public Windows Login Guard source package must contain source code,
documentation, example configuration, static images, dependency lists, and
release checksums only.

It must not contain deployment-specific runtime state.

## Never include

Do not commit or publish:

- management databases or SQLite journals;
- server private keys, PKCS#12/PFX files, or deployment certificates;
- DPAPI-protected blobs;
- registration bundles or `registration.json`;
- device, workstation, bearer, enrollment, or registration tokens;
- TOTP secrets, QR enrollment payloads, recovery codes, or maintenance keys;
- logs or audit exports;
- generated `launch-config.json`, Remote Agent configuration, or Admin client
  configuration;
- actual computer names, internal domains, private IP addresses, usernames,
  email addresses, or local user-profile paths.

Public documentation must use neutral examples such as:

```text
wlg-server.example.internal
Protected Laptop
<port>
```

Prefer dynamic PowerShell values over copied deployment names:

```powershell
$DnsName = [System.Net.Dns]::GetHostName()
.\install-remote-server.ps1 -DnsName $DnsName
```

## Runtime secret protection

Windows Login Guard protects runtime secrets using Windows DPAPI and restricted
filesystem ACLs.

The management server should store hashes for reusable authentication tokens
where protocol behavior permits. Plaintext tokens should exist only at
creation time or inside DPAPI-protected client state.

Public server certificates are not secret, but deployment-specific
certificates should still remain outside the source release to avoid leaking
internal hostnames or environment metadata.

## Release scanner

Run:

```powershell
python .\check-release-safety.py .
```

The scanner checks for:

- restricted runtime file types and names;
- private-key markers;
- user-profile paths;
- private IPv4 addresses;
- common Windows-generated computer-name patterns;
- email addresses;
- current-machine and current-user values discovered from environment
  variables;
- additional explicit values supplied with `--deny-value`.

Example:

```powershell
python .\check-release-safety.py . `
    --deny-value $env:COMPUTERNAME `
    --deny-value $env:USERNAME
```

The scanner is a guardrail, not a substitute for manual review.

## Release checklist

Before publishing:

1. Build from a clean source checkout.
2. Do not build from an installed runtime directory.
3. Confirm no generated certificate, database, token, log, or bundle exists in
   the source tree.
4. Search documentation for copied hostnames, internal domains, IP addresses,
   usernames, and local paths.
5. Run `check-release-safety.py`.
6. Run Python syntax and PowerShell structural checks.
7. regenerate `SHA256SUMS.txt`.
8. Create the release archive.
9. Scan the final archive contents again.
10. Publish the archive SHA-256 separately.

## Reporting

Do not include real secrets in a defect report. Redact:

- tokens and registration codes;
- QR codes and TOTP seeds;
- recovery and maintenance material;
- private keys;
- full internal hostnames and IP addresses when they are not required;
- user SIDs and usernames when reproducing an issue publicly.

When a real secret is accidentally exposed, revoke or rotate it rather than
only deleting the message or file that contained it.
