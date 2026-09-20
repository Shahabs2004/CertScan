# CertScan

**A read-only console tool that scans the certificate files in a folder and flags every risk in red.**

Point it at a folder, and it lists each certificate it finds, analyses them one by one, and shows a per-certificate risk report. It is built for one question: *"Is it safe to install this certificate, especially an unknown root CA?"*

[فارسی](README.fa.md)

<!-- Add a screenshot here: ![CertScan](docs/screenshot.png) -->

## Why

Installing a root CA makes it a trust anchor. Unless it carries a **Name Constraints** extension, whoever holds its private key can issue certificates that your machine trusts for *any* domain, which enables silent TLS interception. CertScan inspects a certificate file before you trust it and shows exactly what powers it would have.

## Features

- **Automatic discovery:** scans the current folder (or a folder you pass) for `.cer .crt .der .pem .p7b .p7c .spc .pfx .p12`. PEM bundles with several certificates are supported.
- **Each certificate analysed separately**, with its own progress animation, verdict, score (0-100) and risk card.
- **Risks in red:** `CRITICAL` (white on red), `HIGH` and `MEDIUM` (red), `LOW` (dark red). Green means nothing was found.
- **Full details on request:** interactive menu shows identity, validity, fingerprints, key and signature, constraints, EKU, Name Constraints, SAN, CRL/AIA, key identifiers and every extension. Risky fields are highlighted in red.
- **Trusted-store check:** tells you whether the certificate is already installed in the CurrentUser or LocalMachine Trusted Root store.
- **Read-only and offline:** nothing is installed, modified or sent anywhere.
- **No NuGet dependencies:** ASN.1 parsing is done by a small built-in DER reader.
- Small, fast animations (spinner, progress bars, typewriter headings) that switch off automatically when output is redirected.

## Requirements

- .NET SDK 8.0 or later to build (the project multi-targets `net48` and `net8.0`)
- Runs on .NET Framework 4.8 or .NET 8. The tool is aimed at Windows; the trusted-store lookup and console rendering on other platforms depend on the OS.

## Build

```bash
git clone https://github.com/Shahabs2004/CertScan.git
cd CertScan
dotnet build -c Release
```

Output is under `bin/Release/net48/` and `bin/Release/net8.0/`. To build only one target, remove the other from `<TargetFrameworks>` in `CertScan.csproj`.

## Usage

```text
CertScan [folder] [options]
```

| Option | Description |
|---|---|
| `folder` | Folder to scan (default: current directory) |
| `-r`, `--recursive` | Include sub-folders |
| `-d`, `--details` | Print full details of every certificate and exit (no menu) |
| `--no-anim` | Disable animations |
| `--ascii` | Plain ASCII drawing characters, for legacy consoles or fonts |
| `-h`, `--help` | Show help |

Examples:

```bash
CertScan                      # scan the current folder
CertScan C:\certs -r          # scan a folder and its sub-folders
CertScan --details --no-anim  # full report, suitable for redirecting to a file
```

### Interactive menu

| Key | Action |
|---|---|
| `D` | Full details of one certificate (asks for its number) |
| `A` | Full details of all certificates |
| `L` | Risk list (all cards) |
| `S` | Summary table |
| `Q` / `Esc` | Quit |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No notable risk |
| `1` | Low or medium risk |
| `2` | High or critical risk (also when a PEM file contains a private key) |
| `3` | Error (for example, folder not found) |

## What is checked

| Area | Examples of findings |
|---|---|
| Trust anchor | Root CA without Name Constraints (Critical); subordinate CA without Name Constraints; self-signed leaf; self-signed cert without Basic Constraints |
| Name Constraints | Not critical; only exclusions; empty DNS subtree that permits every name; undecodable extension |
| Basic Constraints / Key Usage | CA not marked critical; no `pathLen`; CA without `keyCertSign`; leaf claiming certificate-signing rights |
| Extended Key Usage | CA with no restriction; `anyExtendedKeyUsage`; code signing; smart-card logon / KDC; client auth; S/MIME; document signing |
| Signature and key | MD2/MD4/MD5 (Critical); SHA-1 (High, Low for a self-signed root); RSA below 2048 bits; EC below 256 bits; DSA |
| Validity | Expired; not yet valid; expires within 30 days; very long CA lifetime; TLS lifetime above 398 days |
| Structure | X.509 v1; short or zero serial number; CA subject without Organization; no CRL/OCSP information |
| Names | No SAN on a TLS certificate; TLD-wide wildcard; wildcard names |
| Key exposure | Private key inside a PKCS#12 that opens with an empty password (Critical); private key stored with the certificate; private key material in a PEM file |
| Environment | Certificate is already trusted in a Trusted Root store on this machine |

An unconstrained root is normal for audited public CAs (DigiCert and similar) and unacceptable for an unknown or undocumented issuer. The tool reports the capability and leaves the judgement to you.

## Project layout

```text
CertScan.csproj   multi-target project file
Program.cs        argument parsing, analysis flow, interactive menu
CertLoader.cs     file discovery and loading (PEM, DER, PKCS#7, PKCS#12)
Analyzer.cs       risk rules, OID names, trusted-store lookup
Der.cs            minimal DER reader (Name Constraints, SAN, CRL/AIA, AKI)
Models.cs         data types
Ui.cs             console primitives, glyph sets, spinner and progress bar
View.cs           banner, tables, risk cards, details view
```

## Limitations

- It inspects certificate **files**; it does not build or validate a chain against a live server.
- Password-protected PKCS#12 files cannot be inspected (only empty passwords are tried); they are reported and skipped.
- Findings are heuristics based on the certificate's own contents. A clean result does not prove that a certificate is trustworthy, and a red result does not prove malice. Always verify the SHA-256 fingerprint through an independent channel before installing any root.
- Persian text is not supported in the console UI because consoles render right-to-left text poorly.

## Contributing

Issues and pull requests are welcome. New checks belong in `Analyzer.cs`: add a `Finding` with a severity, a `Field` (used to colour the details view) and a short explanation.

## License
