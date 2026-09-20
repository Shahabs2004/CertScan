using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace CertScan
{
    internal static class Oids
    {
        public const string Rsa = "1.2.840.113549.1.1.1";
        public const string Ec = "1.2.840.10045.2.1";
        public const string Dsa = "1.2.840.10040.4.1";

        public const string ServerAuth = "1.3.6.1.5.5.7.3.1";
        public const string ClientAuth = "1.3.6.1.5.5.7.3.2";
        public const string CodeSigning = "1.3.6.1.5.5.7.3.3";
        public const string EmailProtection = "1.3.6.1.5.5.7.3.4";
        public const string AnyEku = "2.5.29.37.0";
        public const string SmartcardLogon = "1.3.6.1.4.1.311.20.2.2";
        public const string KdcAuth = "1.3.6.1.5.2.3.5";
        public const string DocSigning = "1.3.6.1.4.1.311.10.3.12";

        private static readonly Dictionary<string, string> Names = new Dictionary<string, string>
        {
            { "1.3.6.1.5.5.7.3.1", "Server Authentication (TLS server)" },
            { "1.3.6.1.5.5.7.3.2", "Client Authentication" },
            { "1.3.6.1.5.5.7.3.3", "Code Signing" },
            { "1.3.6.1.5.5.7.3.4", "Secure Email (S/MIME)" },
            { "1.3.6.1.5.5.7.3.8", "Time Stamping" },
            { "1.3.6.1.5.5.7.3.9", "OCSP Signing" },
            { "2.5.29.37.0", "Any Extended Key Usage" },
            { "1.3.6.1.4.1.311.20.2.2", "Smart Card Logon" },
            { "1.3.6.1.5.2.3.5", "KDC Authentication" },
            { "1.3.6.1.4.1.311.10.3.12", "Document Signing" },
            { "1.3.6.1.4.1.311.10.3.4", "Encrypting File System" },
            { "1.3.6.1.5.5.7.3.17", "IPsec IKE Intermediate" },
            { "2.5.29.14", "Subject Key Identifier" },
            { "2.5.29.15", "Key Usage" },
            { "2.5.29.17", "Subject Alternative Name" },
            { "2.5.29.19", "Basic Constraints" },
            { "2.5.29.30", "Name Constraints" },
            { "2.5.29.31", "CRL Distribution Points" },
            { "2.5.29.32", "Certificate Policies" },
            { "2.5.29.35", "Authority Key Identifier" },
            { "2.5.29.37", "Extended Key Usage" },
            { "1.3.6.1.5.5.7.1.1", "Authority Information Access" },
            { "1.3.6.1.4.1.311.21.7", "Certificate Template Information" },
            { "1.3.6.1.4.1.311.20.2", "Certificate Template Name" },
            { "1.3.6.1.4.1.311.21.1", "CA Version" }
        };

        public static string Name(string oid, string fallback)
        {
            string n;
            if (oid != null && Names.TryGetValue(oid, out n)) return n;
            return string.IsNullOrEmpty(fallback) ? "(unknown)" : fallback;
        }
    }

    /// <summary>Which certificates are already trusted on this machine.</summary>
    internal static class Stores
    {
        public static Dictionary<string, string> LoadInstalled()
        {
            Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            Read(map, StoreLocation.CurrentUser, "CurrentUser\\Trusted Root");
            Read(map, StoreLocation.LocalMachine, "LocalMachine\\Trusted Root");
            return map;
        }

        private static void Read(Dictionary<string, string> map, StoreLocation location, string label)
        {
            try
            {
                using (X509Store store = new X509Store(StoreName.Root, location))
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    foreach (X509Certificate2 c in store.Certificates)
                        if (!map.ContainsKey(c.Thumbprint)) map[c.Thumbprint] = label;
                }
            }
            catch
            {
                // store unavailable (permissions / platform) - simply no data
            }
        }
    }

    internal static class Analyzer
    {
        public static void Analyze(CertInfo ci, Dictionary<string, string> installed, DateTime now)
        {
            Extract(ci, installed);
            RunChecks(ci, now);

            ci.Findings = ci.Findings.OrderByDescending(f => f.Severity).ToList();
            ci.MaxSeverity = ci.Findings.Count == 0 ? Severity.Info : ci.Findings.Max(f => f.Severity);
            ci.Score = Math.Min(100, ci.Findings.Sum(f => Weight(f.Severity)));
        }

        private static int Weight(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return 40;
                case Severity.High: return 20;
                case Severity.Medium: return 10;
                case Severity.Low: return 4;
                default: return 0;
            }
        }

        // ------------------------------------------------------------------ extraction

        private static void Extract(CertInfo ci, Dictionary<string, string> installed)
        {
            X509Certificate2 c = ci.Cert;

            ci.SelfSigned = c.SubjectName.RawData.SequenceEqual(c.IssuerName.RawData);

            X509BasicConstraintsExtension bc = c.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if (bc != null)
            {
                ci.HasBasicConstraints = true;
                ci.IsCa = bc.CertificateAuthority;
                ci.BcCritical = bc.Critical;
                ci.PathLen = bc.HasPathLengthConstraint ? bc.PathLengthConstraint : -1;
            }

            if (ci.SelfSigned && (ci.IsCa || bc == null)) ci.Kind = CertKind.Root;
            else if (ci.IsCa) ci.Kind = CertKind.Intermediate;
            else ci.Kind = CertKind.Leaf;

            X509KeyUsageExtension ku = c.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (ku != null)
            {
                ci.HasKeyUsage = true;
                ci.KeyUsages = ku.KeyUsages;
            }

            X509EnhancedKeyUsageExtension eku = c.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (eku != null)
            {
                ci.Eku = new List<string>();
                foreach (Oid o in eku.EnhancedKeyUsages) ci.Eku.Add(o.Value);
            }

            X509Extension nc = c.Extensions["2.5.29.30"];
            if (nc != null)
            {
                try { ci.NameConstraints = DerHelper.ParseNameConstraints(nc.RawData); }
                catch { ci.NameConstraints = new NameConstraintInfo { Unparseable = true }; }
                ci.NameConstraints.Critical = nc.Critical;
            }

            X509Extension san = c.Extensions["2.5.29.17"];
            if (san != null)
            {
                try { ci.San = DerHelper.ParseGeneralNames(san.RawData); } catch { }
            }

            X509Extension crl = c.Extensions["2.5.29.31"];
            if (crl != null)
            {
                try { ci.CrlUrls = DerHelper.CollectUris(crl.RawData); } catch { }
            }

            X509Extension aia = c.Extensions["1.3.6.1.5.5.7.1.1"];
            if (aia != null)
            {
                try { ci.AiaUrls = DerHelper.CollectUris(aia.RawData); } catch { }
            }

            X509Extension aki = c.Extensions["2.5.29.35"];
            if (aki != null)
            {
                try { ci.AuthorityKeyId = DerHelper.AuthorityKeyId(aki.RawData); } catch { }
            }

            X509SubjectKeyIdentifierExtension ski = c.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
            if (ski != null) ci.SubjectKeyId = ski.SubjectKeyIdentifier;

            ci.PublicKeyOid = c.PublicKey.Oid.Value;
            ci.KeySize = KeySize(c, ci.PublicKeyOid);

            byte[] raw = c.RawData;
            using (SHA1 sha1 = SHA1.Create()) ci.Sha1 = DerHelper.Hex(sha1.ComputeHash(raw));
            ci.Sha256 = DerHelper.Hex(Sha256(raw));

            byte[] serial = (byte[])c.GetSerialNumber().Clone();   // little-endian
            Array.Reverse(serial);
            ci.SerialHex = serial.Length == 0 ? "00" : BitConverter.ToString(serial).Replace("-", "");

            string location = null;
            if (installed != null) installed.TryGetValue(c.Thumbprint, out location);
            ci.InstalledIn = location;
        }

        private static byte[] Sha256(byte[] data)
        {
#if NETFRAMEWORK
            // SHA256Cng keeps working when the FIPS policy is enforced (SHA256Managed would throw).
            using (SHA256Cng h = new SHA256Cng()) return h.ComputeHash(data);
#else
            using (SHA256 h = SHA256.Create()) return h.ComputeHash(data);
#endif
        }

        private static int KeySize(X509Certificate2 c, string oid)
        {
            try
            {
                if (oid == Oids.Rsa)
                {
                    using (RSA k = c.GetRSAPublicKey()) return k != null ? k.KeySize : 0;
                }
                if (oid == Oids.Ec)
                {
                    using (ECDsa k = c.GetECDsaPublicKey()) return k != null ? k.KeySize : 0;
                }
                if (oid == Oids.Dsa)
                {
                    using (DSA k = c.GetDSAPublicKey()) return k != null ? k.KeySize : 0;
                }
            }
            catch
            {
                // unsupported key type / explicit EC parameters
            }
            return 0;
        }

        // ------------------------------------------------------------------ checks

        private static void Add(CertInfo ci, Severity sev, string field, string title, string detail)
        {
            ci.Findings.Add(new Finding(sev, field, title, detail));
        }

        private static bool HasEku(CertInfo ci, string oid)
        {
            return ci.Eku != null && ci.Eku.Contains(oid);
        }

        public static string DescribeConstraints(NameConstraintInfo nc)
        {
            if (nc == null) return "none";
            List<string> parts = new List<string>();
            if (nc.Permitted.Count > 0) parts.Add("permitted = " + string.Join(", ", nc.Permitted.ToArray()));
            if (nc.Excluded.Count > 0) parts.Add("excluded = " + string.Join(", ", nc.Excluded.ToArray()));
            return parts.Count == 0 ? "(empty)" : string.Join("; ", parts.ToArray());
        }

        private static void RunChecks(CertInfo ci, DateTime now)
        {
            X509Certificate2 c = ci.Cert;
            bool root = ci.Kind == CertKind.Root;
            bool isCa = ci.Kind != CertKind.Leaf;
            NameConstraintInfo nc = ci.NameConstraints;

            CheckTrustAnchor(ci, root, nc);
            CheckConstraints(ci, isCa, root);
            CheckKeyUsage(ci, isCa);
            CheckEku(ci, isCa, root);
            CheckCrypto(ci, c, root);
            CheckValidity(ci, c, now, isCa);
            CheckMisc(ci, c, root, isCa);
            CheckNames(ci, isCa);
            CheckKeyExposure(ci, root);

            if (ci.InstalledIn != null && isCa)
            {
                Add(ci, Severity.Medium, "Installed", "Already trusted on this machine (" + ci.InstalledIn + ")",
                    "This authority is active on this computer right now: certificates it signs will be accepted without warning. " +
                    "Confirm the installation was intentional and documented.");
            }
        }

        private static void CheckTrustAnchor(CertInfo ci, bool root, NameConstraintInfo nc)
        {
            if (root)
            {
                if (nc == null)
                {
                    Add(ci, Severity.Critical, "NameConstraints", "Unconstrained root CA",
                        "No Name Constraints extension: whoever holds this CA's private key can issue certificates trusted for ANY domain " +
                        "(banks, mail, VPN, internal servers) once the root is installed, allowing silent TLS interception. " +
                        "Accepted for audited public CAs; unacceptable for unknown or undocumented issuers.");
                }
                else
                {
                    Add(ci, Severity.Low, "NameConstraints", "Root CA (trust anchor) with Name Constraints",
                        "Scope is restricted, but verify the namespace matches what you expect: " + DescribeConstraints(nc) + ".");
                }

                if (!ci.HasBasicConstraints)
                {
                    Add(ci, Severity.Medium, "BasicConstraints", "Self-signed certificate without Basic Constraints",
                        "It is not declared as a CA, yet some trust stores accept it as a trust anchor. Behaviour differs between validators.");
                }
            }
            else if (ci.Kind == CertKind.Intermediate && nc == null)
            {
                Add(ci, Severity.Medium, "NameConstraints", "Subordinate CA without Name Constraints",
                    "It can issue certificates for any domain inside its parent's trust scope; nothing limits the namespace it may vouch for.");
            }
            else if (ci.Kind == CertKind.Leaf && ci.SelfSigned)
            {
                Add(ci, Severity.Low, "Issuer", "Self-signed end-entity certificate",
                    "No third party vouches for this identity. If it is placed in a Trusted Root store it becomes a trust anchor for its own name.");
            }

            if (nc != null)
            {
                if (nc.Unparseable)
                {
                    Add(ci, Severity.Medium, "NameConstraints", "Name Constraints could not be decoded",
                        "The extension is malformed or uses an unsupported encoding; its restrictions cannot be verified.");
                    return;
                }

                if (!nc.Critical)
                {
                    Add(ci, Severity.Medium, "NameConstraints", "Name Constraints not marked critical",
                        "Clients that do not understand the extension ignore it, so the restriction may not be enforced everywhere.");
                }

                if (nc.Permitted.Count == 0 && nc.Excluded.Count > 0)
                {
                    Add(ci, Severity.Medium, "NameConstraints", "Name Constraints only exclude names",
                        "There is no permitted list, so every name that is not explicitly excluded remains allowed.");
                }

                if (nc.Permitted.Contains("DNS:"))
                {
                    Add(ci, Severity.High, "NameConstraints", "Name Constraints permit every DNS name",
                        "An empty DNS subtree matches all host names, so the constraint provides no protection.");
                }
            }
        }

        private static void CheckConstraints(CertInfo ci, bool isCa, bool root)
        {
            if (!isCa || !ci.HasBasicConstraints) return;

            if (!ci.BcCritical)
            {
                Add(ci, Severity.Low, "BasicConstraints", "Basic Constraints not marked critical",
                    "RFC 5280 requires the extension to be critical in CA certificates.");
            }

            if (ci.PathLen < 0)
            {
                Add(ci, root ? Severity.Low : Severity.Medium, "BasicConstraints", "No path length constraint",
                    "The CA may create sub-CAs to unlimited depth, widening the reach of a key compromise.");
            }
        }

        private static void CheckKeyUsage(CertInfo ci, bool isCa)
        {
            if (isCa)
            {
                if (!ci.HasKeyUsage)
                {
                    Add(ci, Severity.Low, "KeyUsage", "CA has no Key Usage extension",
                        "Nothing limits which cryptographic operations this CA key may be used for.");
                }
                else if ((ci.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
                {
                    Add(ci, Severity.Medium, "KeyUsage", "CA certificate without keyCertSign",
                        "Inconsistent CA flags: some validators will reject it, others will still honour it.");
                }
            }
            else if (ci.HasKeyUsage && (ci.KeyUsages & (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)) != 0)
            {
                Add(ci, Severity.High, "KeyUsage", "End-entity certificate claims certificate-signing rights",
                    "Key Usage allows signing certificates or CRLs although Basic Constraints says this is not a CA.");
            }
        }

        private static void CheckEku(CertInfo ci, bool isCa, bool root)
        {
            if (isCa)
            {
                if (ci.Eku == null)
                {
                    Add(ci, root ? Severity.High : Severity.Medium, "EKU", "CA has no Extended Key Usage restriction",
                        "It may issue certificates for every purpose: TLS, code signing, S/MIME and smart-card logon.");
                    return;
                }

                if (HasEku(ci, Oids.AnyEku))
                    Add(ci, Severity.High, "EKU", "CA allows anyExtendedKeyUsage", "Equivalent to having no purpose restriction at all.");

                if (HasEku(ci, Oids.CodeSigning))
                    Add(ci, Severity.High, "EKU", "CA may issue code-signing certificates",
                        "Enables signing malware that passes Authenticode checks and PowerShell AllSigned policies.");

                if (HasEku(ci, Oids.SmartcardLogon) || HasEku(ci, Oids.KdcAuth))
                    Add(ci, Severity.High, "EKU", "CA may issue smart-card logon / KDC authentication certificates",
                        "Combined with NTAuth trust this allows Active Directory impersonation, a known path to domain compromise.");

                if (HasEku(ci, Oids.ClientAuth))
                    Add(ci, Severity.Medium, "EKU", "CA may issue client-authentication certificates",
                        "Client identities (mutual TLS, VPN, 802.1X) can be forged.");

                if (HasEku(ci, Oids.EmailProtection))
                    Add(ci, Severity.Medium, "EKU", "CA may issue S/MIME certificates",
                        "Signed or encrypted e-mail can be forged for any address.");

                if (HasEku(ci, Oids.DocSigning))
                    Add(ci, Severity.Medium, "EKU", "CA may issue document-signing certificates",
                        "Signed documents can be forged.");
            }
            else
            {
                if (ci.Eku == null)
                {
                    Add(ci, Severity.Low, "EKU", "No Extended Key Usage", "The certificate is valid for every purpose.");
                    return;
                }

                if (HasEku(ci, Oids.AnyEku))
                    Add(ci, Severity.Medium, "EKU", "Certificate allows anyExtendedKeyUsage", "It is valid for every purpose.");

                if (HasEku(ci, Oids.CodeSigning))
                    Add(ci, Severity.Medium, "EKU", "Code-signing certificate",
                        "Can sign executables and scripts; treat as sensitive.");
            }
        }

        private static void CheckCrypto(CertInfo ci, X509Certificate2 c, bool root)
        {
            string sigOid = c.SignatureAlgorithm.Value ?? "";
            string sigName = (c.SignatureAlgorithm.FriendlyName ?? sigOid).ToLowerInvariant();

            bool broken = sigName.Contains("md5") || sigName.Contains("md4") || sigName.Contains("md2") ||
                          sigOid == "1.2.840.113549.1.1.2" || sigOid == "1.2.840.113549.1.1.3" || sigOid == "1.2.840.113549.1.1.4";

            bool sha1 = sigName.Contains("sha1") ||
                        sigOid == "1.2.840.113549.1.1.5" || sigOid == "1.3.14.3.2.29" ||
                        sigOid == "1.2.840.10040.4.3" || sigOid == "1.2.840.10045.4.1";

            string shown = c.SignatureAlgorithm.FriendlyName ?? sigOid;

            if (broken)
            {
                Add(ci, Severity.Critical, "Signature", "Broken signature hash (" + shown + ")",
                    "Practical collision attacks exist; forged certificates with a valid signature can be produced.");
            }
            else if (sha1)
            {
                if (root)
                    Add(ci, Severity.Low, "Signature", "Root self-signed with SHA-1",
                        "Not directly exploitable for a root, but it marks a legacy CA that has not been modernised.");
                else
                    Add(ci, Severity.High, "Signature", "SHA-1 signature (" + shown + ")",
                        "Chosen-prefix collision attacks are feasible; modern browsers and operating systems reject SHA-1 certificates.");
            }

            int size = ci.KeySize;
            if (ci.PublicKeyOid == Oids.Rsa && size > 0)
            {
                if (size < 1024)
                    Add(ci, Severity.Critical, "PublicKey", "Very weak RSA key (" + size + " bits)", "Keys of this size can be factored with modest resources.");
                else if (size < 2048)
                    Add(ci, Severity.High, "PublicKey", "Weak RSA key (" + size + " bits)", "Below the 2048-bit minimum required by current baselines.");
            }
            else if (ci.PublicKeyOid == Oids.Ec && size > 0)
            {
                if (size < 224)
                    Add(ci, Severity.Critical, "PublicKey", "Very weak EC key (" + size + " bits)", "Far below the security level of current baselines.");
                else if (size < 256)
                    Add(ci, Severity.High, "PublicKey", "Weak EC key (" + size + " bits)", "Below the 256-bit minimum required by current baselines.");
            }
            else if (ci.PublicKeyOid == Oids.Dsa)
            {
                Add(ci, Severity.Medium, "PublicKey", "DSA public key" + (size > 0 ? " (" + size + " bits)" : ""),
                    "DSA is deprecated and rejected by modern TLS stacks.");
            }
        }

        private static void CheckValidity(CertInfo ci, X509Certificate2 c, DateTime now, bool isCa)
        {
            double daysLeft = (c.NotAfter - now).TotalDays;

            if (now > c.NotAfter)
                Add(ci, Severity.Medium, "Validity", "Certificate expired",
                    "Expired " + (int)Math.Ceiling(-daysLeft) + " day(s) ago (" + c.NotAfter.ToString("yyyy-MM-dd") + "). It must not be trusted.");
            else if (now < c.NotBefore)
                Add(ci, Severity.Medium, "Validity", "Certificate not yet valid",
                    "Becomes valid on " + c.NotBefore.ToString("yyyy-MM-dd") + ". Check the system clock and where the file came from.");
            else if (daysLeft <= 30)
                Add(ci, Severity.Low, "Validity", "Expires soon", "Only " + (int)Math.Ceiling(daysLeft) + " day(s) left.");

            double lifetimeDays = (c.NotAfter - c.NotBefore).TotalDays;
            double years = lifetimeDays / 365.25;

            if (isCa)
            {
                if (years >= 40)
                    Add(ci, Severity.Medium, "Validity", "Extremely long validity (" + years.ToString("0") + " years)",
                        "Effectively permanent trust: it cannot be rotated in any realistic timeframe and outlives its key hygiene.");
                else if (years > 20)
                    Add(ci, Severity.Low, "Validity", "Very long validity (" + years.ToString("0") + " years)",
                        "A long-lived trust anchor stays exposed for its whole lifetime once installed.");
            }
            else if ((ci.Eku == null || HasEku(ci, Oids.ServerAuth)) && lifetimeDays > 398)
            {
                Add(ci, Severity.Low, "Validity", "TLS certificate lifetime exceeds 398 days",
                    "Public browsers reject TLS certificates valid for longer; on private CAs it prolongs exposure after a key compromise.");
            }
        }

        private static void CheckMisc(CertInfo ci, X509Certificate2 c, bool root, bool isCa)
        {
            if (c.Version == 1)
            {
                Add(ci, Severity.Medium, "Version", "X.509 version 1 certificate",
                    "No extensions at all: no Basic Constraints, Key Usage, EKU or Name Constraints can restrict what it is used for.");
            }

            byte[] serial = c.GetSerialNumber();          // little-endian
            int n = serial.Length;
            while (n > 1 && serial[n - 1] == 0) n--;
            if (n == 1 && serial[0] == 0)
                Add(ci, Severity.Low, "Serial", "Serial number is zero", "Serial numbers must be positive and unique per issuer.");
            else if (n < 8)
                Add(ci, Severity.Low, "Serial", "Short serial number (" + n + " byte" + (n == 1 ? "" : "s") + ")",
                    "Low-entropy serials make collision-based attacks on the signature easier.");

            if (isCa && !Regex.IsMatch(c.Subject, @"(^|,\s*)O="))
            {
                Add(ci, Severity.Low, "Subject", "CA subject has no Organization (O)",
                    "Anonymous CA identity: hard to attribute and hard to hold accountable.");
            }

            if (!root && ci.CrlUrls.Count == 0 && ci.AiaUrls.Count == 0)
            {
                Add(ci, Severity.Low, "Revocation", "No CRL / OCSP information",
                    "If the key is compromised, relying parties have no way to learn that the certificate was revoked.");
            }
        }

        private static void CheckNames(CertInfo ci, bool isCa)
        {
            bool tls = ci.Eku == null || HasEku(ci, Oids.ServerAuth);
            if (isCa || !tls) return;

            if (ci.San.Count == 0)
            {
                Add(ci, Severity.Medium, "SAN", "No Subject Alternative Name",
                    "Modern clients ignore the CN for host names and will reject this TLS certificate.");
                return;
            }

            bool wildcardReported = false;
            foreach (string entry in ci.San)
            {
                if (!entry.StartsWith("DNS:", StringComparison.Ordinal)) continue;
                string name = entry.Substring(4);

                if (name == "*" || Regex.IsMatch(name, @"^\*\.[^.]+$"))
                {
                    Add(ci, Severity.High, "SAN", "Wildcard covers an entire top-level domain (" + name + ")",
                        "A certificate for a whole TLD is valid for every host beneath it.");
                }
                else if (name.StartsWith("*.", StringComparison.Ordinal) && !wildcardReported)
                {
                    wildcardReported = true;
                    Add(ci, Severity.Low, "SAN", "Wildcard name (" + name + ")",
                        "One compromised key exposes every sub-domain.");
                }
            }
        }

        private static void CheckKeyExposure(CertInfo ci, bool root)
        {
            bool hasKey;
            try { hasKey = ci.Cert.HasPrivateKey; }
            catch { hasKey = false; }

            if (!hasKey) return;

            if (ci.LoadedWithEmptyPassword)
            {
                Add(ci, Severity.Critical, "PrivateKey", "Private key exposed: PKCS#12 opens with an empty password",
                    "Anyone who can read this file can extract the private key and impersonate the owner" +
                    (root ? " (and mint trusted certificates, because this is a root CA)." : "."));
            }
            else
            {
                Add(ci, root ? Severity.Critical : Severity.High, "PrivateKey", "Private key stored together with the certificate",
                    "The private key travels with this file; protect or remove it.");
            }
        }
    }
}
