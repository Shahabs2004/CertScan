using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace CertScan
{
    internal enum Severity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    internal enum CertKind
    {
        Root,
        Intermediate,
        Leaf
    }

    /// <summary>One risk detected on a certificate.</summary>
    internal sealed class Finding
    {
        public Severity Severity;
        public string Field;   // which certificate attribute it relates to (used to colour the details view)
        public string Title;
        public string Detail;

        public Finding(Severity severity, string field, string title, string detail)
        {
            Severity = severity;
            Field = field;
            Title = title;
            Detail = detail;
        }
    }

    /// <summary>File-level remark (unreadable file, private key inside a PEM, ...).</summary>
    internal sealed class FileNote
    {
        public string File;
        public string Message;
        public bool IsRisk;
    }

    internal sealed class NameConstraintInfo
    {
        public bool Critical;
        public bool Unparseable;
        public List<string> Permitted = new List<string>();
        public List<string> Excluded = new List<string>();
    }

    internal sealed class CertInfo
    {
        // origin
        public int Index;
        public string FilePath;
        public string FileName;
        public string Format;
        public bool LoadedWithEmptyPassword;
        public X509Certificate2 Cert;

        // classification
        public CertKind Kind;
        public bool SelfSigned;

        // parsed extensions
        public bool HasBasicConstraints;
        public bool IsCa;
        public bool BcCritical;
        public int PathLen = -1;                 // -1 = not present
        public bool HasKeyUsage;
        public X509KeyUsageFlags KeyUsages;
        public List<string> Eku;                 // null = extension absent
        public NameConstraintInfo NameConstraints;
        public List<string> San = new List<string>();
        public List<string> CrlUrls = new List<string>();
        public List<string> AiaUrls = new List<string>();
        public string SubjectKeyId;
        public string AuthorityKeyId;

        // crypto
        public string PublicKeyOid;
        public int KeySize;
        public string Sha1;
        public string Sha256;
        public string SerialHex;

        // environment
        public string InstalledIn;               // null = not in a trusted root store

        // result
        public List<Finding> Findings = new List<Finding>();
        public int Score;
        public Severity MaxSeverity;

        public bool HasRisk(string field)
        {
            return Findings.Any(f => f.Field == field && f.Severity > Severity.Info);
        }

        public int Count(Severity s)
        {
            return Findings.Count(f => f.Severity == s);
        }
    }

    internal sealed class ScanResult
    {
        public List<string> Files = new List<string>();
        public List<CertInfo> Certs = new List<CertInfo>();
        public List<FileNote> Notes = new List<FileNote>();
    }
}
