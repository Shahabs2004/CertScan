using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace CertScan
{
    internal static class CertLoader
    {
        private static readonly HashSet<string> Extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".cer", ".crt", ".der", ".pem", ".p7b", ".p7c", ".spc", ".pfx", ".p12"
        };

        private static readonly Regex PemBlock = new Regex(
            @"-----BEGIN (?<label>[A-Z0-9 ]+)-----(?<body>.*?)-----END \k<label>-----",
            RegexOptions.Singleline | RegexOptions.Compiled);

        private const long MaxFileSize = 16L * 1024 * 1024;

#if NET6_0_OR_GREATER
        private const X509KeyStorageFlags ImportFlags = X509KeyStorageFlags.EphemeralKeySet;
#else
        private const X509KeyStorageFlags ImportFlags = X509KeyStorageFlags.DefaultKeySet;
#endif

        /// <summary>Finds every certificate-like file in <paramref name="dir"/> and loads all certificates from them.</summary>
        public static ScanResult Scan(string dir, bool recursive)
        {
            ScanResult result = new ScanResult();
            Collect(dir, recursive, result);
            result.Files.Sort(StringComparer.OrdinalIgnoreCase);

            foreach (string file in result.Files)
                LoadFile(file, result);

            return result;
        }

        private static void Collect(string dir, bool recursive, ScanResult result)
        {
            try
            {
                foreach (string f in Directory.GetFiles(dir))
                    if (Extensions.Contains(Path.GetExtension(f)))
                        result.Files.Add(f);
            }
            catch (Exception ex)
            {
                result.Notes.Add(new FileNote { File = dir, Message = "Cannot read directory: " + ex.Message });
                return;
            }

            if (!recursive) return;

            try
            {
                foreach (string d in Directory.GetDirectories(dir))
                    Collect(d, true, result);
            }
            catch
            {
                // inaccessible sub-folders are skipped silently
            }
        }

        private static void LoadFile(string file, ScanResult result)
        {
            string name = Path.GetFileName(file);
            byte[] data;

            try
            {
                if (new FileInfo(file).Length > MaxFileSize)
                {
                    result.Notes.Add(new FileNote { File = name, Message = "Skipped: file is larger than 16 MB." });
                    return;
                }
                data = File.ReadAllBytes(file);
            }
            catch (Exception ex)
            {
                result.Notes.Add(new FileNote { File = name, Message = "Cannot read file: " + ex.Message });
                return;
            }

            string text = Encoding.ASCII.GetString(data);
            if (text.IndexOf("-----BEGIN ", StringComparison.Ordinal) >= 0)
                LoadPem(file, name, text, result);
            else
                LoadBinary(file, name, data, result);
        }

        private static void LoadPem(string file, string name, string text, ScanResult result)
        {
            int found = 0;
            List<string> keyLabels = new List<string>();

            foreach (Match m in PemBlock.Matches(text))
            {
                string label = m.Groups["label"].Value;
                string body = Regex.Replace(m.Groups["body"].Value, @"\s+", "");

                if (label.IndexOf("PRIVATE KEY", StringComparison.Ordinal) >= 0)
                {
                    keyLabels.Add(label);
                    continue;
                }

                try
                {
                    if (label == "CERTIFICATE" || label == "X509 CERTIFICATE")
                    {
                        X509Certificate2 c = new X509Certificate2(Convert.FromBase64String(body));
                        result.Certs.Add(NewInfo(file, name, "PEM", c, false));
                        found++;
                    }
                    else if (label == "PKCS7")
                    {
                        X509Certificate2Collection col = new X509Certificate2Collection();
                        col.Import(Convert.FromBase64String(body));
                        foreach (X509Certificate2 c in col)
                        {
                            result.Certs.Add(NewInfo(file, name, "PEM/PKCS#7", c, false));
                            found++;
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Notes.Add(new FileNote { File = name, Message = "Invalid " + label + " block: " + ex.Message });
                }
            }

            if (keyLabels.Count > 0)
            {
                result.Notes.Add(new FileNote
                {
                    File = name,
                    IsRisk = true,
                    Message = "File contains private key material (" + string.Join(", ", keyLabels.ToArray()) +
                              "). Anyone who can read this file can impersonate the key owner."
                });
            }

            if (found == 0 && keyLabels.Count == 0)
                result.Notes.Add(new FileNote { File = name, Message = "No certificate blocks found." });
        }

        private static void LoadBinary(string file, string name, byte[] data, ScanResult result)
        {
            string ext = Path.GetExtension(file).ToLowerInvariant();
            bool pkcs12 = ext == ".pfx" || ext == ".p12";
            string format = pkcs12 ? "PKCS#12" : (ext == ".p7b" || ext == ".p7c" || ext == ".spc") ? "PKCS#7" : "DER";

            X509Certificate2Collection col = new X509Certificate2Collection();
            try
            {
                col.Import(data, "", ImportFlags);
            }
            catch (CryptographicException)
            {
                result.Notes.Add(new FileNote
                {
                    File = name,
                    Message = pkcs12
                        ? "PKCS#12 is password-protected (or corrupt) and cannot be inspected without the password."
                        : "Not a valid certificate file."
                });
                return;
            }
            catch (Exception ex)
            {
                result.Notes.Add(new FileNote { File = name, Message = "Cannot parse: " + ex.Message });
                return;
            }

            if (col.Count == 0)
            {
                result.Notes.Add(new FileNote { File = name, Message = "File contains no certificates." });
                return;
            }

            foreach (X509Certificate2 c in col)
                result.Certs.Add(NewInfo(file, name, format, c, pkcs12));
        }

        private static CertInfo NewInfo(string path, string name, string format, X509Certificate2 cert, bool emptyPassword)
        {
            return new CertInfo
            {
                FilePath = path,
                FileName = name,
                Format = format,
                Cert = cert,
                LoadedWithEmptyPassword = emptyPassword
            };
        }
    }
}
