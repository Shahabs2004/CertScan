using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace CertScan
{
    internal sealed class Cell
    {
        public string Text;
        public ConsoleColor Fg;

        public Cell(string text, ConsoleColor fg = ConsoleColor.Gray)
        {
            Text = text;
            Fg = fg;
        }
    }

    /// <summary>All screen rendering. Red is reserved for risks; green means "nothing found".</summary>
    internal static class View
    {
        private const int LabelWidth = 22;

        private static readonly string[] CertArt =
        {
            " ██████╗███████╗██████╗ ████████╗",
            "██╔════╝██╔════╝██╔══██╗╚══██╔══╝",
            "██║     █████╗  ██████╔╝   ██║   ",
            "██║     ██╔══╝  ██╔══██╗   ██║   ",
            "╚██████╗███████╗██║  ██║   ██║   ",
            " ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   "
        };

        private static readonly string[] ScanArt =
        {
            "███████╗ ██████╗ █████╗ ███╗   ██╗",
            "██╔════╝██╔════╝██╔══██╗████╗  ██║",
            "███████╗██║     ███████║██╔██╗ ██║",
            "╚════██║██║     ██╔══██║██║╚██╗██║",
            "███████║╚██████╗██║  ██║██║ ╚████║",
            "╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
        };

        // ------------------------------------------------------------------ helpers

        public static string Fit(string s, int width)
        {
            if (s == null) s = "";
            if (s.Length > width) s = width > 1 ? s.Substring(0, width - 1) + G.Ell : s.Substring(0, width);
            return s.PadRight(width);
        }

        /// <summary>Shortens from the left so the tail (file name / extension) stays visible.</summary>
        public static string Shorten(string s, int max)
        {
            if (s == null) return "";
            if (s.Length <= max || max < 4) return s;
            return G.Ell + s.Substring(s.Length - (max - 1));
        }

        private static List<string> Wrap(string text, int width)
        {
            List<string> lines = new List<string>();
            if (string.IsNullOrEmpty(text)) return lines;

            StringBuilder cur = new StringBuilder();
            foreach (string word in text.Split(' '))
            {
                if (cur.Length > 0 && cur.Length + 1 + word.Length > width)
                {
                    lines.Add(cur.ToString());
                    cur.Length = 0;
                }
                if (cur.Length > 0) cur.Append(' ');
                cur.Append(word);
            }
            if (cur.Length > 0) lines.Add(cur.ToString());
            return lines;
        }

        private static string[] SplitDn(string dn)
        {
            return Regex.Split(dn ?? "", @",\s*(?=[A-Za-z0-9][A-Za-z0-9.]*=)");
        }

        private static string CommonName(X509Certificate2 c)
        {
            string n = c.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrEmpty(n) ? "(no name)" : n;
        }

        public static string Verdict(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return "DANGEROUS";
                case Severity.High: return "HIGH RISK";
                case Severity.Medium: return "MEDIUM RISK";
                case Severity.Low: return "LOW RISK";
                default: return "CLEAN";
            }
        }

        private static ConsoleColor VerdictColor(Severity s)
        {
            switch (s)
            {
                case Severity.Info: return ConsoleColor.Green;
                case Severity.Low: return ConsoleColor.DarkRed;
                default: return ConsoleColor.Red;
            }
        }

        private static ConsoleColor SevColor(Severity s)
        {
            return s == Severity.Low ? ConsoleColor.DarkRed : ConsoleColor.Red;
        }

        private static void SevTag(Severity s, bool pad)
        {
            string text;
            switch (s)
            {
                case Severity.Critical: text = " CRITICAL "; break;
                case Severity.High: text = "[HIGH]"; break;
                case Severity.Medium: text = "[MEDIUM]"; break;
                default: text = "[LOW]"; break;
            }

            if (s == Severity.Critical)
            {
                Ui.Put(text, ConsoleColor.White, ConsoleColor.Red);
            }
            else
            {
                Ui.Put(pad ? text.PadRight(10) : text, SevColor(s));
                return;
            }

            if (pad && text.Length < 10) Ui.Put(new string(' ', 10 - text.Length));
        }

        private static string RoleText(CertInfo ci)
        {
            switch (ci.Kind)
            {
                case CertKind.Root: return "ROOT CA (self-signed trust anchor)";
                case CertKind.Intermediate: return "Intermediate / subordinate CA";
                default: return ci.SelfSigned ? "End-entity certificate (self-signed)" : "End-entity (leaf) certificate";
            }
        }

        private static string KindShort(CertKind k)
        {
            switch (k)
            {
                case CertKind.Root: return "ROOT";
                case CertKind.Intermediate: return "INTER";
                default: return "LEAF";
            }
        }

        // ------------------------------------------------------------------ banner & sections

        public static void Banner()
        {
            Console.WriteLine();

            if (G.Ascii)
            {
                Ui.Line("  C E R T S C A N", ConsoleColor.Cyan);
            }
            else
            {
                for (int i = 0; i < CertArt.Length; i++)
                {
                    Ui.Put("  " + CertArt[i], i < 3 ? ConsoleColor.Cyan : ConsoleColor.DarkCyan);
                    Ui.Line(ScanArt[i], ConsoleColor.White);
                    Ui.Pause(45);
                }
            }

            string dot = G.Ascii ? " - " : "  ·  ";
            Console.WriteLine();
            Ui.Put("  ", ConsoleColor.Gray);
            Ui.Typewrite("Certificate Risk Scanner" + dot + "root / CA trust audit by Shahab Sadeghi", ConsoleColor.Gray, 6);
            Console.WriteLine();
            Ui.Line("  Read-only: files are analysed offline, nothing is installed or modified.", ConsoleColor.DarkGray);
        }

        public static void Section(string title)
        {
            Console.WriteLine();
            Ui.Put("  " + G.Arrow + " ", ConsoleColor.Cyan);
            Ui.Typewrite(title.ToUpperInvariant(), ConsoleColor.White, 5);
            Ui.Put(" ", ConsoleColor.Gray);
            Ui.Line(Ui.Rep(G.H, Math.Max(3, Ui.Width - title.Length - 6)), ConsoleColor.DarkGray);
        }

        public static void ScanSummary(string dir, ScanResult scan)
        {
            Ui.Put("    Folder   ", ConsoleColor.DarkCyan);
            Ui.Line(dir, ConsoleColor.White);
            Ui.Put("    Files    ", ConsoleColor.DarkCyan);
            Ui.Put(scan.Files.Count + " certificate file(s), ", ConsoleColor.White);
            Ui.Line(scan.Certs.Count + " certificate(s) loaded", ConsoleColor.White);
            Console.WriteLine();

            foreach (string file in scan.Files)
            {
                string f = file;
                int count = scan.Certs.Count(c => c.FilePath == f);
                Ui.Put("    " + G.Dot + " ", ConsoleColor.DarkCyan);
                Ui.Put(Fit(System.IO.Path.GetFileName(file), 38), ConsoleColor.White);
                Ui.Line(count == 0 ? "no certificate loaded" : count + " certificate(s)", count == 0 ? ConsoleColor.Yellow : ConsoleColor.Gray);
                Ui.Pause(20);
            }

            foreach (FileNote note in scan.Notes)
            {
                if (note.IsRisk)
                {
                    Ui.Put("    " + G.Cross + " ", ConsoleColor.Red);
                    Ui.Put(note.File + ": ", ConsoleColor.Red);
                    Ui.Line(note.Message, ConsoleColor.DarkRed);
                }
                else
                {
                    Ui.Put("    ! ", ConsoleColor.Yellow);
                    Ui.Put(note.File + ": ", ConsoleColor.Yellow);
                    Ui.Line(note.Message, ConsoleColor.DarkYellow);
                }
                Ui.Pause(20);
            }
        }

        public static void NothingFound(string dir)
        {
            Console.WriteLine();
            Ui.Line("    No certificates found in this folder.", ConsoleColor.Yellow);
            Ui.Line("    Supported: .cer .crt .der .pem .p7b .p7c .pfx .p12   (use -r to include sub-folders)", ConsoleColor.DarkGray);
            Ui.Line("    Tip: copy the certificate file next to CertScan.exe, or pass a folder:  CertScan <folder>", ConsoleColor.DarkGray);
        }

        // ------------------------------------------------------------------ analysis progress

        public static void AnalysisResult(CertInfo ci, string label)
        {
            if (ci.Findings.Count == 0)
            {
                Ui.Put("  " + G.Check + " ", ConsoleColor.Green);
                Ui.Put(Fit(label, 46), ConsoleColor.Gray);
                Ui.Line("CLEAN", ConsoleColor.Green);
            }
            else
            {
                ConsoleColor vc = VerdictColor(ci.MaxSeverity);
                Ui.Put("  " + G.Cross + " ", vc);
                Ui.Put(Fit(label, 46), ConsoleColor.Gray);
                Ui.Put(Verdict(ci.MaxSeverity).PadRight(13), vc);
                Ui.Line(ci.Findings.Count + " risk(s)", vc);
            }
            Ui.Pause(15);
        }

        // ------------------------------------------------------------------ tables

        private static void TableRule(string left, string mid, string right, int[] widths, ConsoleColor border)
        {
            Ui.Put("  " + left, border);
            for (int i = 0; i < widths.Length; i++)
            {
                Ui.Put(Ui.Rep(G.H, widths[i] + 2), border);
                Ui.Put(i == widths.Length - 1 ? right : mid, border);
            }
            Console.WriteLine();
        }

        private static void TableRow(Cell[] cells, int[] widths, ConsoleColor border)
        {
            Ui.Put("  " + G.V, border);
            for (int i = 0; i < widths.Length; i++)
            {
                Ui.Put(" " + Fit(cells[i].Text, widths[i]) + " ", cells[i].Fg);
                Ui.Put(G.V, border);
            }
            Console.WriteLine();
        }

        private static void Table(string[] headers, int[] widths, List<Cell[]> rows, ConsoleColor border, int rowPause)
        {
            TableRule(G.TL, G.TM, G.TR, widths, border);
            TableRow(headers.Select(h => new Cell(h, ConsoleColor.White)).ToArray(), widths, border);
            TableRule(G.ML, G.X, G.MR, widths, border);
            foreach (Cell[] row in rows)
            {
                TableRow(row, widths, border);
                Ui.Pause(rowPause);
            }
            TableRule(G.BL, G.BM, G.BR, widths, border);
        }

        public static void Overview(List<CertInfo> certs)
        {
            int width = Ui.Width;
            bool bar = width >= 100;
            int barWidth = bar ? 8 : 0;
            int riskWidth = bar ? barWidth + 4 : 3;
            int fixedWidth = 3 + 5 + riskWidth + 11 + 7;
            int remaining = Math.Max(20, width - 25 - fixedWidth);
            int fileWidth = Math.Max(10, remaining * 2 / 5);
            int subjectWidth = Math.Max(10, remaining - fileWidth);

            int[] widths = { 3, fileWidth, subjectWidth, 5, riskWidth, 11, 7 };
            string[] headers = { "#", "File", "Subject (CN)", "Type", "Risk", "Verdict", "C/H/M/L" };

            List<Cell[]> rows = new List<Cell[]>();
            foreach (CertInfo ci in certs)
            {
                ConsoleColor vc = VerdictColor(ci.MaxSeverity);
                string risk = (bar ? Ui.Bar(ci.Score, 100, barWidth) + " " : "") + ci.Score.ToString().PadLeft(3);
                string counts = ci.Count(Severity.Critical) + "/" + ci.Count(Severity.High) + "/" +
                                ci.Count(Severity.Medium) + "/" + ci.Count(Severity.Low);

                rows.Add(new[]
                {
                    new Cell(ci.Index.ToString(), ConsoleColor.Gray),
                    new Cell(ci.FileName, ConsoleColor.White),
                    new Cell(CommonName(ci.Cert), ConsoleColor.White),
                    new Cell(KindShort(ci.Kind), ConsoleColor.Cyan),
                    new Cell(risk, vc),
                    new Cell(Verdict(ci.MaxSeverity), vc),
                    new Cell(counts, ci.Findings.Count == 0 ? ConsoleColor.DarkGray : vc)
                });
            }

            Table(headers, widths, rows, ConsoleColor.DarkGray, 30);
            Console.WriteLine();

            int dangerous = certs.Count(c => c.MaxSeverity == Severity.Critical);
            int high = certs.Count(c => c.MaxSeverity == Severity.High);
            int medium = certs.Count(c => c.MaxSeverity == Severity.Medium);
            int low = certs.Count(c => c.MaxSeverity == Severity.Low);
            int clean = certs.Count(c => c.MaxSeverity == Severity.Info);

            Ui.Put("  Totals  ", ConsoleColor.DarkCyan);
            Ui.Put(certs.Count + " certificate(s)   ", ConsoleColor.White);
            Ui.Put(dangerous + " dangerous  ", dangerous > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray);
            Ui.Put(high + " high  ", high > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray);
            Ui.Put(medium + " medium  ", medium > 0 ? ConsoleColor.Red : ConsoleColor.DarkGray);
            Ui.Put(low + " low  ", low > 0 ? ConsoleColor.DarkRed : ConsoleColor.DarkGray);
            Ui.Line(clean + " clean", clean > 0 ? ConsoleColor.Green : ConsoleColor.DarkGray);
        }

        // ------------------------------------------------------------------ risk report

        public static void Findings(CertInfo ci, string prefix, ConsoleColor border)
        {
            int textWidth = Math.Max(30, Ui.Width - prefix.Length - 10);

            if (ci.Findings.Count == 0)
            {
                Ui.Put(prefix, border);
                Ui.Line(G.Check + " No risks detected", ConsoleColor.Green);
                return;
            }

            foreach (Finding f in ci.Findings)
            {
                ConsoleColor color = SevColor(f.Severity);
                Ui.Put(prefix, border);
                Ui.Put(G.Cross + " ", color);
                SevTag(f.Severity, true);
                Ui.Put(" ", ConsoleColor.Gray);
                Ui.Line(f.Title, color);

                foreach (string line in Wrap(f.Detail, textWidth))
                {
                    Ui.Put(prefix, border);
                    Ui.Line("    " + line, ConsoleColor.DarkRed);
                }
                Ui.Pause(25);
            }
        }

        public static void RiskCard(CertInfo ci, int total)
        {
            X509Certificate2 c = ci.Cert;
            ConsoleColor vc = VerdictColor(ci.MaxSeverity);
            int width = Ui.Width;
            int valueWidth = Math.Max(20, width - 16);
            string prefix = "  " + G.V + " ";

            string title = " [" + ci.Index + "/" + total + "] " + ci.FileName + " ";
            Console.WriteLine();
            Ui.Put("  " + G.TL + G.H, vc);
            Ui.Put(title, ConsoleColor.White);
            Ui.Line(Ui.Rep(G.H, width - title.Length - 5), vc);

            CardRow(prefix, vc, "Subject", Shorten(c.Subject, valueWidth), ConsoleColor.White);
            CardRow(prefix, vc, "Issuer", ci.SelfSigned ? "(self-signed)" : Shorten(c.Issuer, valueWidth), ConsoleColor.White);
            CardRow(prefix, vc, "Role", RoleText(ci), ConsoleColor.Cyan);
            CardRow(prefix, vc, "Valid", c.NotBefore.ToString("yyyy-MM-dd") + " " + (G.Ascii ? "->" : "→") + " " + c.NotAfter.ToString("yyyy-MM-dd"), ConsoleColor.Gray);
            CardRow(prefix, vc, "SHA-1", ci.Sha1.Replace(":", ""), ConsoleColor.DarkGray);

            Ui.Put(prefix, vc);
            Ui.Put("Verdict  ", ConsoleColor.DarkCyan);
            Ui.Put(Verdict(ci.MaxSeverity), vc);
            Ui.Put("   " + Ui.Bar(ci.Score, 100, 20) + " " + ci.Score + "/100", vc);
            Console.WriteLine();

            Ui.Put("  " + G.ML, vc);
            Ui.Line(Ui.Rep(G.H, width - 4), vc);

            Findings(ci, prefix, vc);

            Ui.Put("  " + G.BL, vc);
            Ui.Line(Ui.Rep(G.H, width - 4), vc);
        }

        private static void CardRow(string prefix, ConsoleColor border, string label, string value, ConsoleColor valueColor)
        {
            Ui.Put(prefix, border);
            Ui.Put(label.PadRight(9), ConsoleColor.DarkCyan);
            Ui.Line(value, valueColor);
        }

        public static void Legend()
        {
            Console.WriteLine();
            Ui.Put("  Legend  ", ConsoleColor.DarkCyan);
            SevTag(Severity.Critical, false);
            Ui.Put("  ", ConsoleColor.Gray);
            SevTag(Severity.High, false);
            Ui.Put("  ", ConsoleColor.Gray);
            SevTag(Severity.Medium, false);
            Ui.Put("  ", ConsoleColor.Gray);
            SevTag(Severity.Low, false);
            Ui.Put("     red = risk   ", ConsoleColor.DarkGray);
            Ui.Line(G.Check + " green = nothing found", ConsoleColor.Green);
        }

        // ------------------------------------------------------------------ full details

        private static void Group(string title)
        {
            Console.WriteLine();
            Ui.Put("  " + G.H + G.H + " ", ConsoleColor.DarkGray);
            Ui.Put(title, ConsoleColor.Cyan);
            Ui.Put(" ", ConsoleColor.Gray);
            Ui.Line(Ui.Rep(G.H, Math.Max(3, Ui.Width - title.Length - 7)), ConsoleColor.DarkGray);
        }

        private static void KV(string label, string value, bool risk = false, ConsoleColor normal = ConsoleColor.White)
        {
            Ui.Put("    " + label.PadRight(LabelWidth), ConsoleColor.DarkCyan);
            Ui.Line(value, risk ? ConsoleColor.Red : normal);
        }

        private static void KVLines(string label, IEnumerable<string> lines, bool risk = false)
        {
            bool first = true;
            foreach (string l in lines)
            {
                Ui.Put("    " + (first ? label : "").PadRight(LabelWidth), ConsoleColor.DarkCyan);
                Ui.Line(l, risk ? ConsoleColor.Red : ConsoleColor.White);
                first = false;
            }
            if (first) KV(label, "-", risk);
        }

        public static void Details(CertInfo ci, int total)
        {
            X509Certificate2 c = ci.Cert;
            DateTime now = DateTime.Now;

            Console.WriteLine();
            string title = " CERTIFICATE " + ci.Index + "/" + total + "   " + ci.FileName + " ";
            Ui.Put("  " + Ui.Rep(G.HH, 3), ConsoleColor.Cyan);
            Ui.Put(title, ConsoleColor.White);
            Ui.Line(Ui.Rep(G.HH, Math.Max(3, Ui.Width - title.Length - 5)), ConsoleColor.Cyan);

            Group("Identity");
            KVLines("Subject", SplitDn(c.Subject), ci.HasRisk("Subject"));
            KVLines("Issuer", SplitDn(c.Issuer), ci.HasRisk("Issuer"));
            KV("Role", RoleText(ci), false, ConsoleColor.Cyan);
            KV("Source file", ci.FileName + "   [" + ci.Format + "]");
            KV("Full path", ci.FilePath, false, ConsoleColor.DarkGray);
            KV("Trusted root store", ci.InstalledIn ?? "not installed on this machine", ci.HasRisk("Installed"),
               ci.InstalledIn == null ? ConsoleColor.Green : ConsoleColor.White);

            Group("Validity");
            bool vr = ci.HasRisk("Validity");
            double daysLeft = (c.NotAfter - now).TotalDays;
            string status = now > c.NotAfter ? "EXPIRED " + (int)Math.Ceiling(-daysLeft) + " day(s) ago"
                          : now < c.NotBefore ? "NOT YET VALID"
                          : "valid, " + (int)daysLeft + " day(s) remaining";
            KV("Not before", c.NotBefore.ToString("yyyy-MM-dd HH:mm:ss"));
            KV("Not after", c.NotAfter.ToString("yyyy-MM-dd HH:mm:ss"), vr);
            KV("Status", status, vr, ConsoleColor.Green);
            KV("Lifetime", ((c.NotAfter - c.NotBefore).TotalDays / 365.25).ToString("0.0") + " years", vr);

            Group("Fingerprints");
            KV("SHA-1", ci.Sha1);
            string[] parts = ci.Sha256.Split(':');
            KVLines("SHA-256", new[]
            {
                string.Join(":", parts, 0, 16),
                string.Join(":", parts, 16, parts.Length - 16)
            });

            Group("Cryptography");
            bool hasKey;
            try { hasKey = c.HasPrivateKey; } catch { hasKey = false; }
            string sigFriendly = c.SignatureAlgorithm.FriendlyName ?? "unknown";
            string keyText = (c.PublicKey.Oid.FriendlyName ?? c.PublicKey.Oid.Value) + (ci.KeySize > 0 ? "  " + ci.KeySize + " bits" : "");
            KV("Version", "v" + c.Version, ci.HasRisk("Version"));
            KV("Serial number", ci.SerialHex, ci.HasRisk("Serial"));
            KV("Signature algorithm", sigFriendly + "  (" + c.SignatureAlgorithm.Value + ")", ci.HasRisk("Signature"));
            KV("Public key", keyText, ci.HasRisk("PublicKey"));
            KV("Private key in file", hasKey ? "YES - key material is inside this file" : "no", ci.HasRisk("PrivateKey"), ConsoleColor.Green);

            Group("Constraints & permitted usage");
            string bcText = !ci.HasBasicConstraints
                ? "(not present)"
                : "CA=" + (ci.IsCa ? "yes" : "no") + ", pathLen=" + (ci.PathLen < 0 ? "unlimited" : ci.PathLen.ToString()) +
                  ", " + (ci.BcCritical ? "critical" : "NOT critical");
            KV("Basic Constraints", bcText, ci.HasRisk("BasicConstraints"));
            KV("Key Usage", ci.HasKeyUsage ? ci.KeyUsages.ToString() : "(not present)", ci.HasRisk("KeyUsage"));

            List<string> ekuLines = new List<string>();
            if (ci.Eku == null) ekuLines.Add("(not present - valid for ALL purposes)");
            else foreach (string o in ci.Eku) ekuLines.Add(Oids.Name(o, null) + "  (" + o + ")");
            KVLines("Extended Key Usage", ekuLines, ci.HasRisk("EKU"));

            List<string> ncLines = new List<string>();
            NameConstraintInfo nc = ci.NameConstraints;
            if (nc == null)
            {
                ncLines.Add(ci.Kind == CertKind.Leaf ? "(not present)" : "(not present - UNRESTRICTED namespace)");
            }
            else if (nc.Unparseable)
            {
                ncLines.Add("(present but could not be decoded)");
            }
            else
            {
                ncLines.Add(nc.Critical ? "critical" : "NOT critical");
                foreach (string p in nc.Permitted) ncLines.Add("permitted  " + p);
                foreach (string x in nc.Excluded) ncLines.Add("excluded   " + x);
            }
            KVLines("Name Constraints", ncLines, ci.HasRisk("NameConstraints"));

            Group("Names & revocation");
            KVLines("Subject Alt Names", ci.San.Count == 0 ? new List<string> { "(none)" } : ci.San, ci.HasRisk("SAN"));
            KVLines("CRL distribution", ci.CrlUrls.Count == 0 ? new List<string> { "(none)" } : ci.CrlUrls, ci.HasRisk("Revocation"));
            KVLines("Authority info (AIA)", ci.AiaUrls.Count == 0 ? new List<string> { "(none)" } : ci.AiaUrls, ci.HasRisk("Revocation"));
            KV("Subject Key ID", ci.SubjectKeyId ?? "(none)", false, ConsoleColor.Gray);
            KV("Authority Key ID", ci.AuthorityKeyId ?? "(none)", false, ConsoleColor.Gray);

            Group("All extensions");
            int nameWidth = Math.Max(16, Ui.Width - 24 - 8 - 6 - 16);
            int[] widths = { 24, nameWidth, 8, 6 };
            List<Cell[]> rows = new List<Cell[]>();
            foreach (X509Extension e in c.Extensions)
            {
                string oid = e.Oid.Value;
                rows.Add(new[]
                {
                    new Cell(oid, ConsoleColor.Gray),
                    new Cell(Oids.Name(oid, e.Oid.FriendlyName), ConsoleColor.White),
                    new Cell(e.Critical ? "critical" : "-", e.Critical ? ConsoleColor.Yellow : ConsoleColor.DarkGray),
                    new Cell(e.RawData.Length.ToString(), ConsoleColor.DarkGray)
                });
            }
            if (rows.Count == 0) rows.Add(new[] { new Cell("(none)"), new Cell(""), new Cell(""), new Cell("") });
            Table(new[] { "OID", "Extension", "Flag", "Bytes" }, widths, rows, ConsoleColor.DarkGray, 0);

            Group("Risks");
            Findings(ci, "    ", ConsoleColor.DarkGray);

            Console.WriteLine();
            Ui.Line("  " + Ui.Rep(G.HH, Math.Max(3, Ui.Width - 3)), ConsoleColor.Cyan);
        }

        // ------------------------------------------------------------------ menu

        private static void MenuKey(string key, string text)
        {
            Ui.Put("[", ConsoleColor.DarkGray);
            Ui.Put(key, ConsoleColor.Cyan);
            Ui.Put("] ", ConsoleColor.DarkGray);
            Ui.Put(text + "   ", ConsoleColor.Gray);
        }

        public static void MenuBar()
        {
            Console.WriteLine();
            Ui.Put("  ", ConsoleColor.Gray);
            MenuKey("D", "Full details of one");
            MenuKey("A", "Details of all");
            MenuKey("L", "Risk list");
            MenuKey("S", "Summary table");
            MenuKey("Q", "Quit");
            Console.WriteLine();
        }
    }
}
