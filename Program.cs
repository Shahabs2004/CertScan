using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CertScan
{
    internal sealed class Options
    {
        public string TargetPath;
        public bool Recursive;
        public bool NoAnim;
        public bool Ascii;
        public bool Details;
        public bool Help;

        public static Options Parse(string[] args)
        {
            Options o = new Options();
            foreach (string raw in args)
            {
                switch (raw.ToLowerInvariant())
                {
                    case "-r":
                    case "--recursive":
                        o.Recursive = true;
                        break;
                    case "--no-anim":
                        o.NoAnim = true;
                        break;
                    case "--ascii":
                        o.Ascii = true;
                        break;
                    case "-d":
                    case "--details":
                        o.Details = true;
                        break;
                    case "-h":
                    case "--help":
                    case "/?":
                        o.Help = true;
                        break;
                    default:
                        if (!raw.StartsWith("-", StringComparison.Ordinal)) o.TargetPath = raw;
                        break;
                }
            }
            return o;
        }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            Options opt = Options.Parse(args);
            if (opt.Help)
            {
                PrintHelp();
                return 0;
            }

            Ui.Init(opt.Ascii, !opt.NoAnim);
            Console.CancelKeyPress += delegate { Ui.Shutdown(); };

            try
            {
                return Run(opt);
            }
            catch (Exception ex)
            {
                Ui.Line("  Fatal error: " + ex.Message, ConsoleColor.Red);
                return 3;
            }
            finally
            {
                Ui.Shutdown();
            }
        }

        private static int Run(Options opt)
        {
            string dir = Path.GetFullPath(opt.TargetPath ?? Directory.GetCurrentDirectory());
            if (!Directory.Exists(dir))
            {
                Ui.Line("  Directory not found: " + dir, ConsoleColor.Red);
                return 3;
            }

            View.Banner();

            // 1. discover -------------------------------------------------------------------
            View.Section("Discovery");
            Dictionary<string, string> installed = Ui.Spin("Reading trusted root stores", () => Stores.LoadInstalled());
            ScanResult scan = Ui.Spin("Scanning " + View.Shorten(dir, 60), () => CertLoader.Scan(dir, opt.Recursive));
            View.ScanSummary(dir, scan);

            if (scan.Certs.Count == 0)
            {
                View.NothingFound(dir);
                return scan.Notes.Any(n => n.IsRisk) ? 2 : 0;
            }

            // 2. analyse each certificate separately ------------------------------------------
            View.Section("Analyzing certificates");
            DateTime now = DateTime.Now;
            int total = scan.Certs.Count;

            for (int i = 0; i < total; i++)
            {
                CertInfo ci = scan.Certs[i];
                ci.Index = i + 1;

                string label = "[" + ci.Index + "/" + total + "] " + View.Shorten(ci.FileName, 34);
                Ui.ProgressLine(label, 22, 140, ConsoleColor.Cyan);
                Analyzer.Analyze(ci, installed, now);
                View.AnalysisResult(ci, label);
            }

            // 3. overview + per-certificate risk cards -----------------------------------------
            View.Section("Overview");
            View.Overview(scan.Certs);

            View.Section("Risk report");
            foreach (CertInfo ci in scan.Certs)
                View.RiskCard(ci, total);
            View.Legend();

            int exitCode = ExitCode(scan);

            // 4. full details on request ----------------------------------------------------------
            if (opt.Details)
            {
                foreach (CertInfo ci in scan.Certs)
                    View.Details(ci, total);
                return exitCode;
            }

            if (!Console.IsInputRedirected && !Console.IsOutputRedirected)
                Menu(scan.Certs);

            return exitCode;
        }

        private static int ExitCode(ScanResult scan)
        {
            Severity max = scan.Certs.Count == 0 ? Severity.Info : scan.Certs.Max(c => c.MaxSeverity);
            if (max >= Severity.High || scan.Notes.Any(n => n.IsRisk)) return 2;
            return max >= Severity.Low ? 1 : 0;
        }

        // ------------------------------------------------------------------ interactive menu

        private static void Menu(List<CertInfo> certs)
        {
            while (true)
            {
                View.MenuBar();

                ConsoleKeyInfo key;
                try { key = Console.ReadKey(true); }
                catch (InvalidOperationException) { return; }

                if (key.Key == ConsoleKey.Escape) return;

                switch (char.ToUpperInvariant(key.KeyChar))
                {
                    case 'D':
                        ShowOne(certs);
                        break;

                    case 'A':
                        foreach (CertInfo ci in certs)
                            View.Details(ci, certs.Count);
                        break;

                    case 'L':
                        foreach (CertInfo ci in certs)
                            View.RiskCard(ci, certs.Count);
                        View.Legend();
                        break;

                    case 'S':
                        Console.WriteLine();
                        View.Overview(certs);
                        break;

                    case 'Q':
                        Console.WriteLine();
                        Ui.Line("  Done. Stay safe.", ConsoleColor.Cyan);
                        return;
                }
            }
        }

        private static void ShowOne(List<CertInfo> certs)
        {
            int index = 1;

            if (certs.Count > 1)
            {
                Console.WriteLine();
                Ui.Put("  Certificate number (1-" + certs.Count + "): ", ConsoleColor.Cyan);

                try { Console.CursorVisible = true; } catch { }
                string input = Console.ReadLine();
                try { Console.CursorVisible = false; } catch { }

                if (!int.TryParse((input ?? "").Trim(), out index) || index < 1 || index > certs.Count)
                {
                    Ui.Line("  Invalid number.", ConsoleColor.Yellow);
                    return;
                }
            }

            View.Details(certs[index - 1], certs.Count);
        }

        // ------------------------------------------------------------------ help

        private static void PrintHelp()
        {
            Console.WriteLine();
            Console.WriteLine("CertScan - certificate risk scanner");
            Console.WriteLine();
            Console.WriteLine("Usage:  CertScan [folder] [options]");
            Console.WriteLine();
            Console.WriteLine("  folder           Folder to scan (default: current directory)");
            Console.WriteLine("  -r, --recursive  Include sub-folders");
            Console.WriteLine("  -d, --details    Print full details of every certificate and exit (no menu)");
            Console.WriteLine("      --no-anim    Disable animations");
            Console.WriteLine("      --ascii      Plain ASCII drawing characters (for legacy consoles)");
            Console.WriteLine("  -h, --help       Show this help");
            Console.WriteLine();
            Console.WriteLine("Scanned files: .cer .crt .der .pem .p7b .p7c .spc .pfx .p12");
            Console.WriteLine();
            Console.WriteLine("Exit code: 0 = no notable risk, 1 = low/medium risk, 2 = high/critical risk,");
            Console.WriteLine("           3 = error");
        }
    }
}
