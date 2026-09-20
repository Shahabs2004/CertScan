using System;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace CertScan
{
    /// <summary>Glyphs: Unicode box-drawing (WGL4 subset, safe in Consolas) or plain ASCII fallback.</summary>
    internal static class G
    {
        public static bool Ascii;

        public static string H { get { return Ascii ? "-" : "─"; } }
        public static string HH { get { return Ascii ? "=" : "═"; } }
        public static string V { get { return Ascii ? "|" : "│"; } }
        public static string TL { get { return Ascii ? "+" : "┌"; } }
        public static string TR { get { return Ascii ? "+" : "┐"; } }
        public static string BL { get { return Ascii ? "+" : "└"; } }
        public static string BR { get { return Ascii ? "+" : "┘"; } }
        public static string ML { get { return Ascii ? "+" : "├"; } }
        public static string MR { get { return Ascii ? "+" : "┤"; } }
        public static string TM { get { return Ascii ? "+" : "┬"; } }
        public static string BM { get { return Ascii ? "+" : "┴"; } }
        public static string X { get { return Ascii ? "+" : "┼"; } }

        public static string Full { get { return Ascii ? "#" : "█"; } }
        public static string Empty { get { return Ascii ? "." : "░"; } }
        public static string Dot { get { return Ascii ? "*" : "●"; } }
        public static string Cross { get { return Ascii ? "x" : "×"; } }
        public static string Check { get { return Ascii ? "+" : "√"; } }
        public static string Arrow { get { return Ascii ? ">" : "►"; } }
        public static string Ell { get { return Ascii ? "~" : "…"; } }
        public static string Spinner { get { return Ascii ? "|/-\\" : "▌▀▐▄"; } }
    }

    internal static class Ui
    {
        public static bool Animate = true;

        public static void Init(bool ascii, bool animate)
        {
            G.Ascii = ascii;
            Animate = animate && !Console.IsOutputRedirected;

            try { if (!ascii) Console.OutputEncoding = new UTF8Encoding(false); } catch { }
            try { Console.CursorVisible = false; } catch { }
            try { Console.Title = "CertScan - Certificate Risk Scanner"; } catch { }
        }

        public static void Shutdown()
        {
            try { Console.ResetColor(); } catch { }
            try { Console.CursorVisible = true; } catch { }
        }

        public static int Width
        {
            get
            {
                try { return Math.Max(79, Math.Min(Console.WindowWidth - 1, 130)); }
                catch { return 100; }
            }
        }

        // ------------------------------------------------------------------ basic output

        public static void Put(string text, ConsoleColor fg = ConsoleColor.Gray, ConsoleColor? bg = null)
        {
            Console.ForegroundColor = fg;
            if (bg.HasValue) Console.BackgroundColor = bg.Value;
            Console.Write(text);
            Console.ResetColor();
        }

        public static void Line(string text = "", ConsoleColor fg = ConsoleColor.Gray, ConsoleColor? bg = null)
        {
            Put(text, fg, bg);
            Console.WriteLine();
        }

        public static string Rep(string s, int count)
        {
            if (count <= 0) return "";
            StringBuilder sb = new StringBuilder(s.Length * count);
            for (int i = 0; i < count; i++) sb.Append(s);
            return sb.ToString();
        }

        public static void Pause(int ms)
        {
            if (Animate && ms > 0) Thread.Sleep(ms);
        }

        public static void ClearLine()
        {
            if (!Animate) return;
            Console.Write("\r" + new string(' ', Width) + "\r");
        }

        // ------------------------------------------------------------------ animations

        /// <summary>Types text out character by character.</summary>
        public static void Typewrite(string text, ConsoleColor fg, int msPerChar)
        {
            if (!Animate)
            {
                Put(text, fg);
                return;
            }

            foreach (char ch in text)
            {
                Put(ch.ToString(), fg);
                Thread.Sleep(msPerChar);
            }
        }

        public static string Bar(int value, int max, int width)
        {
            if (max <= 0 || width <= 0) return "";
            int filled = (int)Math.Round((double)Math.Max(0, Math.Min(value, max)) / max * width);
            return Rep(G.Full, filled) + Rep(G.Empty, width - filled);
        }

        /// <summary>Runs work on a background thread while a small spinner is shown.</summary>
        public static T Spin<T>(string message, Func<T> work, int minMs = 450)
        {
            if (!Animate)
            {
                T direct = work();
                Line("  " + G.Check + " " + message, ConsoleColor.Green);
                return direct;
            }

            T result = default(T);
            Exception error = null;

            Thread worker = new Thread(() =>
            {
                try { result = work(); }
                catch (Exception ex) { error = ex; }
            });
            worker.IsBackground = true;
            worker.Start();

            string frames = G.Spinner;
            Stopwatch sw = Stopwatch.StartNew();
            int i = 0;

            while (worker.IsAlive || sw.ElapsedMilliseconds < minMs)
            {
                Console.Write("\r");
                Put("  " + frames[i++ % frames.Length] + " ", ConsoleColor.Cyan);
                Put(message + "...", ConsoleColor.Gray);
                Thread.Sleep(80);
            }

            worker.Join();
            ClearLine();

            if (error != null) throw new InvalidOperationException(error.Message, error);

            Put("  " + G.Check + " ", ConsoleColor.Green);
            Line(message, ConsoleColor.Gray);
            return result;
        }

        /// <summary>Quick left-to-right progress bar that erases itself when finished.</summary>
        public static void ProgressLine(string label, int barWidth, int totalMs, ConsoleColor color)
        {
            if (!Animate) return;

            int delay = Math.Max(1, totalMs / Math.Max(1, barWidth));
            for (int i = 0; i <= barWidth; i++)
            {
                Console.Write("\r");
                Put("  " + G.Arrow + " " + label + " ", ConsoleColor.Gray);
                Put(Bar(i, barWidth, barWidth), color);
                Put(" " + (i * 100 / barWidth).ToString().PadLeft(3) + "%", ConsoleColor.DarkGray);
                Thread.Sleep(delay);
            }

            ClearLine();
        }
    }
}
