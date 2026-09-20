using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace CertScan
{
    /// <summary>One TLV element of a DER structure.</summary>
    internal sealed class DerItem
    {
        public byte Tag;
        public byte[] Buffer;
        public int Start;
        public int Length;

        public int TagNumber { get { return Tag & 0x1F; } }
        public bool Constructed { get { return (Tag & 0x20) != 0; } }

        /// <summary>True for a context-specific tag with the given number ([n]).</summary>
        public bool IsContext(int number)
        {
            return (Tag & 0xC0) == 0x80 && TagNumber == number;
        }

        public DerReader Children()
        {
            return new DerReader(Buffer, Start, Start + Length);
        }

        public byte[] Content()
        {
            byte[] r = new byte[Length];
            Array.Copy(Buffer, Start, r, 0, Length);
            return r;
        }
    }

    /// <summary>Sequential reader over DER bytes (single-byte tags only, which is all X.509 extensions need).</summary>
    internal sealed class DerReader
    {
        private readonly byte[] _buf;
        private int _pos;
        private readonly int _end;

        public DerReader(byte[] buffer) : this(buffer, 0, buffer.Length) { }

        public DerReader(byte[] buffer, int start, int end)
        {
            _buf = buffer;
            _pos = start;
            _end = end;
        }

        public bool HasData { get { return _pos < _end; } }

        public DerItem Read()
        {
            if (_end - _pos < 2) throw new FormatException("Truncated DER data.");

            byte tag = _buf[_pos++];
            if ((tag & 0x1F) == 0x1F) throw new FormatException("High tag numbers are not supported.");

            int len = _buf[_pos++];
            if ((len & 0x80) != 0)
            {
                int n = len & 0x7F;
                if (n == 0 || n > 4 || _end - _pos < n) throw new FormatException("Invalid DER length.");
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | _buf[_pos++];
            }

            if (len < 0 || len > _end - _pos) throw new FormatException("DER length exceeds buffer.");

            DerItem item = new DerItem { Tag = tag, Buffer = _buf, Start = _pos, Length = len };
            _pos += len;
            return item;
        }
    }

    /// <summary>Decoders for the few extensions the analyzer needs to understand.</summary>
    internal static class DerHelper
    {
        public static string Hex(byte[] data)
        {
            return BitConverter.ToString(data).Replace('-', ':');
        }

        private static string Ascii(DerItem it)
        {
            return Encoding.ASCII.GetString(it.Buffer, it.Start, it.Length);
        }

        private static string IpText(byte[] b)
        {
            if (b.Length == 4 || b.Length == 16) return new IPAddress(b).ToString();

            if (b.Length == 8 || b.Length == 32)
            {
                int half = b.Length / 2;
                byte[] addr = new byte[half];
                byte[] mask = new byte[half];
                Array.Copy(b, 0, addr, 0, half);
                Array.Copy(b, half, mask, 0, half);
                return new IPAddress(addr) + "/" + new IPAddress(mask);
            }

            return Hex(b);
        }

        public static string GeneralName(DerItem it)
        {
            switch (it.Tag)
            {
                case 0x82: return "DNS:" + Ascii(it);
                case 0x81: return "email:" + Ascii(it);
                case 0x86: return "URI:" + Ascii(it);
                case 0x87: return "IP:" + IpText(it.Content());
                case 0xA4: return "directoryName";
                case 0xA0: return "otherName";
                default: return "type[" + it.TagNumber + "]";
            }
        }

        /// <summary>Decodes the Name Constraints extension (2.5.29.30).</summary>
        public static NameConstraintInfo ParseNameConstraints(byte[] raw)
        {
            NameConstraintInfo info = new NameConstraintInfo();
            DerItem seq = new DerReader(raw).Read();
            DerReader r = seq.Children();

            while (r.HasData)
            {
                DerItem group = r.Read();                                  // [0] permitted, [1] excluded
                List<string> target = group.IsContext(0) ? info.Permitted : info.Excluded;
                DerReader subtrees = group.Children();

                while (subtrees.HasData)
                {
                    DerItem subtree = subtrees.Read();                     // GeneralSubtree ::= SEQUENCE { base, ... }
                    target.Add(GeneralName(subtree.Children().Read()));
                }
            }

            return info;
        }

        /// <summary>Decodes a GeneralNames sequence (used for Subject Alternative Name).</summary>
        public static List<string> ParseGeneralNames(byte[] raw)
        {
            List<string> list = new List<string>();
            DerReader r = new DerReader(raw).Read().Children();
            while (r.HasData) list.Add(GeneralName(r.Read()));
            return list;
        }

        /// <summary>Collects every URI (tag [6]) found anywhere inside CRL Distribution Points / AIA.</summary>
        public static List<string> CollectUris(byte[] raw)
        {
            List<string> uris = new List<string>();
            Walk(new DerReader(raw), uris);
            return uris;
        }

        private static void Walk(DerReader r, List<string> uris)
        {
            while (r.HasData)
            {
                DerItem it = r.Read();
                if (it.Constructed) Walk(it.Children(), uris);
                else if (it.Tag == 0x86) uris.Add(Ascii(it));
            }
        }

        /// <summary>Extracts keyIdentifier from Authority Key Identifier (2.5.29.35).</summary>
        public static string AuthorityKeyId(byte[] raw)
        {
            DerReader r = new DerReader(raw).Read().Children();
            while (r.HasData)
            {
                DerItem it = r.Read();
                if (it.IsContext(0)) return Hex(it.Content());
            }
            return null;
        }
    }
}
