/*  This file is part of Wii NAND Extractor.
 *  Copyright (C) 2009 Ben Wilson
 *
 *  Wii NAND Extractor is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Wii NAND Extractor is distributed in the hope that it will be
 *  useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *  of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace NAND_Extractor
{
    public class Nand
    {
        public class Node
        {
            public ushort Key { get; }
            public string Description { get; }
            public List<Node> Children { get; } = new List<Node>();
            public byte Mode { get; }

            public Node(ushort key, string description, byte mode)
            {
                Description = description;
                Key = key;
                Mode = mode;
            }
        }

        public class Fst_t
        {
            public byte[] filename = new byte[0x0B];
            public byte mode;
            public byte attr;
            public UInt16 sub;
            public UInt16 sib;
            public UInt32 size;
            public UInt32 uid;
            public UInt16 gid;
            public UInt32 x3;
        }

        private enum DumpType
        {
             Unknown = -1,
             NoEcc = 0,
             Ecc = 1,
             OldBootMii = 2,
        }

        public byte[] key = new byte[16];
        readonly byte[] iv = new byte[16];
        readonly Int32 loc_super;
        readonly Int32 loc_fat;
        readonly Int32 loc_fst;
        readonly DumpType type = DumpType.Unknown;

        public string FilePath { get; }
        public Node FstRoot { get; }
        public uint Size { get; private set; }
        public uint Files { get; private set; }

        public Nand(string path)
        {
            FilePath = path;
            using var rom = new BinaryReader(File.Open(FilePath,
                                        FileMode.Open,
                                        FileAccess.Read,
                                        FileShare.Read),
                                    Encoding.ASCII);


            type = GetDumpType(rom.BaseStream.Length);

            try
            {
                loc_super = FindSuperblock(rom);
            }
            catch
            {
                throw new InvalidOperationException("Can't find superblock.\nAre you sure this is a Full (with ECC) or BootMii NAND dump?");
            }

            Int32[] n_fatlen = { 0x010000, 0x010800, 0x010800 };
            loc_fat = loc_super;
            loc_fst = loc_fat + 0x0C + n_fatlen[(int)type];

            string filename = Path.GetFileName(FilePath);
            string details_desc = "   mode|attr   uid:gid   filesize (in bytes)";


            filename = Path.ChangeExtension(filename, null);

            FstRoot = new Node(0, filename + details_desc, 2);

            ViewFST(0, FstRoot, rom);
        }

        internal void Extract(Node node, string extractPath)
        {
            using var rom = new BinaryReader(File.Open(FilePath,
                                        FileMode.Open,
                                        FileAccess.Read,
                                        FileShare.Read),
                                    Encoding.ASCII);

            ExtractFST(node.Key, "", rom, extractPath, true);
        }

        private DumpType GetDumpType(Int64 FileSize) => FileSize switch
        {
            536870912 => DumpType.NoEcc,
            553648128 => DumpType.Ecc,
            553649152 => DumpType.OldBootMii,
            _ => DumpType.Unknown
        };

        public void LoadKey()
        {
            switch (type)
            {
                case DumpType.NoEcc:
                case DumpType.Ecc:
                    var keyPath = Path.Combine(Path.GetDirectoryName(FilePath), "keys.bin");
                    key = ReadKeyfile(keyPath);
                    return;

                case DumpType.OldBootMii:
                    using (var rom = new BinaryReader(File.Open(FilePath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read),
                    Encoding.ASCII))
                    {
                        rom.BaseStream.Seek(0x21000158, SeekOrigin.Begin);
                        var readBytes = rom.Read(key, 0, 16);
                        if (readBytes != 16)
                            throw new InvalidOperationException($"Tried to read 16 bytes as key but only got {readBytes}");
                        return;
                    }
                default:
                    throw new NotImplementedException();
            };
        }

        public static byte[] ReadKeyfile(string path)
        {
            if (!File.Exists(path))
                throw new ArgumentException(string.Format("You tried to open a file that doesn't exist:\n{0}", path));

            try
            {
                byte[] retval = new byte[16];
                BinaryReader br = new BinaryReader(File.Open(path,
                            FileMode.Open,
                            FileAccess.Read,
                            FileShare.Read),
                            Encoding.ASCII);
                br.BaseStream.Seek(0x158, SeekOrigin.Begin);
                br.Read(retval, 0, 16);
                br.Close();
                return retval;
            }
            catch
            {
                throw new InvalidOperationException(string.Format("Can't open key.bin:\n{0}\n" +
                                        "Try closing any program(s) that may be accessing it.",
                                        path));
            }
        }

        private Int32 FindSuperblock(BinaryReader rom)
        {
            Int32 loc, current, last = 0;

            var (start, end, len) = type switch
            {
                DumpType.NoEcc => (0x1FC00000, 0x20000000, 0x40000),
                DumpType.Ecc => (0x20BE0000, 0x21000000, 0x42000),
                DumpType.OldBootMii => (0x20BE0000, 0x21000000, 0x42000),
                _ => throw new NotSupportedException()
            };

            rom.BaseStream.Seek(start + 4, SeekOrigin.Begin);

            for (loc = start; loc < end; loc += len)
            {
                current = (int) Bswap(rom.ReadUInt32());

                if (current > last)
                    last = current;
                else
                    return loc - len;

                rom.BaseStream.Seek(len - 4, SeekOrigin.Current);
            }

            throw new InvalidOperationException("No superblock found");
        }

        private byte[] GetCluster(UInt16 cluster_entry, BinaryReader rom)
        {
            var (clusterlen, pagelen) = type switch
            {
                DumpType.NoEcc => (0x4000, 0x800),
                DumpType.Ecc => (0x4200, 0x840),
                DumpType.OldBootMii => (0x4200, 0x840),
                _ => throw new NotSupportedException()
            };

            byte[] cluster = new byte[0x4000];

            rom.BaseStream.Seek(cluster_entry * clusterlen, SeekOrigin.Begin);

            for (int i = 0; i < 8; i++)
            {
                byte[] page = rom.ReadBytes(pagelen);
                Buffer.BlockCopy(page, 0, cluster, i * 0x800, 0x800);
            }

            return AesDecrypt(key, iv, cluster);
        }

        private UInt16 GetFAT(UInt16 fat_entry, BinaryReader rom)
        {
            /*
             * compensate for "off-16" storage at beginning of superblock
             * 53 46 46 53   XX XX XX XX   00 00 00 00
             * S  F  F  S     "version"     padding?
             *   1     2       3     4       5     6
             */
            fat_entry += 6;

            // location in fat of cluster chain
            var n_fat = type switch
            {
                DumpType.NoEcc => 0, DumpType.Ecc => 0x20, DumpType.OldBootMii =>  0x20,
                _ => throw new NotSupportedException()
            };
            int loc = loc_fat + (fat_entry / 0x400 * n_fat + fat_entry) * 2;

            rom.BaseStream.Seek(loc, SeekOrigin.Begin);
            return Bswap(rom.ReadUInt16());
        }

        private Fst_t GetFST(UInt16 entry, BinaryReader rom)
        {
            Fst_t fst = new Fst_t();

            // compensate for 64 bytes of ecc data every 64 fst entries
            var n_fst = type switch
            {
                DumpType.NoEcc => 0,
                DumpType.Ecc => 2,
                DumpType.OldBootMii => 2,
                _ => throw new NotSupportedException()
            };
            int loc_entry = (entry / 0x40 * n_fst + entry) * 0x20;

            rom.BaseStream.Seek(loc_fst + loc_entry, SeekOrigin.Begin);

            fst.filename = rom.ReadBytes(0x0C);
            fst.mode = rom.ReadByte();
            fst.attr = rom.ReadByte();
            fst.sub = Bswap(rom.ReadUInt16());
            fst.sib = Bswap(rom.ReadUInt16());
            fst.size = Bswap(rom.ReadUInt32());
            fst.uid = Bswap(rom.ReadUInt32());
            fst.gid = Bswap(rom.ReadUInt16());
            fst.x3 = Bswap(rom.ReadUInt32());

            fst.mode &= 1;

            return fst;
        }

        /*
         * Viewer functions.
         */
        private void ViewFST(UInt16 entry, Node parent, BinaryReader rom)
        {
            Fst_t fst = GetFST(entry, rom);

            if (fst.sib != 0xffff)
                ViewFST(fst.sib, parent, rom);

            AddEntry(fst, entry, parent, rom);

            Size += fst.size;
            Files++;
            Application.DoEvents();
        }

        private void AddEntry(Fst_t fst, UInt16 entry, Node parent, BinaryReader rom)
        {
            string details;
            string[] modes = { "d|", "f|" };

            details = ASCIIEncoding.ASCII.GetString(fst.filename).Replace("\0", " ");
            details += TxtPadLeft(modes[fst.mode], 5);
            details += TxtPadRight( fst.attr.ToString(), 3 );
            details += string.Format("{0}:{1}",
                            fst.uid.ToString("x4").ToUpper(),
                            fst.gid.ToString("x4").ToUpper() );
            if (fst.size > 0)
                details += TxtPadLeft(fst.size.ToString("d"), 11) + "B";

            if (entry != 0)
            {
                var child = new Node(entry, details, fst.mode);
                parent.Children.Add(child);
                parent = child;
            }

            if (fst.mode == 0 && fst.sub != 0xffff)
                ViewFST(fst.sub, parent, rom);
        }

        private void ExtractFST(UInt16 entry, string parent, BinaryReader rom, string extractPath, bool single)
        {
            Fst_t fst = GetFST(entry, rom);

            if (fst.sib != 0xffff && !single)
                ExtractFST(fst.sib, parent, rom, extractPath, single);

            switch (fst.mode)
            {
                case 0:
                    ExtractDir(fst, parent, rom, extractPath);
                    break;
                case 1:
                    ExtractFile(fst, parent, rom, extractPath);
                    break;
                default:
                    throw new NotSupportedException(String.Format("Unsupported mode {0}.\n\t\t(FST entry #{1})",
                                                fst.mode,
                                                entry.ToString("x4")));
            }
        }

        private void ExtractDir(Fst_t fst, string parent, BinaryReader rom, string extractPath)
        {
            string filename = ASCIIEncoding.ASCII.GetString(fst.filename).Replace("\0", string.Empty);

            if (filename != "/")
            {
                if (parent != "/" && parent != "")
                    filename = Path.Combine(parent, filename);

                Directory.CreateDirectory(Path.Combine(extractPath, filename));
            }

            if (fst.sub != 0xffff)
                ExtractFST(fst.sub, filename, rom, extractPath, false);
        }

        private void ExtractFile(Fst_t fst, string parent, BinaryReader rom, string extractPath)
        {
            UInt16 fat;
            int cluster_span = (int) (fst.size / 0x4000) + 1;
            byte[] data = new byte[cluster_span * 0x4000];

            string filename =
                            Encoding.ASCII.GetString(fst.filename).
                            Replace("\0", string.Empty).
                            Replace(":", "-");
            if (parent != null)

                filename = Path.Combine(parent, filename);
            var filePath = Path.Combine(Properties.Settings.Default.ExtractPath, filename);
            try
            {
                BinaryWriter bw = new BinaryWriter(File.Open(filePath,
                                                                FileMode.Create,
                                                                FileAccess.Write,
                                                                FileShare.Read),
                                                            Encoding.ASCII);
                fat = fst.sub;
                for (int i = 0; fat < 0xFFF0; i++)
                {
                    Buffer.BlockCopy(GetCluster(fat, rom), 0, data, i * 0x4000, 0x4000);
                    fat = GetFAT(fat, rom);
                }

                bw.Write(data, 0, (int)fst.size);
                bw.Close();
            }
            catch
            {
                throw new InvalidOperationException($"Can't open file for writing:\n{filePath}" );
            }
        }

        /*
         * Crypto functions (encryption unused, but included for reference).
         * Key required length of 16 bytes.
         * IV can be from 1 to 16 byte(s) and will be padded with 0x00.
         */
        private byte[] AesDecrypt(byte[] key, byte[] iv, byte[] enc_data)
        {
            // zero out any remaining iv bytes
            byte[] iv16 = new byte[16];
            Buffer.BlockCopy(iv, 0, iv16, 0, iv.Length);

            RijndaelManaged aes = new RijndaelManaged
            {
                Padding = PaddingMode.None,
                Mode = CipherMode.CBC
            };

            ICryptoTransform decryptor = aes.CreateDecryptor(key, iv16);
            MemoryStream memoryStream = new MemoryStream(enc_data);
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
                                                      decryptor,
                                                      CryptoStreamMode.Read);

            byte[] dec_data = new byte[enc_data.Length];
            _ = cryptoStream.Read(dec_data, 0, dec_data.Length);

            memoryStream.Close();
            cryptoStream.Close();

            Application.DoEvents();
            return dec_data;
        }

        public static UInt16 Bswap(UInt16 value)
        {
            return (UInt16)((0x00FF & (value >> 8))
                             | (0xFF00 & (value << 8)));
        }

        public static UInt32 Bswap(UInt32 value)
        {
            UInt32 swapped = (0x000000FF) & (value >> 24)
                             | (0x0000FF00) & (value >> 8)
                             | (0x00FF0000) & (value << 8)
                             | (0xFF000000) & (value << 24);
            return swapped;
        }

        public static byte[] StrToByte(string hexString)
        {
            hexString = System.Text.RegularExpressions.Regex.Replace(hexString.ToUpper(), "[^0-9A-F]", string.Empty);
            byte[] b = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                b[i / 2] = byte.Parse(hexString.Substring(i, 2), System.Globalization.NumberStyles.AllowHexSpecifier);

            return b;
        }

        private string TxtPadLeft(string textString, int desiredLength)
        {
            while (textString.Length < desiredLength)
                textString = string.Concat(" ", textString);
            return textString;
        }

        private string TxtPadRight(string textString, int desiredLength)
        {
            while (textString.Length < desiredLength)
                textString = string.Concat(textString, " ");
            return textString;
        }
    }
}
