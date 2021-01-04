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

using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace NAND_Extractor
{
    public partial class NandExtractor : Form
    {
        public NandExtractor()
        {
            InitializeComponent();
            this.Load += NandExtractor_Load;
        }

        private void NandExtractor_Load(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(Properties.Settings.Default.NandPath))
                ViewFile();
        }


        /*
         * Class for fst entries.
         */
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

        /*
         * Globals.
         */
        public static byte[] key = new byte[16];
        public static byte[] iv = new byte[16];
        public static Int32 loc_super;
        public static Int32 loc_fat;
        public static Int32 loc_fst;
        private static DumpType type = DumpType.Unknown;


        /*
         * Core functions.
         */
        private void FileOpen()
        {
            FileDialog fd = new OpenFileDialog
            {
                Filter = "Wii NAND dump (*.bin,*.img)|*.bin;*.img|All files (*.*)|*.*",
                Title = "Open Wii NAND dump file"
            };
            if (!string.IsNullOrEmpty(Properties.Settings.Default.NandPath))
                fd.FileName = Properties.Settings.Default.NandPath;

            if (fd.ShowDialog(this) == DialogResult.Cancel)
                return;

            Properties.Settings.Default.NandPath = fd.FileName;
#if DEBUG
            Properties.Settings.Default.Save();
#endif

            ViewFile();
        }

        private void ViewFile()
        {
            string filename = Path.GetFileName(Properties.Settings.Default.NandPath);
            string details_desc = "   mode|attr   uid:gid   filesize (in bytes)";

            StatusText(string.Format("Loading {0} for viewing...", filename));

            filename = Path.ChangeExtension(filename, null);

            info.Items["size"].Text = "0";
            info.Items["files"].Text = "0";
            fileView.Nodes.Clear();
            fileView.Nodes.Add("0000", filename + details_desc, 2, 2);

            try
            {
                InitNand();
            }
            catch (Exception e)
            {
                Msg_Error(e.Message);
            }

            StatusText(string.Empty);
        }

        private void InitNand()
        {
            using var rom = new BinaryReader(File.Open(Properties.Settings.Default.NandPath,
                                        FileMode.Open,
                                        FileAccess.Read,
                                        FileShare.Read),
                                    Encoding.ASCII);


            type = GetDumpType(rom.BaseStream.Length);

            LoadKey(type, rom);

            try
            {
                loc_super = FindSuperblock(rom);
            }
            catch
            {
                StatusText("Invalid or non-ECC NAND dump");
                fileView.Nodes.Clear();
                throw new InvalidOperationException("Can't find superblock.\nAre you sure this is a Full (with ECC) or BootMii NAND dump?");
            }

            Int32[] n_fatlen = { 0x010000, 0x010800, 0x010800 };
            loc_fat = loc_super;
            loc_fst = loc_fat + 0x0C + n_fatlen[(int)type];

            ViewFST(0, 0, rom);

            fileView.Sort();
            fileView.Nodes["0000"].Expand();
        }

        private DumpType GetDumpType(Int64 FileSize) => FileSize switch
        {
            536870912 => DumpType.NoEcc,
            553648128 => DumpType.Ecc,
            553649152 => DumpType.OldBootMii,
            _ => DumpType.Unknown
        };

        private void LoadKey(DumpType type, BinaryReader rom)
        {
            var keyPath = Path.Combine(Path.GetDirectoryName(Properties.Settings.Default.NandPath), "keys.bin");

            try
            {
                switch (type)
                {
                    case DumpType.NoEcc:
                    case DumpType.Ecc:
                        key = ReadKeyfile(keyPath);
                        return;

                    case DumpType.OldBootMii:
                        rom.BaseStream.Seek(0x21000158, SeekOrigin.Begin);
                        var readBytes = rom.Read(key, 0, 16);
                        if (readBytes != 16)
                            throw new InvalidOperationException($"Tried to read 16 bytes as key but only got {readBytes}");
                        return;
                    default:
                        throw new NotImplementedException();
                };
            }
            catch (Exception) when (Properties.Settings.Default.nand_key?.Length == 32)
            {
                key = StrToByte(Properties.Settings.Default.nand_key);
                Msg_Info(string.Format("No new key data found, using manually entered key\n{0}\n\n" +
                    "MAKE SURE THIS IS THE RIGHT KEY OR YOUR\nEXTRACTED FILES WILL NOT DECRYPT CORRECTLY!",
                    BitConverter.ToString(key).Replace("-", string.Empty)));
            }
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
        private void ViewFST(UInt16 entry, UInt16 parent, BinaryReader rom)
        {
            Fst_t fst = GetFST(entry, rom);

            if (fst.sib != 0xffff)
                ViewFST(fst.sib, parent, rom);

            AddEntry(fst, entry, parent, rom);

            info.Items["size"].Text = (Convert.ToInt32(info.Items["size"].Text) + (int)fst.size).ToString();
            info.Items["files"].Text = (Convert.ToInt32(info.Items["files"].Text) + 1).ToString();
            Application.DoEvents();
        }

        private void AddEntry(Fst_t fst, UInt16 entry, UInt16 parent, BinaryReader rom)
        {
            string details;
            string[] modes = { "d|", "f|" };
            TreeNode[] node = fileView.Nodes.Find(parent.ToString("x4"), true);

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
                if (node.Count() > 0)
                    node[0].Nodes.Add(entry.ToString("x4"), details, fst.mode, fst.mode);
                else
                    fileView.Nodes.Add(entry.ToString("x4"), details, fst.mode, fst.mode);
            }

            if (fst.mode == 0 && fst.sub != 0xffff)
                ViewFST(fst.sub, entry, rom);
        }


        /*
         * Extraction functions.
         */
        private void ExtractNAND()
        {
            if (!SetUpExtractPath())
                return;

            StatusText("Extracting NAND...");

            using var rom = new BinaryReader(File.Open(Properties.Settings.Default.NandPath,
                                                    FileMode.Open,
                                                    FileAccess.Read,
                                                    FileShare.Read),
                                                Encoding.ASCII);

            ExtractFST(0, "", rom);

            StatusText(string.Empty);
        }

        private static bool SetUpExtractPath()
        {
            if (string.IsNullOrEmpty(Properties.Settings.Default.ExtractPath))
            {
                var dialog = new CommonOpenFileDialog
                {
                    IsFolderPicker = true
                };
                if (dialog.ShowDialog() != CommonFileDialogResult.Ok)
                    return false;

                Properties.Settings.Default.ExtractPath = dialog.FileName;
#if DEBUG
                Properties.Settings.Default.Save();
#endif
            }

            if (!Directory.Exists(Properties.Settings.Default.ExtractPath))
                Directory.CreateDirectory(Properties.Settings.Default.ExtractPath);

            return true;
        }

        private void ExtractFST(UInt16 entry, string parent, BinaryReader rom)
        {
            Fst_t fst = GetFST(entry, rom);

            if (fst.sib != 0xffff)
                ExtractFST(fst.sib, parent, rom);

            switch (fst.mode)
            {
                case 0:
                    ExtractDir(fst, parent, rom);
                    break;
                case 1:
                    ExtractFile(fst, parent, rom);
                    break;
                default:
                    throw new NotSupportedException(String.Format("Unsupported mode {0}.\n\t\t(FST entry #{1})",
                                                fst.mode,
                                                entry.ToString("x4")));
            }
        }

        private void ExtractSingleFST(UInt16 entry, string parent, BinaryReader rom)
        {
            if (!SetUpExtractPath())
                return;

            Fst_t fst = GetFST(entry, rom);

            switch (fst.mode)
            {
                case 0:
                    ExtractDir(fst, parent, rom);
                    break;
                case 1:
                    ExtractFile(fst, parent, rom);
                    break;
                default:
                    Msg_Error(String.Format("Ignoring unsupported mode {0}.\n\t\t(FST entry #{1})",
                                                fst.mode,
                                                entry.ToString("x4")));
                    break;
            }
        }

        private void ExtractDir(Fst_t fst, string parent, BinaryReader rom)
        {
            string filename = ASCIIEncoding.ASCII.GetString(fst.filename).Replace("\0", string.Empty);

            StatusText(string.Format("Extracting:  {0}", filename));

            if (filename != "/")
            {
                if (parent != "/" && parent != "")
                    filename = Path.Combine(parent, filename);

                Directory.CreateDirectory(Path.Combine(Properties.Settings.Default.ExtractPath, filename));
            }

            if (fst.sub != 0xffff)
                ExtractFST(fst.sub, filename, rom);
        }

        private void ExtractFile(Fst_t fst, string parent, BinaryReader rom)
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
                    StatusText(string.Format("Extracting:  {0} (cluster {1})", filename, fat));
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

        /*
         * Helper/misc functions.
         */
        public static void Msg_Error(string message)
        {
            MessageBox.Show(Form.ActiveForm, message, "Error!",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
        }

        public static void Msg_Info(string message)
        {
            MessageBox.Show(Form.ActiveForm, message, "Information!",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Information);
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

        public void StatusText(string message)
        {
            status.Text = message.Replace("\\", "/");
            if (message == string.Empty)
            {
                contextExtract.Enabled = true;
                extractAllFileMenu.Enabled = true;
            }
            else
            {
                contextExtract.Enabled = false;
                extractAllFileMenu.Enabled = false;
            }
            Application.DoEvents();
        }

        public void NandExtractor_Resize(object sender, System.EventArgs e)
        {
            this.fileView.Width = Size.Width - 28;
            this.fileView.Height = Size.Height - 102; // 80 w/out new info bar
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


        /*
         * Menu functions.
         */

        private void OpenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            FileOpen();
        }

        private void ExtractToolStripMenuItem_Click(object sender, EventArgs e)
        {
            extractTime.Text = string.Empty;
            var stopwatch = Stopwatch.StartNew();

            ExtractNAND();

            stopwatch.Stop();

            extractTime.Text = stopwatch.Elapsed.ToString();
        }

        private void AboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            MessageBox.Show(this,   "Wii NAND Extractor\n" +
                                    "Version " + FileVersionInfo.GetVersionInfo(GetType().Assembly.Location).ProductVersion + "\n\n" +
                                    "Copyright 2009 Ben Wilson / parannoyed\n" +
                                    "http://sites.google.com/site/parannoyedwii/" +
                                    "Copyright 2020, 2021 Gerd Katzenbeisser", "About",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Question);
        }

        private void ExitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void ContextExtract_Click(object sender, EventArgs e)
        {
            if (fileView.SelectedNode == null)
            {
                Msg_Error("Try choosing a file/directory.");
                return;
            }

            var stopwatch = Stopwatch.StartNew();

            using var rom = new BinaryReader(File.Open(Properties.Settings.Default.NandPath,
                                                FileMode.Open,
                                                FileAccess.Read,
                                                FileShare.Read),
                                            Encoding.ASCII);

            if (rom.BaseStream.Length <= 0)
            {
                Msg_Error("Empty stream");
                return;
            }

            try
            {
                ExtractSingleFST(Convert.ToUInt16(fileView.SelectedNode.Name, 16), "", rom);
            }
            catch(Exception ex)
            {
                Msg_Error(ex.Message);
            }

            stopwatch.Stop();

            StatusText(string.Empty);
            extractTime.Text = stopwatch.Elapsed.ToString();
        }

        private void FileView_MouseDown(object sender, MouseEventArgs e)
        {
            if(e.Button != MouseButtons.Right)
                return;
            fileView.SelectedNode = fileView.GetNodeAt(e.X,e.Y);
        }

        private void EnterNandKeyMenuItem_Click(object sender, EventArgs e)
        {
            Form frm = new NandKey();
            frm.ShowDialog(this);
        }
    }
}
