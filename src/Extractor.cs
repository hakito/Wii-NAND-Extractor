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
using System.Windows.Forms;

namespace NAND_Extractor
{
    public partial class Extractor : Form
    {
        Nand nand;

        public Extractor()
        {
            InitializeComponent();
            this.Load += NandExtractor_Load;
        }

        private void NandExtractor_Load(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(Properties.Settings.Default.NandPath))
                ViewFile();
        }

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
            StatusText(string.Format("Loading {0} for viewing...", Path.GetFileName(Properties.Settings.Default.NandPath)));

            info.Items["size"].Text = "0";
            info.Items["files"].Text = "0";
            fileView.Nodes.Clear();

            try
            {
                nand = new Nand(Properties.Settings.Default.NandPath);
                try
                {
                    nand.LoadKey();
                }
                catch (Exception) when (Properties.Settings.Default.nand_key?.Length == 32)
                {
                    nand.key = Nand.StrToByte(Properties.Settings.Default.nand_key);
                    Msg_Info(string.Format("No new key data found, using manually entered key\n{0}\n\n" +
                        "MAKE SURE THIS IS THE RIGHT KEY OR YOUR\nEXTRACTED FILES WILL NOT DECRYPT CORRECTLY!",
                        BitConverter.ToString(nand.key).Replace("-", string.Empty)));
                }

                var nandRoot = nand.FstRoot;
                var treeNode = fileView.Nodes.Add(nandRoot.Key.ToString("x4"), nandRoot.Description, nandRoot.Mode, nandRoot.Mode);
                treeNode.Tag = nandRoot;
                ViewFST(treeNode);

                fileView.Sort();
                fileView.Nodes[nandRoot.Key].Expand();

                StatusText(string.Empty);
            }
            catch (Exception e)
            {
                StatusText("Invalid or non-ECC NAND dump");
                fileView.Nodes.Clear();
                Msg_Error(e.Message);
                return;
            }
        }

        private void ViewFST(TreeNode treeNode)
        {
            var nandNode = (Nand.Node)treeNode.Tag;
            foreach(var child in nandNode.Children)
            {
                var childTreeNode = treeNode.Nodes.Add(child.Key.ToString("x4"), child.Description, child.Mode, child.Mode);
                childTreeNode.Tag = child;
                if (nandNode.Children.Any())
                    ViewFST(childTreeNode);
            }
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

        /*
         * Menu functions.
         */

        private void OpenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            FileOpen();
        }

        private void ExtractToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (!SetUpExtractPath())
                return;

            extractTime.Text = string.Empty;
            var stopwatch = Stopwatch.StartNew();

            StatusText("Extracting NAND...");

            nand.Extract(nand.FstRoot, Properties.Settings.Default.ExtractPath);

            StatusText(string.Empty);

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

            if (!SetUpExtractPath())
                return;

            var stopwatch = Stopwatch.StartNew();

            try
            {
                nand.Extract((Nand.Node)fileView.SelectedNode.Tag, Properties.Settings.Default.ExtractPath);
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
