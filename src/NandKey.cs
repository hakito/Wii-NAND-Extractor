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
using System.Windows.Forms;

namespace NAND_Extractor
{
    public partial class NandKey : Form
    {
        public NandKey()
        {
            InitializeComponent();
        }

        private void TextBox_TextChanged(object sender, EventArgs e)
        {
            int i = textBox.SelectionStart;
            textBox.Text = textBox.Text.Replace(" ", string.Empty);
            textBox.Text = textBox.Text.Replace("-", string.Empty);

            if (i > 0)
                textBox.SelectionStart = i;
        }

        private void ButtonOk_Click(object sender, EventArgs e)
        {
            if (textBox.Text.Length == 32)
            {
                Properties.Settings.Default.nand_key = textBox.Text;
                Properties.Settings.Default.Save();
                Close();
            }
            else
                Extractor.Msg_Error("Your NAND Key is the wrong length.  It should be 32 characters long.  Please check your key and try again.");
        }

        private void ButtonCancel_Click(object sender, EventArgs e)
        {
            Close();
        }
    }
}
