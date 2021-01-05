using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;

namespace NAND_Extractor.Views
{
    public class NandKey : Window
    {
        public string Key { get; set; }

        public NandKey()
        {
            this.InitializeComponent();
            this.DataContext = this;
#if DEBUG
            this.AttachDevTools();
#endif
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0051:Remove unused private members", Justification = "<Pending>")]
        private async void Ok_Click()
        {
            if (Key.Length == 32)
            {
                Properties.Settings.Default.nand_key = Key;
                Properties.Settings.Default.Save();
                this.Close();
            }
            else
                await Dispatcher.UIThread.InvokeAsync(async () =>
                await MessageBox.Show(this, "Your NAND Key is the wrong length.  It should be 32 characters long.  Please check your key and try again.", "Error!",
                        MessageBox.MessageBoxButtons.Ok, "error"));
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0051:Remove unused private members", Justification = "<Pending>")]
        private void Cancel_Click() => Close();
    }
}
