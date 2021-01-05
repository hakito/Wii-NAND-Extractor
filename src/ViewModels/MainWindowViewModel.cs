using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using NAND_Extractor.Views;
using ReactiveUI;
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reactive;
using System.Threading.Tasks;

namespace NAND_Extractor.ViewModels
{
    public class MainWindowViewModel : ViewModelBase
    {
        public class TreeNode
        {
            public ReactiveCommand<Unit, Unit> ContextExtractCommand { get; }
            public Nand.Node NandNode { get; set; }
            public ObservableCollection<TreeNode> Children { get; } = new ObservableCollection<TreeNode>();
            public bool IsExpanded { get; set; }
            public TreeNode(Nand.Node nandNode, MainWindowViewModel mainWindowViewModel)
            {
                NandNode = nandNode;
                foreach (var child in nandNode.Children.OrderBy(n => n.Description))
                    Children.Add(new TreeNode(child, mainWindowViewModel));

                ContextExtractCommand = ReactiveCommand.CreateFromTask(Extract);
                async Task Extract()
                {
                    if (!await mainWindowViewModel.SetUpExtractPath())
                        return;

                    var stopwatch = Stopwatch.StartNew();
                    try
                    {
                        await Task.Run(() =>
                        {
                            mainWindowViewModel.nand.Extract(nandNode, Properties.Settings.Default.ExtractPath);
                        });
                    }
                    catch (Exception ex)
                    {
                        await mainWindowViewModel.Msg_Error(ex.Message);
                    }

                    stopwatch.Stop();
                }
            }
        }

        private Nand nand;
        public Control View { get; set; }
        public ObservableCollection<TreeNode> Nodes { get; } = new ObservableCollection<TreeNode>();
        private string size;
        public string Size
        {
            get => size;
            set => this.RaiseAndSetIfChanged(ref size, value);
        }
        private string files;
        public string Files
        {
            get => files;
            set => this.RaiseAndSetIfChanged(ref files, value);
        }

        private string status;
        public string Status
        {
            get => status;
            set => this.RaiseAndSetIfChanged(ref status, value);
        }

        private string extractTime;
        public string ExtractTime
        {
            get => extractTime;
            set => this.RaiseAndSetIfChanged(ref extractTime, value);
        }
        public ReactiveCommand<Unit, Unit> OpenCommand { get; }
        public ReactiveCommand<Unit, Unit> ExtractAllCommand { get; }
        public ReactiveCommand<Unit, Unit> EnterNandKeyCommand { get; }
        public ReactiveCommand<Unit, Unit> CloseCommand { get; }
        public ReactiveCommand<Unit, Unit> AboutCommand { get; }

        public MainWindowViewModel()
        {
            OpenCommand = ReactiveCommand.CreateFromTask(FileOpen);
            ExtractAllCommand = ReactiveCommand.CreateFromTask(ExtractAll);
            EnterNandKeyCommand = ReactiveCommand.CreateFromTask(EnterNandKey);
            AboutCommand = ReactiveCommand.CreateFromTask(AboutToolStripMenuItem_Click);
            CloseCommand = ReactiveCommand.Create(() => ((Window)View.GetVisualRoot()).Close());
            Status = "Nothing loaded";
        }

        private async Task FileOpen()
        {
            if (View?.GetVisualRoot() is not Window window)
                return;

            var fd = new OpenFileDialog();
            var binFilter = new FileDialogFilter() { Name = "Wii NAND dump (*.bin,*.img)" };
            binFilter.Extensions.AddRange(new[] { "bin", "img" } );
            var allFilter = new FileDialogFilter() { Name = "All files (*.*)" };
            allFilter.Extensions.Add("*");
            fd.Filters.Add(binFilter);
            fd.Filters.Add(allFilter);
            fd.Title = "Open Wii NAND dump file";

            if (!string.IsNullOrEmpty(Properties.Settings.Default.NandPath))
                fd.InitialFileName = Properties.Settings.Default.NandPath;

            var path = (await fd.ShowAsync(window)).FirstOrDefault();
            if (string.IsNullOrEmpty(path))
                return;

            Properties.Settings.Default.NandPath = path;
#if DEBUG
            Properties.Settings.Default.Save();
#endif

            await ViewFile();
        }

        public async Task ViewFile()
        {
            StatusText(string.Format("Loading {0} for viewing...", Path.GetFileName(Properties.Settings.Default.NandPath)));

            try
            {
                nand = await Task.Run(() => new Nand(Properties.Settings.Default.NandPath));
                Size = nand.Size.ToString();
                Files = nand.Files.ToString();
                try
                {
                    await Task.Run(nand.LoadKey);
                }
                catch (Exception) when (Properties.Settings.Default.nand_key?.Length == 32)
                {
                    nand.key = Nand.StrToByte(Properties.Settings.Default.nand_key);
                    await Msg_Info(string.Format("No new key data found, using manually entered key\n{0}\n\n" +
                        "MAKE SURE THIS IS THE RIGHT KEY OR YOUR\nEXTRACTED FILES WILL NOT DECRYPT CORRECTLY!",
                        BitConverter.ToString(nand.key).Replace("-", string.Empty)));
                }

                var treeRoot = new TreeNode(nand.FstRoot, this)
                {
                    IsExpanded = true
                };
                Nodes.Add(treeRoot);

                StatusText(string.Empty);
            }
            catch (Exception e)
            {
                StatusText("Invalid or non-ECC NAND dump");
                Size = "0";
                Files = "0";
                Nodes.Clear();
                await Msg_Error(e.Message);
            }
        }

        private async Task<bool> SetUpExtractPath()
        {
            if (string.IsNullOrEmpty(Properties.Settings.Default.ExtractPath))
            {
                var dialog = new OpenFolderDialog();
                var path = await dialog.ShowAsync((Window)View.GetVisualRoot());
                if (string.IsNullOrEmpty(path))
                    return false;

                Properties.Settings.Default.ExtractPath = path;
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
        public async Task Msg_Error(string message)
        {
            await Dispatcher.UIThread.InvokeAsync(async() =>
                await MessageBox.Show(View.GetVisualRoot() as Window, message, "Error!",
                        MessageBox.MessageBoxButtons.Ok, "error")
            );
        }

        public async Task Msg_Info(string message)
        {
            await Dispatcher.UIThread.InvokeAsync(async () =>
                await MessageBox.Show(View.GetVisualRoot() as Window, message, "Information!",
                        MessageBox.MessageBoxButtons.Ok, "info")
            );
        }

        public void StatusText(string message)
        {
            Status = message.Replace("\\", "/");
        }

        private async Task ExtractAll()
        {
            if (!await SetUpExtractPath())
                return;

            ExtractTime = string.Empty;
            var stopwatch = Stopwatch.StartNew();

            StatusText("Extracting NAND...");

            await Task.Run(() => nand.Extract(nand.FstRoot, Properties.Settings.Default.ExtractPath));

            StatusText(string.Empty);

            stopwatch.Stop();

            ExtractTime = stopwatch.Elapsed.ToString();
        }

        private async Task AboutToolStripMenuItem_Click()
        {
            await MessageBox.Show(View.GetVisualRoot() as Window, "Wii NAND Extractor\n" +
                                    "Version " + FileVersionInfo.GetVersionInfo(GetType().Assembly.Location).ProductVersion + "\n\n" +
                                    "Copyright 2009 Ben Wilson / parannoyed\n" +
                                    "http://sites.google.com/site/parannoyedwii/\n" +
                                    "Copyright 2020, 2021 Gerd Katzenbeisser", "About",
                                MessageBox.MessageBoxButtons.Ok, "info");
        }

        private async Task EnterNandKey()
        {
            var frm = new NandKey();
            await frm.ShowDialog((Window)View.GetVisualRoot());
        }
    }
}

