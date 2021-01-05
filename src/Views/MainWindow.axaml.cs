using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using NAND_Extractor.ViewModels;
using System;

namespace NAND_Extractor.Views
{
    public class MainWindow : Window
    {
        public MainWindow()
        {
            this.Opened += MainWindow_Initialized;
            InitializeComponent();            
#if DEBUG
            this.AttachDevTools();
#endif
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

        public MainWindowViewModel _model;

        protected override void OnDataContextChanged(EventArgs e)
        {
            if (_model != null)
                _model.View = null;
            _model = DataContext as MainWindowViewModel;
            if (_model != null)
                _model.View = this;

            base.OnDataContextChanged(e);
        }
        private async void MainWindow_Initialized(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(Properties.Settings.Default.NandPath))
                await _model.ViewFile();
        }
    }
}
