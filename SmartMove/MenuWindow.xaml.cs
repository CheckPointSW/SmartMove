using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace SmartMove
{
    /// <summary>
    /// Interaction logic for MenuWindow.xaml
    /// </summary>
    public partial class MenuWindow : Window
    {
        public MenuWindow()
        {
            InitializeComponent();
            ShowDisclaimer();
        }

        #region Events

        private void CloseButton_OnClick(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void MinimizeButton_OnClick(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void HelpButton_OnClick(object sender, RoutedEventArgs e)
        {
        }

        private void HeaderPanel_OnMouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left && e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }

        #endregion

        private void ShowDisclaimer()
        {
            // Display the disclaimer document only once per tool version.
            string version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            if (!File.Exists(version))
            {
                var disclaimerWindow = new DisclaimerWindow();
                var res = disclaimerWindow.ShowDialog();

                if (res.HasValue && res.Value)
                {
                    // Create a flag file.
                    var fsFlag = new FileStream(version, FileMode.CreateNew, FileAccess.Write);
                    fsFlag.Close();
                }
                else
                {
                    Close();
                }
            }
        }

        private void ButtonSmartMove_Click(object sender, RoutedEventArgs e)
        {
            var smartMoveWindow = new MainWindow();
            smartMoveWindow.Owner = this;
            smartMoveWindow.ShowDialog();
        }
        private void ButtonSmartAnalyze_Click(object sender, RoutedEventArgs e)
        {
            var smartanalyzeWindow = new AnalyzeWindow();
            smartanalyzeWindow.Owner = this;
            smartanalyzeWindow.ShowDialog();

        }
    }
}
