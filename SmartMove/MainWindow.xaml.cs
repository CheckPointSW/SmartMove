/********************************************************************
Copyright (c) 2017, Check Point Software Technologies Ltd.
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
********************************************************************/

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms;
using System.Windows.Input;
using CiscoMigration;
using MigrationBase;

namespace SmartMove
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        #region Constants

        public const string DefaultSKText = "SmartMove release notes and latest updates: ";
        public const string DefaultSKLinkText = "sk115416";
        public const string DefaultSKLinkAddress = @"https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk115416";
        private const string DefaultPSText = "For the best results, please contact ";
        private const string DefaultPSLinkText = "Check Point's Professional Services or your local partner";
        private const string DefaultPSLinkAddress = @"https://www.checkpoint.com/support-services/design-deploy-operate-optimize";
        private const string SourceFolder = @"C:\";
        private const string TargetFolder = @"C:\";

        #endregion

        #region Private Members

        private readonly SupportedVendors _supportedVendors = new SupportedVendors();
        
        #endregion

        #region Construction

        public MainWindow()
        {
            InitializeComponent();
            ShowDisclaimer();
            LoadContactInfo();

            ConfigFilePath.Text = SourceFolder;
            TargetFolderPath.Text = TargetFolder;

            _supportedVendors.SelectedVendor = Vendor.CiscoASA;
            ConfigurationFileLabel = SupportedVendors.CiscoConfigurationFileLabel;
        }

        #endregion

        #region Properties

        #region ConfigurationFileLabel

        public string ConfigurationFileLabel
        {
            get { return (string)GetValue(ConfigurationFileLabelProperty); }
            set { SetValue(ConfigurationFileLabelProperty, value); }
        }

        public static readonly DependencyProperty ConfigurationFileLabelProperty =
            DependencyProperty.Register("ConfigurationFileLabel", typeof(string), typeof(MainWindow), new PropertyMetadata(null));

        #endregion

        #region ConvertNATConfiguration

        public bool ConvertNATConfiguration
        {
            get { return (bool)GetValue(ConvertNATConfigurationProperty); }
            set { SetValue(ConvertNATConfigurationProperty, value); }
        }

        public static readonly DependencyProperty ConvertNATConfigurationProperty =
            DependencyProperty.Register("ConvertNATConfiguration", typeof(bool), typeof(MainWindow), new PropertyMetadata(true));

        #endregion

        #region ConvertedPolicyRulesCount

        public string ConvertedPolicyRulesCount
        {
            get { return (string)GetValue(ConvertedPolicyRulesCountProperty); }
            set { SetValue(ConvertedPolicyRulesCountProperty, value); }
        }

        public static readonly DependencyProperty ConvertedPolicyRulesCountProperty =
            DependencyProperty.Register("ConvertedPolicyRulesCount", typeof(string), typeof(MainWindow), new PropertyMetadata(null));
        
        #endregion

        #region ConvertedOptimizedPolicyRulesCount

        public string ConvertedOptimizedPolicyRulesCount
        {
            get { return (string)GetValue(ConvertedOptimizedPolicyRulesCountProperty); }
            set { SetValue(ConvertedOptimizedPolicyRulesCountProperty, value); }
        }

        public static readonly DependencyProperty ConvertedOptimizedPolicyRulesCountProperty =
            DependencyProperty.Register("ConvertedOptimizedPolicyRulesCount", typeof(string), typeof(MainWindow), new PropertyMetadata(null));
        
        #endregion

        #region ConvertedNATPolicyRulesCount

        public string ConvertedNATPolicyRulesCount
        {
            get { return (string)GetValue(ConvertedNATPolicyRulesCountProperty); }
            set { SetValue(ConvertedNATPolicyRulesCountProperty, value); }
        }

        public static readonly DependencyProperty ConvertedNATPolicyRulesCountProperty =
            DependencyProperty.Register("ConvertedNATPolicyRulesCount", typeof(string), typeof(MainWindow), new PropertyMetadata(null));

        #endregion

        #region ConversionIssuesCount

        public string ConversionIssuesCount
        {
            get { return (string)GetValue(ConversionIssuesCountProperty); }
            set { SetValue(ConversionIssuesCountProperty, value); }
        }

        public static readonly DependencyProperty ConversionIssuesCountProperty =
            DependencyProperty.Register("ConversionIssuesCount", typeof(string), typeof(MainWindow), new PropertyMetadata(null));

        #endregion

        #region ConfigurationFileLinesCount

        public string ConfigurationFileLinesCount
        {
            get { return (string)GetValue(ConfigurationFileLinesCountProperty); }
            set { SetValue(ConfigurationFileLinesCountProperty, value); }
        }

        public static readonly DependencyProperty ConfigurationFileLinesCountProperty =
            DependencyProperty.Register("ConfigurationFileLinesCount", typeof(string), typeof(MainWindow), new PropertyMetadata(null));

        #endregion

        #region CLI

        public static string SKText { get; private set; }
        public static string SKLinkText { get; private set; }
        public static object SKLinkAddress { get; private set; }
        
        #endregion

        #endregion

        #region Event Handlers

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
            var aboutWindow = new AboutWindow(_supportedVendors.SelectedVendor);
            aboutWindow.ShowDialog();
        }

        private void HeaderPanel_OnMouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left && e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }

        private void BrowseConfigFile_OnClick(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog();

            try
            {
                openFileDialog.InitialDirectory = Path.GetDirectoryName(ConfigFilePath.Text);
            }
            catch (Exception ex)
            {
                openFileDialog.InitialDirectory = SourceFolder;
            }

            string filter = "";

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    filter = "conf files (*.conf, *.txt)|*.conf; *.txt|All files (*.*)|*.*";
                    break;
            }

            openFileDialog.Filter = filter;
            openFileDialog.FilterIndex = 1;
            openFileDialog.RestoreDirectory = true;

            if (openFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                try
                {
                    ConfigFilePath.Text = openFileDialog.FileName;
                    TargetFolderPath.Text = Path.GetDirectoryName(ConfigFilePath.Text);
                    OutputPanel.Visibility = Visibility.Collapsed;
                }
                catch (Exception ex)
                {
                    ShowMessage("Could not read file from disk.\nOriginal error: " + ex.Message, MessageTypes.Error);
                }
            }
        }

        private void BrowseTargetFolder_OnClick(object sender, RoutedEventArgs e)
        {
            var openFolderDialog = new FolderBrowserDialog();

            try
            {
                openFolderDialog.Description = "Select the target folder for conversion output:";
                openFolderDialog.SelectedPath = Path.GetDirectoryName(TargetFolderPath.Text);
            }
            catch (Exception ex)
            {
                openFolderDialog.SelectedPath = TargetFolder;
            }

            if (openFolderDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                try
                {
                    TargetFolderPath.Text = openFolderDialog.SelectedPath;
                }
                catch (Exception ex)
                {
                    ShowMessage("Could not read file from disk.\nOriginal error: " + ex.Message, MessageTypes.Error);
                }
            }
        }

        private async void Go_OnClick(object sender, RoutedEventArgs e)
        {
            string fileName = Path.GetFileNameWithoutExtension(ConfigFilePath.Text);

            if (string.IsNullOrEmpty(ConfigFilePath.Text) || string.IsNullOrEmpty(fileName))
            {
                ShowMessage("Configuration file is not selected.", MessageTypes.Error);
                return;
            }

            if (!File.Exists(ConfigFilePath.Text))
            {
                ShowMessage("Cannot find configuration file.", MessageTypes.Error);
                return;
            }

            if (fileName.Length > 20)
            {
                ShowMessage("Configuration file name is restricted to 20 characters at most.", MessageTypes.Error);
                return;
            }

            if (!Directory.Exists(TargetFolderPath.Text))
            {
                ShowMessage("Cannot find target folder for conversion output.", MessageTypes.Error);
                return;
            }

            Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
            EnableDisableControls(false);
            ProgressPanel.Visibility = Visibility.Visible;
            ResultsPanel.Visibility = Visibility.Collapsed;
            OutputPanel.Visibility = Visibility.Visible;

            UpdateProgress(10, "Parsing configuration file ...");

            VendorParser vendorParser;

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    vendorParser = new CiscoParser();
                    break;
                default:
                    throw new InvalidDataException("Unexpected!!!");
            }

            try
            {
                string ciscoFile = ConfigFilePath.Text;
                await Task.Run(() => vendorParser.Parse(ciscoFile));
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                EnableDisableControls(true);
                OutputPanel.Visibility = Visibility.Collapsed;
                ShowMessage(string.Format("Could not parse configuration file.\n\nMessage: {0}\nModule:\t{1}\nClass:\t{2}\nMethod:\t{3}", ex.Message, ex.Source, ex.TargetSite.ReflectedType.Name, ex.TargetSite.Name), MessageTypes.Error);
                return;
            }

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        ShowMessage("Unspecified ASA version.\nCannot find ASA version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                    }
                    else if (vendorParser.MajorVersion < 8 || (vendorParser.MajorVersion == 8 && vendorParser.MinorVersion < 3))
                    {
                        ShowMessage("Unsupported ASA version (" + vendorParser.Version + ").\nThis tool supports ASA 8.3 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                    }
                    break;
            }

            string vendorFileName = Path.GetFileNameWithoutExtension(ConfigFilePath.Text);
            string toolVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            string targetFolder = TargetFolderPath.Text + "\\";
            bool convertNat = ConvertNATConfiguration;

            vendorParser.Export(targetFolder + vendorFileName + ".json");

            VendorConverter vendorConverter;

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    vendorConverter = new CiscoConverter();
                    break;
                default:
                    throw new InvalidDataException("Unexpected!!!");
            }

            vendorConverter.Initialize(vendorParser, ConfigFilePath.Text, toolVersion, targetFolder, DomainName.Text);
            vendorConverter.ConversionProgress += OnConversionProgress;

            try
            {
                await Task.Run(() => vendorConverter.Convert(convertNat));
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                EnableDisableControls(true);
                OutputPanel.Visibility = Visibility.Collapsed;
                ShowMessage(string.Format("Could not convert configuration file.\n\nMessage: {0}\nModule:\t{1}\nClass:\t{2}\nMethod:\t{3}", ex.Message, ex.Source, ex.TargetSite.ReflectedType.Name, ex.TargetSite.Name), MessageTypes.Error);
                return;
            }

            UpdateProgress(90, "Exporting Check Point configuration ...");
            vendorConverter.ExportConfigurationAsHtml();
            vendorConverter.ExportPolicyPackagesAsHtml();
            if (ConvertNATConfiguration)
            {
                vendorConverter.ExportNatLayerAsHtml();
            }
            UpdateProgress(100, "");

            vendorConverter.ConversionProgress -= OnConversionProgress;

            Mouse.OverrideCursor = null;
            EnableDisableControls(true);
            ProgressPanel.Visibility = Visibility.Collapsed;
            ResultsPanel.Visibility = Visibility.Visible;

            ShowResults(vendorConverter, vendorParser.ParsedLines);
        }

        private void Link_OnClick(object sender, MouseButtonEventArgs e)
        {
            var link = (TextBlock)sender;
            if (link != null)
            {
                var psi = new ProcessStartInfo(link.Tag.ToString()) { UseShellExecute = true };
                Process.Start(psi);
            }
        }

        private void OnConversionProgress(int progress, string title)
        {
            Dispatcher.Invoke(() => UpdateProgress(progress, title));
        }

        #endregion

        #region Methods

        private void UpdateProgress(int value, string title)
        {
            Thread.Sleep(100);   // MUST, because we are on the UI thread!!!

            ProgressText.Text = title;
            ProgressIndicator.Value = value;
        }

        private void EnableDisableControls(bool enable)
        {
            ConfigFilePath.IsEnabled = enable;
            BrowseConfigFile.IsEnabled = enable;
            TargetFolderPath.IsEnabled = enable;
            BrowseTargetFolder.IsEnabled = enable;
            DomainName.IsEnabled = enable;
            ConvertNAT.IsEnabled = enable;
            Go.IsEnabled = enable;
        }

        private void ShowResults(VendorConverter vendorConverter, int convertedLinesCount)
        {
            ConversionIssuesPanel.Visibility = (vendorConverter.ConversionIncidentCategoriesCount > 0) ? Visibility.Visible : Visibility.Collapsed;
            ConvertedNatPolicyPanel.Visibility = ConvertNATConfiguration ? Visibility.Visible : Visibility.Collapsed;

            ConfigurationFileLinesCount = string.Format(" ({0} lines)", convertedLinesCount);
            ConvertedPolicyRulesCount = string.Format(" ({0} rules)", vendorConverter.RulesInConvertedPackage());
            ConvertedOptimizedPolicyRulesCount = string.Format(" ({0} rules)", vendorConverter.RulesInConvertedOptimizedPackage());
            ConvertedNATPolicyRulesCount = string.Format(" ({0} rules)", vendorConverter.RulesInNatLayer());
            ConversionIssuesCount = string.Format("Found {0} conversion issues in {1} configuration lines", vendorConverter.ConversionIncidentCategoriesCount, vendorConverter.ConversionIncidentsCommandsCount);

            OriginalFileLink.Tag = vendorConverter.VendorHtmlFile;
            ConvertedPolicyLink.Tag = vendorConverter.PolicyHtmlFile;
            ConvertedOptimizedPolicyLink.Tag = vendorConverter.PolicyOptimizedHtmlFile;
            ConvertedNatPolicy.Tag = vendorConverter.NatHtmlFile;
            ObjectsScript.Tag = vendorConverter.ObjectsScriptFile;
            RulebaseScript.Tag = vendorConverter.PolicyScriptFile;
            RulebaseOptimizedScript.Tag = vendorConverter.PolicyOptimizedScriptFile;
        }

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

        private void LoadContactInfo()
        {
            try
            {
                string[] skLines = File.ReadAllLines("sk.txt");
                SKTextDisplay.Text = skLines[0];
                SKLinkDisplay.Text = skLines[1];
                SKLinkDisplay.Tag = skLines[2];
            }
            catch (Exception ex)
            {
                SKTextDisplay.Text = DefaultSKText;
                SKLinkDisplay.Text = DefaultSKLinkText;
                SKLinkDisplay.Tag = DefaultSKLinkAddress;
            }

            SKText = SKTextDisplay.Text;
            SKLinkText = SKLinkDisplay.Text;
            SKLinkAddress = SKLinkDisplay.Tag;

            try
            {
                string[] contactLines = File.ReadAllLines("contact.txt");
                PSTextDisplay.Text = contactLines[0];
                PSLinkDisplay.Text = contactLines[1];
                PSLinkDisplay.Tag = contactLines[2];
            }
            catch (Exception ex)
            {
                PSTextDisplay.Text = DefaultPSText;
                PSLinkDisplay.Text = DefaultPSLinkText;
                PSLinkDisplay.Tag = DefaultPSLinkAddress;
            }
        }

        public static void ShowMessage(string message, MessageTypes messageType)
        {
            var messageWindow = new MessageWindow
            {
                Message = message, MessageType = messageType
            };

            messageWindow.ShowDialog();
        }

        #endregion
    }
}
