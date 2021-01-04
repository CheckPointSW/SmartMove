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
using JuniperMigration;
using MigrationBase;
using NetScreenMigration;
using FortiGateMigration;
using PaloAltoMigration;
using PanoramaPaloAltoMigration;

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
            _supportedVendors.SelectedVendor = Vendor.CiscoASA;   // this is the default

            InitializeComponent();
            ShowDisclaimer();
            LoadContactInfo();
            HandleCommandLineArgs();
        }

        #endregion

        #region Properties

        #region SelectedVendor

        public Vendor SelectedVendor
        {
            get { return _supportedVendors.SelectedVendor; }
            set { _supportedVendors.SelectedVendor = value; }
        }
        
        #endregion

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

        #region SkipUnusedObjectsConversion

        public bool SkipUnusedObjectsConversion
        {
            get { return (bool)GetValue(SkipUnusedObjectsConversionProperty); }
            set { SetValue(SkipUnusedObjectsConversionProperty, value); }
        }

        public static readonly DependencyProperty SkipUnusedObjectsConversionProperty =
            DependencyProperty.Register("SkipUnusedObjectsConversion", typeof(bool), typeof(MainWindow), new PropertyMetadata(false));

        #endregion

        #region ConvertUserConfiguration

        public bool ConvertUserConfiguration
        {
            get { return (bool)GetValue(ConvertUserConfigurationProperty); }
            set { SetValue(ConvertUserConfigurationProperty, value); }
        }

        public static readonly DependencyProperty ConvertUserConfigurationProperty =
            DependencyProperty.Register("ConvertUserConfiguration", typeof(bool), typeof(MainWindow), new PropertyMetadata(false));

        #endregion

        #region ConvertingWarningsCount

        public string ConvertingWarningsCount
        {
            get { return (string)GetValue(ConvertingWarningsCountProperty); }
            set { SetValue(ConvertingWarningsCountProperty, value); }
        }

        public static readonly DependencyProperty ConvertingWarningsCountProperty =
            DependencyProperty.Register("ConvertingWarningsCount", typeof(string), typeof(MainWindow), new PropertyMetadata(null));

        #endregion

        #region ConvertingErrorsCount

        public string ConvertingErrorsCount
        {
            get { return (string)GetValue(ConvertingErrorsCountProperty); }
            set { SetValue(ConvertingErrorsCountProperty, value); }
        }

        public static readonly DependencyProperty ConvertingErrorsCountProperty =
            DependencyProperty.Register("ConvertingErrorsCount", typeof(string), typeof(MainWindow), new PropertyMetadata(null));

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

        private void VendorSelector_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            DomainNameTB.Visibility = Visibility.Visible;
            DomainName.Visibility = Visibility.Visible;

            ConvertUserConf.Visibility = Visibility.Collapsed;
            LDAPAccountUnitTB.Visibility = Visibility.Collapsed;
            LDAPAccountUnitBlock.Visibility = Visibility.Collapsed;
            SkipUnusedObjects.Visibility = Visibility.Collapsed;
            ConvertUserConfiguration = false;

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    ConfigurationFileLabel = SupportedVendors.CiscoConfigurationFileLabel;
                    break;
                case Vendor.JuniperJunosOS:
                    ConfigurationFileLabel = SupportedVendors.JuniperConfigurationFileLabel;
                    break;
                case Vendor.JuniperScreenOS:
                    ConfigurationFileLabel = SupportedVendors.NetScreenConfigurationFileLabel;
                    break;
                case Vendor.FortiGate:
                    ConfigurationFileLabel = SupportedVendors.FortiGateConfigurationFileLabel;
                    DomainNameTB.Visibility = Visibility.Collapsed;
                    DomainName.Visibility = Visibility.Collapsed;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    ConvertUserConf.Visibility = Visibility.Visible;
                    break;
                case Vendor.PaloAlto:
                    ConfigurationFileLabel = SupportedVendors.PaloAltoConfigurationFileLabel;
                    DomainNameTB.Visibility = Visibility.Collapsed;
                    DomainName.Visibility = Visibility.Collapsed;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    ConvertUserConf.Visibility = Visibility.Visible;
                    break;
                case Vendor.PaloAltoPanorama:
                    ConfigurationFileLabel = SupportedVendors.PaloAltoPanoramaConfigurationFileLabel;
                    DomainNameTB.Visibility = Visibility.Collapsed;
                    DomainName.Visibility = Visibility.Collapsed;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    ConvertUserConf.Visibility = Visibility.Visible;
                    break;
            }

            ConfigFilePath.Text = SourceFolder;
            TargetFolderPath.Text = TargetFolder;
            OutputPanel.Visibility = Visibility.Collapsed;
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
                case Vendor.JuniperJunosOS:
                    filter = "xml files (*.xml)|*.xml";
                    break;
                case Vendor.JuniperScreenOS:
                    filter = "conf files (*.txt)|*.txt|All files (*.*)|*.*";
                    break;
                case Vendor.FortiGate:
                    filter = "conf files (*.conf)|*.conf";
                    break;
                case Vendor.PaloAlto:
                    filter = "xml files (*.xml)|*.xml|All files (*.*)|*.*";
                    break;
                case Vendor.PaloAltoPanorama:
                    filter = "Gzipped tar files (*.tgz)|*.tgz";
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

            if (ConvertUserConfiguration)
            {
                if (LDAPAccountUnit.Text.Trim().Equals("") || LDAPAccountUnit.Text.Trim().Contains(" "))
                {
                    ShowMessage("LDAP Account Unit field cannot be empty or containt space(s).", MessageTypes.Error);
                    return;
                }
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
                case Vendor.JuniperJunosOS:
                    vendorParser = new JuniperParser();
                    break;
                case Vendor.JuniperScreenOS:
                    vendorParser = new ScreenOSParser();
                    break;
                case Vendor.FortiGate:
                    vendorParser = new FortiGateParser();
                    break;
                case Vendor.PaloAlto:
                    vendorParser = new PaloAltoParser();
                    break;
                case Vendor.PaloAltoPanorama:
                    vendorParser = new PanoramaParser();
                    break;
                default:
                    throw new InvalidDataException("Unexpected!!!");
            }
			
            string vendorFileName = Path.GetFileNameWithoutExtension(ConfigFilePath.Text);
            string toolVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            string targetFolder = TargetFolderPath.Text + "\\";
            bool convertNat = ConvertNATConfiguration;
            string ldapAccountUnit = LDAPAccountUnit.Text.Trim();

            try
            {
                string ciscoFile = ConfigFilePath.Text;
				switch (_supportedVendors.SelectedVendor)
                {
                    case Vendor.PaloAltoPanorama:
                        PanoramaParser panParser = (PanoramaParser)vendorParser;                        
                        await Task.Run(() => panParser.ParseWithTargetFolder(ciscoFile,targetFolder));
                        break;
                    default:
                        await Task.Run(() => vendorParser.Parse(ciscoFile));
                        break;
                }

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

                case Vendor.JuniperJunosOS:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        ShowMessage("Unspecified SRX version.\nCannot find SRX version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                    }
                    else if (vendorParser.MajorVersion < 12 || (vendorParser.MajorVersion == 12 && vendorParser.MinorVersion < 1))
                    {
                        ShowMessage("Unsupported SRX version (" + vendorParser.Version + ").\nThis tool supports SRX 12.1 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                    }
                    break;

                case Vendor.JuniperScreenOS:
                    break;

                case Vendor.FortiGate:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        ShowMessage("Unspecified FortiGate version.\nCannot find FortiGate version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                    }
                    else if(vendorParser.MajorVersion < 5)
                    {
                        ShowMessage("Unsupported FortiGate version (" + vendorParser.Version + ").\nThis tool supports FortiGate 5.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                    }
                    break;
                case Vendor.PaloAlto:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        ShowMessage("Unspecified PaloAlto version.\nCannot find PaloAlto PAN-OS version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        ShowMessage("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto PAN-OS 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                    }
                    break;
                case Vendor.PaloAltoPanorama:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        ShowMessage("Unspecified PaloAlto version.\nCannot find PaloAlto Panorama version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        ShowMessage("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto Panorama 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;
            }

            vendorParser.Export(targetFolder + vendorFileName + ".json");

            VendorConverter vendorConverter;

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    vendorConverter = new CiscoConverter();
                    break;
                case Vendor.JuniperJunosOS:
                    vendorConverter = new JuniperConverter();
                    break;
                case Vendor.JuniperScreenOS:
                    vendorConverter = new ScreenOSConverter();
                    break;
                case Vendor.FortiGate:
                    FortiGateConverter fgConverter = new FortiGateConverter();
                    fgConverter.OptimizeConf = SkipUnusedObjectsConversion;
                    fgConverter.ConvertUserConf = ConvertUserConfiguration;
                    fgConverter.LDAPAccoutUnit = ldapAccountUnit.Trim();
                    vendorConverter = fgConverter;
                    break;
                case Vendor.PaloAlto:
                    PaloAltoConverter paConverter = new PaloAltoConverter();
                    paConverter.OptimizeConf = SkipUnusedObjectsConversion;
                    paConverter.ConvertUserConf = ConvertUserConfiguration;
                    paConverter.LDAPAccoutUnit = ldapAccountUnit.Trim();
                    vendorConverter = paConverter;
                    break;
                case Vendor.PaloAltoPanorama:
                    PanoramaConverter panoramaConverter = new PanoramaConverter();                    
                    panoramaConverter.OptimizeConf = SkipUnusedObjectsConversion;
                    panoramaConverter.ConvertUserConf = ConvertUserConfiguration;
                    panoramaConverter.LDAPAccoutUnit = ldapAccountUnit.Trim();
                    vendorConverter = panoramaConverter;
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
		ConvertedNatPolicyLink.MouseUp -= Link_OnClick;
                vendorConverter.ExportNatLayerAsHtml();

                //check if the user asked for NAT policy and no rules found.
                if (vendorConverter.RulesInNatLayer() == 0 ) // anly if 0 then we do not show NAT report.
                {
                    ConvertedNatPolicyLink.Style = (Style)ConvertedNatPolicyLink.FindResource("NormalTextBloclStyle");
                }
                else // otherwise it is single NAT report or Catalog for NAT reports (value = -1)
                {
                    ConvertedNatPolicyLink.Style = (Style)ConvertedNatPolicyLink.FindResource("HyperLinkStyle");
                    ConvertedNatPolicyLink.MouseUp += Link_OnClick;
                }
            }
            UpdateProgress(100, "");

            vendorConverter.ConversionProgress -= OnConversionProgress;

            Mouse.OverrideCursor = null;
            EnableDisableControls(true);
            ProgressPanel.Visibility = Visibility.Collapsed;
            ResultsPanel.Visibility = Visibility.Visible;

            ShowResults(vendorConverter, vendorParser.ParsedLines);
        }

        private void ConvertUserConf_Checked(object sender, RoutedEventArgs e)
        {
            if (ConvertUserConfiguration)
            {
                LDAPAccountUnitTB.Visibility = Visibility.Visible;
                LDAPAccountUnitBlock.Visibility = Visibility.Visible;
            }
            else
            {
                LDAPAccountUnitTB.Visibility = Visibility.Collapsed;
                LDAPAccountUnitBlock.Visibility = Visibility.Collapsed;
            }
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
            VendorSelector.IsEnabled = enable;
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
            ConvertingWarningsCount = "";
            ConvertingErrorsCount = "";

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Collapsed;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Visible;
                    RulebaseOptimizedScriptLink.Visibility = Visibility.Visible;
                    break;

                case Vendor.FortiGate:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Collapsed;
                    RulebaseOptimizedScriptLink.Visibility = Visibility.Collapsed;

                    FortiGateConverter fgConverter = (FortiGateConverter)vendorConverter;
                    ConvertedPolicyRulesCount = (fgConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", fgConverter.RulesInConvertedPackage()) : " Check report.";
                    ConvertedNATPolicyRulesCount = (fgConverter.RulesInNatLayer() != -1) ? string.Format(" ({0} rules)", fgConverter.RulesInNatLayer()) : " Check report.";
                    ConvertingWarningsCount = (fgConverter.WarningsInConvertedPackage() != -1) ? string.Format(" ({0} warnings)", fgConverter.WarningsInConvertedPackage()) : " Check report.";
                    ConvertingErrorsCount = (fgConverter.ErrorsInConvertedPackage() != -1) ? string.Format(" ({0} errors)", fgConverter.ErrorsInConvertedPackage()) : " Check report.";
                    break;

                case Vendor.PaloAlto:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Collapsed;
                    RulebaseOptimizedScriptLink.Visibility = Visibility.Collapsed;
                    PaloAltoConverter paConverter = (PaloAltoConverter)vendorConverter;
                    ConvertedPolicyRulesCount = (paConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", paConverter.RulesInConvertedPackage()) : " Check report.";
                    ConvertedNATPolicyRulesCount = (paConverter.RulesInNatLayer() != -1) ? string.Format(" ({0} rules)", paConverter.RulesInNatLayer()) : " Check report.";
                    ConvertingWarningsCount = (paConverter.WarningsInConvertedPackage() != -1) ? string.Format(" ({0} warnings)", paConverter.WarningsInConvertedPackage()) : " Check report.";
                    ConvertingErrorsCount = (paConverter.ErrorsInConvertedPackage() != -1) ? string.Format(" ({0} errors)", paConverter.ErrorsInConvertedPackage()) : " Check report.";
                    break;
                case Vendor.PaloAltoPanorama:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Collapsed;
                    RulebaseOptimizedScriptLink.Visibility = Visibility.Collapsed;

                    PanoramaConverter panoramaConverter = (PanoramaConverter)vendorConverter;
                    ConvertedPolicyRulesCount = (panoramaConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", panoramaConverter.RulesInConvertedPackage()) : " Check report.";
                    ConvertedNATPolicyRulesCount = (panoramaConverter.RulesInNatLayer() != -1) ? string.Format(" ({0} rules)", panoramaConverter.RulesInNatLayer()) : " Check report.";
                    ConvertingWarningsCount = (panoramaConverter.WarningsInConvertedPackage() != -1) ? string.Format(" ({0} warnings)", panoramaConverter.WarningsInConvertedPackage()) : " Check report.";
                    ConvertingErrorsCount = (panoramaConverter.ErrorsInConvertedPackage() != -1) ? string.Format(" ({0} errors)", panoramaConverter.ErrorsInConvertedPackage()) : " Check report.";
                    break;
                default:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Collapsed;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Collapsed;
                    RulebaseOptimizedScriptLink.Visibility = Visibility.Collapsed;
                    break;
            }

            OriginalFileLink.Tag = vendorConverter.VendorHtmlFile;
            ConvertingWarningsLink.Tag = vendorConverter.WarningsHtmlFile;
            ConvertingErrorsLink.Tag = vendorConverter.ErrorsHtmlFile;
            ConvertedPolicyLink.Tag = vendorConverter.PolicyHtmlFile;
            ConvertedOptimizedPolicyLink.Tag = vendorConverter.PolicyOptimizedHtmlFile;
            ConvertedNatPolicyLink.Tag = vendorConverter.NatHtmlFile;
            ObjectsScriptLink.Tag = vendorConverter.ObjectsScriptFile;
            RulebaseScriptLink.Tag = vendorConverter.PolicyScriptFile;
            RulebaseOptimizedScriptLink.Tag = vendorConverter.PolicyOptimizedScriptFile;
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

        private void HandleCommandLineArgs()
        {
            try
            {
                string[] args = Environment.GetCommandLineArgs();
                bool hasArgs = args.Length > 1;

                foreach (var arg in args)
                {
                    if (arg.Equals("asa-spread-acl-remarks", StringComparison.InvariantCultureIgnoreCase))
                    {
                        CiscoParser.SpreadAclRemarks = true;
                        break;
                    }
                }

                if (hasArgs && !CiscoParser.SpreadAclRemarks)
                {
                    ShowMessage(string.Format("Unrecognized command line argument: {0}", args[1]), MessageTypes.Warning);
                }
            }
            catch (Exception ex)
            {
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
