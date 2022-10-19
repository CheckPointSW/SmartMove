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
using System.ComponentModel;
using CommonUtils;
using CheckPointObjects;

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

        private static bool canCloseWindow = true;
        
        #endregion

        #region Construction

        public MainWindow()
        {
            _supportedVendors.SelectedVendor = Vendor.CiscoASA;   // this is the default

            InitializeComponent();
            LoadContactInfo();
            HandleCommandLineArgs();
        }

        void OnLoad(object sender, RoutedEventArgs e)
        {
            this.Owner.Hide();
        }
        void OnClose(object sender, CancelEventArgs e)
        {
            this.Owner.Show();
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
        
        #region OptimizeByCommentsConversion

        public bool OptimizeByCommentsConversion
        {
            get { return (bool)GetValue(OptimizeByCommentsConversionProperty); }
            set { SetValue(OptimizeByCommentsConversionProperty, value); }
        }

        public static readonly DependencyProperty OptimizeByCommentsConversionProperty =
            DependencyProperty.Register("OptimizeByCommentsConversion", typeof(bool), typeof(MainWindow), new PropertyMetadata(false));

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

        #region CreateServiceGroupsConfiguration

        public bool CreateServiceGroupsConfiguration
        {
            get { return (bool)GetValue(CreateServiceGroupsConfigurationProperty); }
            set { SetValue(CreateServiceGroupsConfigurationProperty, value); }
        }

        public static readonly DependencyProperty CreateServiceGroupsConfigurationProperty =
            DependencyProperty.Register("CreateServiceGroupsConfigurationProperty", typeof(bool), typeof(MainWindow), new PropertyMetadata(false));

        #endregion

        #region ExportManagmentReport
        public bool ExportManagmentReport
        {
            get { return (bool)GetValue(ExportManagmentReportProperty); }
            set { SetValue(ExportManagmentReportProperty, value); }
        }

        public static readonly DependencyProperty ExportManagmentReportProperty =
            DependencyProperty.Register("ExportManagmentReport", typeof(bool), typeof(MainWindow), new PropertyMetadata(false));

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
            if (canCloseWindow)
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
            CreateServiceGroupsConf.Visibility = Visibility.Collapsed;
            SkipUnusedObjects.Visibility = Visibility.Collapsed;
            OptimizeByComments.Visibility = Visibility.Collapsed;
            ConvertUserConfiguration = false;
            //Create service groups option
            CreateServiceGroupsConfiguration = true;
            


            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    ConfigurationFileLabel = SupportedVendors.CiscoConfigurationFileLabel;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    //CreateServiceGroupsConf.Visibility = Visibility.Visible;
                    OptimizeByComments.Visibility = Visibility.Visible;
                    break;
                case Vendor.FirePower:
                    ConfigurationFileLabel = SupportedVendors.FirepowerConfigurationFileLabel;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    //CreateServiceGroupsConf.Visibility = Visibility.Visible;
                    OptimizeByComments.Visibility = Visibility.Visible;
                    break;
                case Vendor.JuniperJunosOS:
                    ConfigurationFileLabel = SupportedVendors.JuniperConfigurationFileLabel;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    //CreateServiceGroupsConf.Visibility = Visibility.Visible;
                    break;
                case Vendor.JuniperScreenOS:
                    ConfigurationFileLabel = SupportedVendors.NetScreenConfigurationFileLabel;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    //CreateServiceGroupsConf.Visibility = Visibility.Visible;
                    break;
                case Vendor.FortiGate:
                    ConfigurationFileLabel = SupportedVendors.FortiGateConfigurationFileLabel;
                    DomainNameTB.Visibility = Visibility.Visible;
                    DomainName.Visibility = Visibility.Visible;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    //CreateServiceGroupsConf.Visibility = Visibility.Visible;
                    ConvertUserConf.Visibility = Visibility.Visible;
                    break;
                case Vendor.PaloAlto:
                    ConfigurationFileLabel = SupportedVendors.PaloAltoConfigurationFileLabel;
                    DomainNameTB.Visibility = Visibility.Visible;
                    DomainName.Visibility = Visibility.Visible;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    //CreateServiceGroupsConf.Visibility = Visibility.Visible;
                    ConvertUserConf.Visibility = Visibility.Visible;
                    break;
                case Vendor.PaloAltoPanorama:
                    ConfigurationFileLabel = SupportedVendors.PaloAltoPanoramaConfigurationFileLabel;
                    DomainNameTB.Visibility = Visibility.Visible;
                    DomainName.Visibility = Visibility.Visible;
                    SkipUnusedObjects.Visibility = Visibility.Visible;
                    //CreateServiceGroupsConf.Visibility = Visibility.Visible;
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
#pragma warning disable CS0168 // The variable 'ex' is declared but never used
            catch (Exception ex)
#pragma warning restore CS0168 // The variable 'ex' is declared but never used
            {
                openFileDialog.InitialDirectory = SourceFolder;
            }

            string filter = "";

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                case Vendor.FirePower:
                    filter = "conf files (*.conf, *.txt, *.cfg)|*.conf; *.txt; *.cfg|All files (*.*)|*.*";
                    break;
                case Vendor.JuniperJunosOS:
                    filter = "xml files (*.xml)|*.xml";
                    break;
                case Vendor.JuniperScreenOS:
                    filter = "conf files (*.txt)|*.txt|All files (*.*)|*.*";
                    break;
                case Vendor.FortiGate:
                    filter = "conf files (*.conf)|*.conf| All files (*.*)|*.*";
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
                    SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", ex.Message + "\n" + ex.StackTrace);
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
#pragma warning disable CS0168 // The variable 'ex' is declared but never used
            catch (Exception ex)
#pragma warning restore CS0168 // The variable 'ex' is declared but never used
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
                    SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", ex.Message + "\n" + ex.StackTrace);
                    ShowMessage("Could not read file from disk.\nOriginal error: " + ex.Message, MessageTypes.Error);
                }
            }
        }

        private async void Go_OnClick(object sender, RoutedEventArgs e)
        {
            canCloseWindow = false;
            string fileName = Path.GetFileNameWithoutExtension(ConfigFilePath.Text);

            if (string.IsNullOrEmpty(ConfigFilePath.Text) || string.IsNullOrEmpty(fileName))
            {
                SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Configuration file is not selected.");
                ShowMessage("Configuration file is not selected.", MessageTypes.Error);
                return;
            }

            if (!File.Exists(ConfigFilePath.Text))
            {
                SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Cannot find configuration file.");
                ShowMessage("Cannot find configuration file.", MessageTypes.Error);
                return;
            }

            if (fileName.Length > 15)
            {
                SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Configuration file name is restricted to 15 characters at most.");
                ShowMessage("Configuration file name is restricted to 15 characters at most.", MessageTypes.Error);
                return;
            }

            if (!Directory.Exists(TargetFolderPath.Text))
            {
                SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Cannot find target folder for conversion output.");
                ShowMessage("Cannot find target folder for conversion output.", MessageTypes.Error);
                return;
            }

            if (ConvertUserConfiguration)
            {
                if (LDAPAccountUnit.Text.Trim().Equals("") || LDAPAccountUnit.Text.Trim().Contains(" "))
                {
                    SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "LDAP Account Unit field cannot be empty or containt space(s).");
                    ShowMessage("LDAP Account Unit field cannot be empty or containt space(s).", MessageTypes.Error);
                    return;
                }
            }

            VendorParser vendorParser;

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    vendorParser = new CiscoParser();
                    break;
                case Vendor.FirePower:
                    vendorParser = new CiscoParser() { 
                        isUsingForFirePower = true 
                    };
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
                    string compressorsDirPath = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar + "compressors";
                    string compressorZip = Path.Combine(compressorsDirPath, "zip.exe");
                    string compressorGtar = Path.Combine(compressorsDirPath, "gtar.exe");
                    string compressorGzip = Path.Combine(compressorsDirPath, "gzip.exe");
                    if (!File.Exists(compressorZip) || !File.Exists(compressorGtar) || !File.Exists(compressorGzip))
                    {
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "The system cannot find the required files. ");
                        ShowMessage(null, MessageTypes.Error, "these instructions", "https://github.com/CheckPointSW/SmartMove#smart-connector-and-paloalto-panorama-instructions", null, null, 
                            string.Format("{1}{0}{2}", Environment.NewLine, "The system cannot find the required files. ",
                        "Please follow"));
                        return;
                    }
                    vendorParser = new PanoramaParser();
                    break;
                default:
                    throw new InvalidDataException("Unexpected!!!");
            }
			
            Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
            EnableDisableControls(false);
            ProgressPanel.Visibility = Visibility.Visible;
            ResultsPanel.Visibility = Visibility.Collapsed;
            OutputPanel.Visibility = Visibility.Visible;

            UpdateProgress(10, "Parsing configuration file ...");
			
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
                SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", ex.Message + "\n" + ex.StackTrace);
                ShowMessage("Could not convert configuration file.", "Message:\nModule:\nClass:\nMethod:", string.Format("{0}\n{1}\n{2}\n{3}", ex.Message, ex.Source, ex.TargetSite.ReflectedType.Name, ex.TargetSite.Name), MessageTypes.Error); 
                return;
            }

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unspecified ASA version.\nCannot find ASA version for the selected configuration.\nThe configuration may not parse correctly.");
                        ShowMessage("Unspecified ASA version.\nCannot find ASA version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 8 || (vendorParser.MajorVersion == 8 && vendorParser.MinorVersion < 3))
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unsupported ASA version (" + vendorParser.Version + ").\nThis tool supports ASA 8.3 and above configuration files.\nThe configuration may not parse correctly.");
                        ShowMessage("Unsupported ASA version (" + vendorParser.Version + ").\nThis tool supports ASA 8.3 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    break;

                case Vendor.FirePower:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unspecified NGFW version.\nCannot find version for the selected configuration.\nThe configuration may not parse correctly.");
                        ShowMessage("Unspecified NGFW version.\nCannot find version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 6 || (vendorParser.MajorVersion == 6 && vendorParser.MinorVersion < 4))
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unsupported version (" + vendorParser.Version + ").\nThis tool supports NGFW 6.4 and above configuration files.\nThe configuration may not parse correctly.");
                        ShowMessage("Unsupported version (" + vendorParser.Version + ").\nThis tool supports NGFW 6.4 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    break;

                case Vendor.JuniperJunosOS:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unspecified SRX version.\nCannot find SRX version for the selected configuration.\nThe configuration may not parse correctly.");
                        ShowMessage("Unspecified SRX version.\nCannot find SRX version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 12 || (vendorParser.MajorVersion == 12 && vendorParser.MinorVersion < 1))
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unsupported SRX version (" + vendorParser.Version + ").\nThis tool supports SRX 12.1 and above configuration files.\nThe configuration may not parse correctly.");
                        ShowMessage("Unsupported SRX version (" + vendorParser.Version + ").\nThis tool supports SRX 12.1 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    break;

                case Vendor.JuniperScreenOS:
                    break;

                case Vendor.FortiGate:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unspecified FortiGate version.\nCannot find FortiGate version for the selected configuration.\nThe configuration may not parse correctly.");
                        ShowMessage("Unspecified FortiGate version.\nCannot find FortiGate version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    else if(vendorParser.MajorVersion < 5)
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unsupported FortiGate version (" + vendorParser.Version + ").\nThis tool supports FortiGate 5.x and above configuration files.\nThe configuration may not parse correctly.");
                        ShowMessage("Unsupported FortiGate version (" + vendorParser.Version + ").\nThis tool supports FortiGate 5.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    break;
                case Vendor.PaloAlto:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unspecified PaloAlto version.\nCannot find PaloAlto PAN-OS version for the selected configuration.\nThe configuration may not parse correctly.");
                        ShowMessage("Unspecified PaloAlto version.\nCannot find PaloAlto PAN-OS version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto PAN-OS 7.x and above configuration files.\nThe configuration may not parse correctly.");
                        ShowMessage("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto PAN-OS 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    break;
                case Vendor.PaloAltoPanorama:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unspecified PaloAlto version.\nCannot find PaloAlto Panorama version for the selected configuration.\nThe configuration may not parse correctly.");
                        ShowMessage("Unspecified PaloAlto version.\nCannot find PaloAlto Panorama version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        EnableWindow();
                        SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", "Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto Panorama 7.x and above configuration files.\nThe configuration may not parse correctly.");
                        ShowMessage("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto Panorama 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Error);
                        return;
                    }
                    break;
            }

            vendorParser.Export(targetFolder + vendorFileName + ".json");

            VendorConverter vendorConverter;

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    CiscoConverter ciscoConverter = new CiscoConverter();
                    ciscoConverter.SkipUnusedObjects = SkipUnusedObjectsConversion;
                    vendorConverter = ciscoConverter;
                    
                    break;
                case Vendor.FirePower:
                    vendorConverter = new CiscoConverter() {
                        isUsingForFirePower = true,
                        SkipUnusedObjects = SkipUnusedObjectsConversion,
                    };
                    break;
                case Vendor.JuniperJunosOS:
                    JuniperConverter juniperConverter = new JuniperConverter();
                    juniperConverter.SkipUnusedObjects = SkipUnusedObjectsConversion;
                    vendorConverter = juniperConverter;
                    break;
                case Vendor.JuniperScreenOS:
                    ScreenOSConverter screenosConverter = new ScreenOSConverter();
                    screenosConverter.SkipUnusedObjects = SkipUnusedObjectsConversion;
                    vendorConverter = screenosConverter;
                    break;
                case Vendor.FortiGate:
                    FortiGateConverter fgConverter = new FortiGateConverter();
                    fgConverter.OptimizeConf = SkipUnusedObjectsConversion;
                    fgConverter.ConvertUserConf = ConvertUserConfiguration;
                    fgConverter.LDAPAccoutUnit = ldapAccountUnit.Trim();
                    fgConverter.CreateManagnetReport = ExportManagmentReport;
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
                    panoramaConverter.CreateManagnetReport = ExportManagmentReport;
                    vendorConverter = panoramaConverter;
                    break;
                default:
                    throw new InvalidDataException("Unexpected!!!");
            }
            vendorConverter.CreateServiceGroups = CreateServiceGroupsConfiguration;

            //here outputformat was set to 'json' by default manually because there is no an option for it on GUI
            vendorConverter.Initialize(vendorParser, ConfigFilePath.Text, toolVersion, targetFolder, DomainName.Text, "json");
            vendorConverter.ConversionProgress += OnConversionProgress;

            try
            {
                await Task.Run(() => vendorConverter.Convert(convertNat));
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", ex.Message + "\n" + ex.StackTrace);
                EnableDisableControls(true);
                OutputPanel.Visibility = Visibility.Collapsed;
                if (ex is InvalidDataException && ex.Message != null && ex.Message.Contains("Policy exceeds the maximum number"))
                {
                    ShowMessage(null, MessageTypes.Error, "ps@checkpoint.com", "mailto:ps@checkpoint.com", null, null,
                        String.Format("{1}{0}{2}{0}{3}", Environment.NewLine, "SmartMove is unable to convert the provided policy.",
                                                "Reason: Policy exceeds the maximum number of supported policy layers.",
                                                "To assure the smooth conversion of your data, it is recommended to contact Check Point Professional Services by sending an e-mail to"));
                }
                else
                {
                    if (ex.Message.Contains("System.OutOfMemoryException"))
                    {
                        ShowMessage(null, MessageTypes.Error, null, null, null, null,
                            String.Format("{1}{0}{2}", Environment.NewLine, "Could not convert configuration file.",
                                                    "Reason: Your device is low on memory."));
                    } else 
                    ShowMessage("Could not convert configuration file.", "Message:\nModule:\nClass:\nMethod:", string.Format("{0}\n{1}\n{2}\n{3}", ex.Message, ex.Source, ex.TargetSite.ReflectedType.Name, ex.TargetSite.Name), MessageTypes.Error);
                }
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
            
            if (OptimizeByCommentsConversion)
            {
                ConvertedOptimizedPolicyLink.MouseUp -= Link_OnClick;
                vendorConverter.ExportPolicyPackagesAsHtml();

                // Check to see if there is no converted optimized.
                if (vendorConverter.RulesInConvertedOptimizedPackage() == vendorConverter.RulesInConvertedPackage() ) // only in case the converted optimize cannot be performed.
                {
                    ConvertedOptimizedPolicyLink.Style = (Style)ConvertedOptimizedPolicyLink.FindResource("NormalTextBloclStyle");
                }
                else // otherwise the link will be clickable.
                {
                    ConvertedOptimizedPolicyLink.Style = (Style)ConvertedOptimizedPolicyLink.FindResource("HyperLinkStyle");
                    ConvertedOptimizedPolicyLink.MouseUp += Link_OnClick;
                }
            }
            
            if (ExportManagmentReport && (typeof(PanoramaConverter) != vendorConverter.GetType() && typeof(FortiGateConverter) != vendorConverter.GetType()))
            {
                vendorConverter.ExportManagmentReport();
            }
            UpdateProgress(100, "");

            vendorConverter.ConversionProgress -= OnConversionProgress;

            Mouse.OverrideCursor = null;
            EnableDisableControls(true);
            ProgressPanel.Visibility = Visibility.Collapsed;
            ResultsPanel.Visibility = Visibility.Visible;

            ShowResults(vendorConverter, vendorParser.ParsedLines);
            canCloseWindow = true;
        }

        private void EnableWindow()
        {
            Mouse.OverrideCursor = null;
            EnableDisableControls(true);
            OutputPanel.Visibility = Visibility.Collapsed;
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
            SkipUnusedObjects.IsEnabled = enable;
            CreateServiceGroupsConf.IsEnabled = false;
            Go.IsEnabled = enable;
        }

        private void ShowResults(VendorConverter vendorConverter, int convertedLinesCount)
        {
            ConversionIssuesPanel.Visibility = Visibility.Collapsed;
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
                case Vendor.FirePower:
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Visible;
                    RulebaseOptimizedScriptLink.Visibility = Visibility.Visible; 
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;

                    CiscoConverter ciscoConverter = (CiscoConverter)vendorConverter;


                    ConvertingWarningsCount = (ciscoConverter.WarningsInConvertedPackage() != 0) ? string.Format(" ({0} warnings)", ciscoConverter.WarningsInConvertedPackage()) : " Check report.";
                    ConvertingErrorsCount = (ciscoConverter.ErrorsInConvertedPackage() != 0) ? string.Format(" ({0} errors)", ciscoConverter.ErrorsInConvertedPackage()) : " Check report.";

                    break;

                case Vendor.FortiGate:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Visible;

                    FortiGateConverter fgConverter = (FortiGateConverter)vendorConverter;

                    RulebaseOptimizedScriptLink.Visibility = fgConverter.ShowBashOptLink ? Visibility.Visible : Visibility.Collapsed;

                    ConvertedPolicyRulesCount = (fgConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", fgConverter.RulesInConvertedPackage()) : " Check report.";
                    ConvertedOptimizedPolicyRulesCount = (fgConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", fgConverter.RulesInConvertedOptimizedPackage()) : " Check report.";
                    ConvertedNATPolicyRulesCount = (fgConverter.RulesInNatLayer() != -1) ? string.Format(" ({0} rules)", fgConverter.RulesInNatLayer()) : " Check report.";
                    ConvertingWarningsCount = (fgConverter.WarningsInConvertedPackage() != -1) ? string.Format(" ({0} warnings)", fgConverter.WarningsInConvertedPackage()) : " Check report.";
                    ConvertingErrorsCount = (fgConverter.ErrorsInConvertedPackage() != -1) ? string.Format(" ({0} errors)", fgConverter.ErrorsInConvertedPackage()) : " Check report.";
                    break;

                case Vendor.JuniperJunosOS:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Visible;
                    RulebaseOptimizedScriptLink.Visibility = Visibility.Visible;
                    JuniperConverter jConverter = (JuniperConverter)vendorConverter;
                    ConvertedOptimizedPolicyRulesCount = (jConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", jConverter.RulesInConvertedOptimizedPackage()) : " Check report.";
                    ConvertingWarningsCount = (jConverter.WarningsInConvertedPackage() != 0) ? string.Format(" ({0} warnings)", jConverter.WarningsInConvertedPackage()) : " Check report.";
                    ConvertingErrorsCount = (jConverter.ErrorsInConvertedPackage() != 0) ? string.Format(" ({0} errors)", jConverter.ErrorsInConvertedPackage()) : " Check report.";
                    break;

                case Vendor.JuniperScreenOS:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Visible;
                    RulebaseOptimizedScriptLink.Visibility = Visibility.Visible;
                    ScreenOSConverter soConverter = (ScreenOSConverter)vendorConverter;
                    ConvertedOptimizedPolicyRulesCount = (soConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", soConverter.RulesInConvertedOptimizedPackage()) : " Check report.";
                    ConvertingWarningsCount = (soConverter.WarningsInConvertedPackage() != 0) ? string.Format(" ({0} warnings)", soConverter.WarningsInConvertedPackage()) : " Check report.";
                    ConvertingErrorsCount = (soConverter.ErrorsInConvertedPackage() != 0) ? string.Format(" ({0} errors)", soConverter.ErrorsInConvertedPackage()) : " Check report.";
                    break;

                case Vendor.PaloAlto:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Visible;

                    PaloAltoConverter paConverter = (PaloAltoConverter)vendorConverter;
                    RulebaseOptimizedScriptLink.Visibility = paConverter.ShowOptBashLink ? Visibility.Visible : Visibility.Collapsed;

                    ConvertedPolicyRulesCount = (paConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", paConverter.RulesInConvertedPackage()) : " Check report.";
                    ConvertedOptimizedPolicyRulesCount = (paConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", paConverter.RulesInConvertedOptimizedPackage()) : " Check report.";
                    ConvertedNATPolicyRulesCount = (paConverter.RulesInNatLayer() != -1) ? string.Format(" ({0} rules)", paConverter.RulesInNatLayer()) : " Check report.";
                    ConvertingWarningsCount = (paConverter.WarningsInConvertedPackage() != -1) ? string.Format(" ({0} warnings)", paConverter.WarningsInConvertedPackage()) : " Check report.";
                    ConvertingErrorsCount = (paConverter.ErrorsInConvertedPackage() != -1) ? string.Format(" ({0} errors)", paConverter.ErrorsInConvertedPackage()) : " Check report.";
                    break;

                case Vendor.PaloAltoPanorama:
                    CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
                    ConvertedOptimizedPolicyPanel.Visibility = Visibility.Visible;

                    PanoramaConverter panoramaConverter = (PanoramaConverter)vendorConverter;

                    RulebaseOptimizedScriptLink.Visibility = panoramaConverter.ShowOptBashLink ? Visibility.Visible : Visibility.Collapsed;

                    ConvertedPolicyRulesCount = (panoramaConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", panoramaConverter.RulesInConvertedPackage()) : " Check report.";
                    ConvertedNATPolicyRulesCount = (panoramaConverter.RulesInNatLayer() != -1) ? string.Format(" ({0} rules)", panoramaConverter.RulesInNatLayer()) : " Check report.";
                    ConvertedOptimizedPolicyRulesCount = (panoramaConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", panoramaConverter.RulesInConvertedOptimizedPackage()) : " Check report.";
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
            ConvertedPolicyLink.Tag = vendorConverter.PolicyHtmlFile;
            ConvertedOptimizedPolicyLink.Tag = vendorConverter.PolicyOptimizedHtmlFile;
            ConvertedNatPolicyLink.Tag = vendorConverter.NatHtmlFile;
            RulebaseOptimizedScriptLink.Tag = vendorConverter.PolicyOptimizedScriptFile;
            ObjectsScriptLink.Tag = vendorConverter.ObjectsScriptFile;
            RulebaseScriptLink.Tag = vendorConverter.PolicyScriptFile;


            ConvertingWarningsLink.Tag = vendorConverter.WarningsHtmlFile;
            ConvertingErrorsLink.Tag = vendorConverter.ErrorsHtmlFile;

            CoversionIssuesPreviewPanel.Visibility = (File.Exists(vendorConverter.WarningsHtmlFile) || File.Exists(vendorConverter.ErrorsHtmlFile)) ? Visibility.Visible : Visibility.Collapsed;
            ConvertingWarningsPanel.Visibility = File.Exists(vendorConverter.WarningsHtmlFile) ? Visibility.Visible : Visibility.Collapsed;
            ConvertingErrorsPanel.Visibility = File.Exists(vendorConverter.ErrorsHtmlFile) ? Visibility.Visible : Visibility.Collapsed;
            ConvertedNatPolicyPanel.Visibility = File.Exists(vendorConverter.NatHtmlFile) ? Visibility.Visible : Visibility.Collapsed;
            ConvertedPolicyLink.Visibility = File.Exists(vendorConverter.PolicyHtmlFile) ? Visibility.Visible : Visibility.Collapsed;
            ObjectsScriptLink.Visibility = File.Exists(vendorConverter.ObjectsScriptFile) ? Visibility.Visible : Visibility.Collapsed;
            RulebaseScriptLink.Visibility = File.Exists(vendorConverter.PolicyScriptFile) ? Visibility.Visible : Visibility.Collapsed;
            RulebaseOptimizedScriptLink.Visibility = File.Exists(vendorConverter.PolicyOptimizedScriptFile) ? Visibility.Visible : Visibility.Collapsed;
            ConvertedOptimizedPolicyPanel.Visibility = File.Exists(vendorConverter.PolicyOptimizedScriptFile) ? Visibility.Visible : Visibility.Collapsed;

            PolicyRulesCountBlock.Visibility = ConvertedPolicyLink.Visibility;
            ConvertedNatPolicyPanel.Visibility = ConvertedNatPolicyLink.Visibility;

            BashScriptsPanel.Visibility = (RulebaseOptimizedScriptLink.Visibility == Visibility.Visible || RulebaseScriptLink.Visibility == Visibility.Visible || ObjectsScriptLink.Visibility == Visibility.Visible) ? Visibility.Visible : Visibility.Collapsed;
            ConvertedPolicyPreviewPanel.Visibility = (ConvertedPolicyLink.Visibility == Visibility.Visible || ConvertedNatPolicyPanel.Visibility == Visibility.Visible || ConvertedOptimizedPolicyPanel.Visibility == Visibility.Visible) ? Visibility.Visible : Visibility.Collapsed;
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
#pragma warning disable CS0168 // The variable 'ex' is declared but never used
            catch (Exception ex)
#pragma warning restore CS0168 // The variable 'ex' is declared but never used
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
#pragma warning disable CS0168 // The variable 'ex' is declared but never used
            catch (Exception ex)
#pragma warning restore CS0168 // The variable 'ex' is declared but never used
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

                    if (arg.Equals("is-optimize-by-comments", StringComparison.InvariantCultureIgnoreCase))
                    {
                        CiscoParser.SpreadAclRemarks = true;
                        RuleBaseOptimizer.IsOptimizeByComments = true;
                        break;
                    }
                }

                if (hasArgs && !CiscoParser.SpreadAclRemarks)
                {
                    SMDebugger.PrintToDebug(TargetFolderPath.Text + "\\", string.Format("Unrecognized command line argument: {0}", args[1]));
                    ShowMessage(string.Format("Unrecognized command line argument: {0}", args[1]), MessageTypes.Warning);
                }
            }
#pragma warning disable CS0168 // The variable 'ex' is declared but never used
            catch (Exception ex)
#pragma warning restore CS0168 // The variable 'ex' is declared but never used
            {
            }
        }
        
        public static void ShowMessage(string header, string columns, string message, MessageTypes messageType)
        {
            ShowMessage(message, messageType, null, null, header, columns);
        }
        
        public static void ShowMessage(string message, MessageTypes messageType)
        {
            ShowMessage(null, messageType, null, null, null, null, message);
        }

        /// <summary>
        /// Build a message for displaying. If need to show technical columns like "method", "Class" then need to pass to message 
        /// message after columns, list of columns to colums and to header pass main message. If need just display a text 
        /// then pass to message, columns, header null values and fill only messageWoColumns
        /// </summary>
        /// <param name="message">message for displaying with columns. If need display without columns set to null</param>
        /// <param name="messageType">message window type (uses always)</param>
        /// <param name="messageLinkText">text for link (uses if need display link)</param>
        /// <param name="messageLinkValue">link(uses if need display link)</param>
        /// <param name="header">header for messages with columns, otherwise set null</param>
        /// <param name="columns">list of columns separated by '\n' symbol. set to null if don't need</param>
        /// <param name="messageWoColumns">message for displaying without columns. if need to display with columns set to null (by default)</param>
        public static void ShowMessage(string message, MessageTypes messageType, string messageLinkText, string messageLinkValue, string header, string columns, string messageWoColumns = null)
        {
            var messageWindow = new MessageWindow
            {
                Header = header,
                Message = message,
                MessageType = messageType,
                MessageLinkText = columns != null ? messageLinkText : null,
                MessageLinkTextClean = columns != null ? null : messageLinkText,
                MessageLinkValue = messageLinkValue,
                Columns = columns,
                MessageWoColumns = messageWoColumns
            };

            Mouse.OverrideCursor = null;
            messageWindow.ShowDialog();
            canCloseWindow = true;
        }
        
        
        #endregion

        private void OptimizeByComments_Checked(object sender, RoutedEventArgs e)
        {
                if (OptimizeByCommentsConversion)
            {
                CiscoParser.SpreadAclRemarks = true;
                RuleBaseOptimizer.IsOptimizeByComments = true;
            }
            else
            {
                CiscoParser.SpreadAclRemarks = false;
                RuleBaseOptimizer.IsOptimizeByComments = false;
            }
        }
    }
}
