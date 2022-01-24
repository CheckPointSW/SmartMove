using CiscoMigration;
using FortiGateMigration;
using JuniperMigration;
using MigrationBase;
using NetScreenMigration;
using PaloAltoMigration;
using PanoramaPaloAltoMigration;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace SmartMove
{
    /// <summary>
    /// Interaction logic for AnalyzeWindow.xaml
    /// </summary>
    public partial class AnalyzeWindow : Window
    {
        #region TotalRulesCount

        public string TotalRulesCount
        {
            get { return (string)GetValue(TotalRulesCountProperty); }
            set { SetValue(TotalRulesCountProperty, value); }
        }

        public static readonly DependencyProperty TotalRulesCountProperty =
            DependencyProperty.Register("TotalRulesCount", typeof(string), typeof(MainWindow), new PropertyMetadata(null));

        #endregion

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

        #region CLI

        public static string SKText { get; private set; }
        public static string SKLinkText { get; private set; }
        public static object SKLinkAddress { get; private set; }

        #endregion

        #region Private Members

        private readonly SupportedVendors _supportedVendors = new SupportedVendors();

        #endregion

        public AnalyzeWindow()
        {
            _supportedVendors.SelectedVendor = Vendor.CiscoASA;   // this is the default

            InitializeComponent();
            LoadContactInfo();
        }

        void OnLoad(object sender, RoutedEventArgs e)
        {
            this.Owner.Hide();
        }
        void OnClose(object sender, CancelEventArgs e)
        {
            this.Owner.Show();
        }

        private async void Analyze_OnClickAsync(object sender, RoutedEventArgs e)
        {
            string fileName = Path.GetFileNameWithoutExtension(ConfigFilePath.Text);

            if (string.IsNullOrEmpty(ConfigFilePath.Text) || string.IsNullOrEmpty(fileName))
            {
                MainWindow.ShowMessage("Configuration file is not selected.", MessageTypes.Error);
                return;
            }

            if (!File.Exists(ConfigFilePath.Text))
            {
                MainWindow.ShowMessage("Cannot find configuration file.", MessageTypes.Error);
                return;
            }

            if (fileName.Length > 20)
            {
                MainWindow.ShowMessage("Configuration file name is restricted to 20 characters at most.", MessageTypes.Error);
                return;
            }

            if (!Directory.Exists(TargetFolderPath.Text))
            {
                MainWindow.ShowMessage("Cannot find target folder for conversion output.", MessageTypes.Error);
                return;
            }

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
                    string compressorsDirPath = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar + "compressors";
                    string compressorZip = Path.Combine(compressorsDirPath, "zip.exe");
                    string compressorGtar = Path.Combine(compressorsDirPath, "gtar.exe");
                    string compressorGzip = Path.Combine(compressorsDirPath, "gzip.exe");
                    if (!File.Exists(compressorZip) || !File.Exists(compressorGtar) || !File.Exists(compressorGzip))
                    {
                        MainWindow.ShowMessage(null, MessageTypes.Error, "these instructions", "https://github.com/CheckPointSW/SmartMove#smart-connector-and-paloalto-panorama-instructions", 
                            null, null, String.Format("{1}{0}{2}", Environment.NewLine, "The system cannot find the required files. ", "Please follow"));
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

            try
            {
                string ciscoFile = ConfigFilePath.Text;
                switch (_supportedVendors.SelectedVendor)
                {
                    case Vendor.PaloAltoPanorama:
                        PanoramaParser panParser = (PanoramaParser)vendorParser;
                        await Task.Run(() => panParser.ParseWithTargetFolder(ciscoFile, targetFolder));
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
                MainWindow.ShowMessage("Could not parse configuration file.", "Message:\nModule:\nClass:\nMethod:", string.Format("{0}\n{1}\n{2}\n{3}", ex.Message, ex.Source, ex.TargetSite.ReflectedType.Name, ex.TargetSite.Name), MessageTypes.Error);
                return;
            }

            switch (_supportedVendors.SelectedVendor)
            {
                case Vendor.CiscoASA:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        MainWindow.ShowMessage("Unspecified ASA version.\nCannot find ASA version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 8 || (vendorParser.MajorVersion == 8 && vendorParser.MinorVersion < 3))
                    {
                        MainWindow.ShowMessage("Unsupported ASA version (" + vendorParser.Version + ").\nThis tool supports ASA 8.3 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;

                case Vendor.JuniperJunosOS:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        MainWindow.ShowMessage("Unspecified SRX version.\nCannot find SRX version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 12 || (vendorParser.MajorVersion == 12 && vendorParser.MinorVersion < 1))
                    {
                        MainWindow.ShowMessage("Unsupported SRX version (" + vendorParser.Version + ").\nThis tool supports SRX 12.1 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;

                case Vendor.JuniperScreenOS:
                    break;

                case Vendor.FortiGate:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        MainWindow.ShowMessage("Unspecified FortiGate version.\nCannot find FortiGate version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 5)
                    {
                        MainWindow.ShowMessage("Unsupported FortiGate version (" + vendorParser.Version + ").\nThis tool supports FortiGate 5.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;
                case Vendor.PaloAlto:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        MainWindow.ShowMessage("Unspecified PaloAlto version.\nCannot find PaloAlto PAN-OS version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        MainWindow.ShowMessage("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto PAN-OS 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;
                case Vendor.PaloAltoPanorama:
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        MainWindow.ShowMessage("Unspecified PaloAlto version.\nCannot find PaloAlto Panorama version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        MainWindow.ShowMessage("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto Panorama 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
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
                    vendorConverter = new FortiGateConverter();
                    break;
                case Vendor.PaloAlto:
                    vendorConverter = new PaloAltoConverter();
                    break;
                case Vendor.PaloAltoPanorama:
                    vendorConverter = new PanoramaConverter();
                    break;
                default:
                    throw new InvalidDataException("Unexpected!!!");
            }

            //here outputformat was set to 'json' by default manually because there is no an option for it on GUI
            vendorConverter.Initialize(vendorParser, ConfigFilePath.Text, toolVersion, targetFolder, "", "json");
            vendorConverter.ConversionProgress += OnConversionProgress;

            try
            {
                await Task.Run(() => vendorConverter.Analyze());
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                EnableDisableControls(true);
                OutputPanel.Visibility = Visibility.Collapsed;
                if (ex is InvalidDataException && ex.Message != null && ex.Message.Contains("Policy exceeds the maximum number"))
                {
                    MainWindow.ShowMessage(null, MessageTypes.Error, "ps@checkpoint.com", "mailto:ps@checkpoint.com", null, null, 
                        String.Format("{1}{0}{2}{0}{3}", Environment.NewLine, "SmartAnalyze is unable to analyze the provided policy.",
                                                "Reason: Policy exceeds the maximum number of supported policy layers.",
                                                "To assure the smooth conversion of your data, it is recommended to contact Check Point Professional Services by sending an e-mail to"));
                }
                else
                {
                    MainWindow.ShowMessage("Could not analyze process file.", "Message:\nModule:\nClass:\nMethod:", string.Format("{0}\n{1}\n{2}\n{3}", ex.Message, ex.Source, ex.TargetSite.ReflectedType.Name, ex.TargetSite.Name), MessageTypes.Error);
                }
                return;
            }

            UpdateProgress(90, "Exporting Check Point report ...");
            //if ((typeof(PanoramaConverter) != vendorConverter.GetType() && typeof(FortiGateConverter) != vendorConverter.GetType()))
            //{
            //    vendorConverter.ExportManagmentReport();
            //}
            UpdateProgress(100, "");

            vendorConverter.ConversionProgress -= OnConversionProgress;

            Mouse.OverrideCursor = null;
            EnableDisableControls(true);
            ProgressPanel.Visibility = Visibility.Collapsed;
            ResultsPanel.Visibility = Visibility.Visible;

            ShowResults(vendorConverter);

        }

        private void ShowResults(VendorConverter vendorConverter)
        {
            TotalAnalyzedPanel.Visibility = Visibility.Visible;
            OptimizationPotential.Visibility = Visibility.Visible;
            OrigConfigFilePanel.Visibility = Visibility.Visible;
            TotalRules.Text = $@"{vendorConverter.TotalRules} rules";
            OptPotential.Text = $@"{vendorConverter.OptimizationPotential.ToString("0.00")}%";
            OriginalFileLink.Tag = vendorConverter.VendorManagmentReportHtmlFile;
            //ConversionIssuesPanel.Visibility = (vendorConverter.ConversionIncidentCategoriesCount > 0) ? Visibility.Visible : Visibility.Collapsed;
            //ConvertedNatPolicyPanel.Visibility = ConvertNATConfiguration ? Visibility.Visible : Visibility.Collapsed;

            //ConfigurationFileLinesCount = string.Format(" ({0} lines)", convertedLinesCount);
            //ConvertedPolicyRulesCount = string.Format(" ({0} rules)", vendorConverter.RulesInConvertedPackage());
            //ConvertedOptimizedPolicyRulesCount = string.Format(" ({0} rules)", vendorConverter.RulesInConvertedOptimizedPackage());
            //ConvertedNATPolicyRulesCount = string.Format(" ({0} rules)", vendorConverter.RulesInNatLayer());
            //ConversionIssuesCount = string.Format("Found {0} conversion issues in {1} configuration lines", vendorConverter.ConversionIncidentCategoriesCount, vendorConverter.ConversionIncidentsCommandsCount);
            //ConvertingWarningsCount = "";
            //ConvertingErrorsCount = "";

            //switch (_supportedVendors.SelectedVendor)
            //{
            //    case Vendor.CiscoASA:
            //        CoversionIssuesPreviewPanel.Visibility = Visibility.Collapsed;
            //        ConvertedOptimizedPolicyPanel.Visibility = Visibility.Visible;
            //        RulebaseOptimizedScriptLink.Visibility = Visibility.Visible;
            //        break;

            //    case Vendor.FortiGate:
            //        CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
            //        ConvertedOptimizedPolicyPanel.Visibility = Visibility.Collapsed;
            //        RulebaseOptimizedScriptLink.Visibility = Visibility.Collapsed;

            //        FortiGateConverter fgConverter = (FortiGateConverter)vendorConverter;
            //        ConvertedPolicyRulesCount = (fgConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", fgConverter.RulesInConvertedPackage()) : " Check report.";
            //        ConvertedNATPolicyRulesCount = (fgConverter.RulesInNatLayer() != -1) ? string.Format(" ({0} rules)", fgConverter.RulesInNatLayer()) : " Check report.";
            //        ConvertingWarningsCount = (fgConverter.WarningsInConvertedPackage() != -1) ? string.Format(" ({0} warnings)", fgConverter.WarningsInConvertedPackage()) : " Check report.";
            //        ConvertingErrorsCount = (fgConverter.ErrorsInConvertedPackage() != -1) ? string.Format(" ({0} errors)", fgConverter.ErrorsInConvertedPackage()) : " Check report.";
            //        break;

            //    case Vendor.PaloAlto:
            //        CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
            //        ConvertedOptimizedPolicyPanel.Visibility = Visibility.Collapsed;
            //        RulebaseOptimizedScriptLink.Visibility = Visibility.Collapsed;
            //        PaloAltoConverter paConverter = (PaloAltoConverter)vendorConverter;
            //        ConvertedPolicyRulesCount = (paConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", paConverter.RulesInConvertedPackage()) : " Check report.";
            //        ConvertedNATPolicyRulesCount = (paConverter.RulesInNatLayer() != -1) ? string.Format(" ({0} rules)", paConverter.RulesInNatLayer()) : " Check report.";
            //        ConvertingWarningsCount = (paConverter.WarningsInConvertedPackage() != -1) ? string.Format(" ({0} warnings)", paConverter.WarningsInConvertedPackage()) : " Check report.";
            //        ConvertingErrorsCount = (paConverter.ErrorsInConvertedPackage() != -1) ? string.Format(" ({0} errors)", paConverter.ErrorsInConvertedPackage()) : " Check report.";
            //        break;
            //    case Vendor.PaloAltoPanorama:
            //        CoversionIssuesPreviewPanel.Visibility = Visibility.Visible;
            //        ConvertedOptimizedPolicyPanel.Visibility = Visibility.Collapsed;
            //        RulebaseOptimizedScriptLink.Visibility = Visibility.Collapsed;

            //        PanoramaConverter panoramaConverter = (PanoramaConverter)vendorConverter;
            //        ConvertedPolicyRulesCount = (panoramaConverter.RulesInConvertedPackage() != -1) ? string.Format(" ({0} rules)", panoramaConverter.RulesInConvertedPackage()) : " Check report.";
            //        ConvertedNATPolicyRulesCount = (panoramaConverter.RulesInNatLayer() != -1) ? string.Format(" ({0} rules)", panoramaConverter.RulesInNatLayer()) : " Check report.";
            //        ConvertingWarningsCount = (panoramaConverter.WarningsInConvertedPackage() != -1) ? string.Format(" ({0} warnings)", panoramaConverter.WarningsInConvertedPackage()) : " Check report.";
            //        ConvertingErrorsCount = (panoramaConverter.ErrorsInConvertedPackage() != -1) ? string.Format(" ({0} errors)", panoramaConverter.ErrorsInConvertedPackage()) : " Check report.";
            //        break;
            //    default:
            //        CoversionIssuesPreviewPanel.Visibility = Visibility.Collapsed;
            //        ConvertedOptimizedPolicyPanel.Visibility = Visibility.Collapsed;
            //        RulebaseOptimizedScriptLink.Visibility = Visibility.Collapsed;
            //        break;
            //}

            //OriginalFileLink.Tag = vendorConverter.VendorHtmlFile;
            //ConvertingWarningsLink.Tag = vendorConverter.WarningsHtmlFile;
            //ConvertingErrorsLink.Tag = vendorConverter.ErrorsHtmlFile;
            //ConvertedPolicyLink.Tag = vendorConverter.PolicyHtmlFile;
            //ConvertedOptimizedPolicyLink.Tag = vendorConverter.PolicyOptimizedHtmlFile;
            //ConvertedNatPolicyLink.Tag = vendorConverter.NatHtmlFile;
            //ObjectsScriptLink.Tag = vendorConverter.ObjectsScriptFile;
            //RulebaseScriptLink.Tag = vendorConverter.PolicyScriptFile;
            //RulebaseOptimizedScriptLink.Tag = vendorConverter.PolicyOptimizedScriptFile;
        }

        private void OnConversionProgress(int progress, string title)
        {
            Dispatcher.Invoke(() => UpdateProgress(progress, title));
        }

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
            Analyze.IsEnabled = enable;
        }

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
            DependencyProperty.Register("ConfigurationFileLabel", typeof(string), typeof(AnalyzeWindow), new PropertyMetadata(null));

        #endregion

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

        #endregion

        private void VendorSelector_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
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
                    break;
                case Vendor.PaloAlto:
                    ConfigurationFileLabel = SupportedVendors.PaloAltoConfigurationFileLabel;
                    break;
                case Vendor.PaloAltoPanorama:
                    ConfigurationFileLabel = SupportedVendors.PaloAltoPanoramaConfigurationFileLabel;
                    break;
            }
            ConfigFilePath.Text = SourceFolder;
            TargetFolderPath.Text = TargetFolder;
            OutputPanel.Visibility = Visibility.Collapsed;
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
                case Vendor.FirePower:
                    filter = "conf files (*.conf, *.txt)|*.conf; *.txt|All files (*.*)|*.*";
                    break;
                case Vendor.JuniperJunosOS:
                    filter = "xml files (*.xml)|*.xml";
                    break;
                case Vendor.JuniperScreenOS:
                    filter = "conf files (*.txt)|*.txt|All files (*.*)|*.*";
                    break;
                case Vendor.FortiGate:
                    filter = "conf files (*.conf)|*.conf | All files (*.*)|*.*";
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
                    MainWindow.ShowMessage("Could not read file from disk.\nOriginal error: " + ex.Message, MessageTypes.Error);
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
                    MainWindow.ShowMessage("Could not read file from disk.\nOriginal error: " + ex.Message, MessageTypes.Error);
                }
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
    }
}
