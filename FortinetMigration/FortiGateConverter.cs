using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using CommonUtils;
using MigrationBase;
using CheckPointObjects;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Net;
using System.Threading;

namespace FortiGateMigration
{
    public class FortiGateConverter : VendorConverter
    {
        public NewAnalizStatistic NewFortigateAnalizStatistic = new NewAnalizStatistic(0, 0);

        #region GUI params

        public bool OptimizeConf { get; set; } //check if Optimized configuration is requested
        public bool ConvertUserConf { get; set; } //check if User converion is requested
        public string LDAPAccoutUnit { get; set; } //read LDAP Account Unit Name for gethering users
        public string OutputFormat { get; set; } //json or text format for output file
        public bool CreateManagnetReport { get; set; }
        public bool ShowBashOptLink { get; set; } = true;

        #endregion

        #region Private Members

        private FortiGateParser _fortiGateParser;

        private HashSet<string> _vDomNames = new HashSet<string>();

        private List<string> _errorsList = new List<string>(); //storing conversion errors for config or each VDOM
        private List<string> _warningsList = new List<string>(); //storing conversion warnings for config or each VDOM
        
        private HashSet<string> _skippedNames = new HashSet<string>(); //if objects was skipped by error of validation here need to be placed his name
        
        private Dictionary<string, List<CheckPointObject>> _localMapperFgCp = new Dictionary<string, List<CheckPointObject>>(); //storing map of FG names to CheckPoint objects

        private Dictionary<string, List<CheckPoint_Host>> _interfacesMapperFgCp = new Dictionary<string, List<CheckPoint_Host>>(); //storing information about interfaces

        private Dictionary<string, string> _intfAliasNamesMapper = new Dictionary<string, string>(); //storing information about interfaces aliases

        private Dictionary<string, bool> _vipPortForwardEnabledMapper = new Dictionary<string, bool>(); //storing VIP which has port_forward

        private List<CheckPoint_Zone> _localIntrazonesList = new List<CheckPoint_Zone>(); //storing all Intrazones

        private Dictionary<string, FgInterface> _interfacesFgDict = new Dictionary<string, FgInterface>(); //storing Fortigate interfaces by their names

        private Dictionary<string, List<string>> _localFgVipGrpsDict = new Dictionary<string, List<string>>(); //storing Fortigate VIP groups with native members
        private Dictionary<string, List<string>> _localFgZoneIntfDict = new Dictionary<string, List<string>>(); //storing Fortigate Interfaces list for each Zone
        private Dictionary<string, List<FgStaticRoute>> _localFgRoutesDict = new Dictionary<string, List<FgStaticRoute>>(); //storing Fortigate static routes by Interface name
        private bool _localFgDynRoutesEnable = false; //indicate if Fortigate dynamic routing is enable

        private int _timeCutterCounter = 0; //postfix for Time objects
        private int _timeGroupCutterCounter = 0; //postfix for TimeGroup objects

        private int _warningsConvertedPackage = 0; //flag
        private int _errorsConvertedPackage = 0; //flag

        private int _rulesInConvertedPackage = 0; //counter
        private int _rulesInOptConvertedPackage = 0; //counter
        private int _rulesInNatLayer = 0; //counter

        /*
         * keys for mapping Fortigate objects names to CheckPoint objects
         */
        private const string FG_PREFIX_KEY_firewall_address = "firewall_address_";
        private const string FG_PREFIX_KEY_firewall_addrgrp = "firewall_addrgrp_";
        private const string FG_PREFIX_KEY_firewall_vip_extip = "firewall_vip_extip_";
        private const string FG_PREFIX_KEY_firewall_vip_mappedip = "firewall_vip_mappedip_";
        private const string FG_PREFIX_KEY_firewall_vip_grp = "firewall_vip_grp_";
        private const string FG_PREFIX_KEY_firewall_service_custom = "firewall_service_custom_";
        private const string FG_PREFIX_KEY_firewall_service_custom_vipe_ = "firewall_service_custom_VIPe_";
        private const string FG_PREFIX_KEY_firewall_service_custom_vipm_ = "firewall_service_custom_VIPm_";

        private const string FG_PREFIX_KEY_firewall_service_group = "firewall_service_group_";
        private const string FG_PREFIX_KEY_firewall_schedule_recurring = "firewall_schedule_recurring_";
        private const string FG_PREFIX_KEY_firewall_schedule_onetime = "firewall_schedule_onetime_";
        private const string FG_PREFIX_KEY_firewall_schedule_group = "firewall_schedule_group_";
        private const string FG_PREFIX_KEY_firewall_ippool = "firewall_ippool_";
        //private const string FG_PREFIX_KEY_firewall_ippool_source = "firewall_ippool_source_";
        private const string FG_PREFIX_KEY_system_zone = "system_zone_";
        private const string FG_PREFIX_KEY_system_zone_host = "system_zone_host_";

        private const string FG_PREFIX_KEY_user_group = "user_group_";

        #endregion

        //Initialization method... stupid method because you must to initialize CheckPoint Objects Store in convert. (from Cisco converter)
        public override void Initialize(VendorParser vendorParser, string vendorFilePath, string toolVersion, string targetFolder, string domainName, string outputFormat = "json")
        {
            _fortiGateParser = (FortiGateParser)vendorParser;
            if (_fortiGateParser == null)
            {
                throw new InvalidDataException("Unexpected!!!");
            }
            OutputFormat = outputFormat;
            base.Initialize(vendorParser, vendorFilePath, toolVersion, targetFolder, domainName, outputFormat);
        }

        protected override bool AddCheckPointObject(CheckPointObject cpObject)
        {
            if (base.AddCheckPointObject(cpObject))
            {
                string vendor = Vendor.FortiGate.ToString();
                if (!cpObject.Tags.Contains(vendor))
                {
                    cpObject.Tags.Add(vendor);
                }
            }

            return false;
        }

        #region Methods are used for reports

        //count of converted rules.
        // -1 is VDOM
        public override int RulesInConvertedPackage()
        {
            return _rulesInConvertedPackage;
        }

        //count of warnings of conversion
        // -1 if VDOM
        public int WarningsInConvertedPackage()
        {
            return _warningsConvertedPackage;
        }

        //count of errors of conversion
        // -1 if VDOM
        public int ErrorsInConvertedPackage()
        {
            return _errorsConvertedPackage;
        }

        public override int RulesInConvertedOptimizedPackage()
        {
            return _rulesInOptConvertedPackage;
        }

        //count of NAT rules
        // -1 if VDOM
        public override int RulesInNatLayer()
        {
            return _rulesInNatLayer;
        }

        public override void ExportConfigurationAsHtml()
        {
            //not used as we have vDOMs
        }

        public override void ExportPolicyPackagesAsHtml()
        {
            //not used as we have vDOMs
        }

        public void ExportManagmentReport(bool optimazed)
        {


            NewFortigateAnalizStatistic._unusedNetworkObjectsCount += _cpNetworks.Count * (optimazed ? -1 : 1);
            NewFortigateAnalizStatistic._unusedNetworkObjectsCount += _cpNetworkGroups.Count * (optimazed ? -1 : 1);
            NewFortigateAnalizStatistic._unusedNetworkObjectsCount += _cpRanges.Count * (optimazed ? -1 : 1);
            NewFortigateAnalizStatistic._unusedNetworkObjectsCount += _cpHosts.Count * (optimazed ? -1 : 1);

            NewFortigateAnalizStatistic._unusedServicesObjectsCount += _cpTcpServices.Count * (optimazed ? -1 : 1);
            NewFortigateAnalizStatistic._unusedServicesObjectsCount += _cpUdpServices.Count * (optimazed ? -1 : 1);
            NewFortigateAnalizStatistic._unusedServicesObjectsCount += _cpSctpServices.Count * (optimazed ? -1 : 1);
            NewFortigateAnalizStatistic._unusedServicesObjectsCount += _cpIcmpServices.Count * (optimazed ? -1 : 1);
            NewFortigateAnalizStatistic._unusedServicesObjectsCount += _cpDceRpcServices.Count * (optimazed ? -1 : 1);
            NewFortigateAnalizStatistic._unusedServicesObjectsCount += _cpOtherServices.Count * (optimazed ? -1 : 1);
            NewFortigateAnalizStatistic._unusedServicesObjectsCount += _cpServiceGroups.Count * (optimazed ? -1 : 1);

            if (optimazed)
            {
                NewFortigateAnalizStatistic.Flush();

            }
            else
            {
                

                int optimazed_count = 0;
                if (_cpPackages.Count > 1)
                {
                    int full = 0;
                    int all = 0;
                    int so_count = 0;
                    int se_count = 0;
                    int de_count = 0;
                    NewFortigateAnalizStatistic._nonServicesLoggingServicesRulesCount = 0;
                    NewFortigateAnalizStatistic._timesServicesRulesCount = 0;
                    NewFortigateAnalizStatistic._cleanupServicesRuleCount = 0;
                    NewFortigateAnalizStatistic._uncommentedServicesRulesCount = 0;
                    NewFortigateAnalizStatistic._disabledServicesRulesCount = 0;

                    foreach (var layer in _cpPackages[0].SubPolicies)
                    {
                        full += layer.Rules.Count();
                        foreach (var policy in layer.Rules)
                        {
                            bool any_fl = true;
                            if (policy.Destination.Count > 0 && policy.Destination.First().Name.Equals("Any"))
                            {
                                de_count++;
                                if (any_fl)
                                {
                                    all++;
                                    any_fl = false;
                                }

                            }
                            if (policy.Source.Count > 0 && policy.Source.First().Name.Equals("Any"))
                            {
                                so_count++;
                                if (any_fl)
                                {
                                    all++;
                                    any_fl = false;
                                }

                            }
                            if (policy.Service.Count > 0 && policy.Service.First().Name.Equals("Any"))
                            {
                                se_count++;
                                if (any_fl)
                                {
                                    all++;
                                    any_fl = false;
                                }

                            }
                            if (policy.Track == CheckPoint_Rule.TrackTypes.None)
                            {
                                NewFortigateAnalizStatistic._nonServicesLoggingServicesRulesCount++;
                            }
                            if (policy.Time.Count > 0)
                            {
                                NewFortigateAnalizStatistic._timesServicesRulesCount++;
                            }
                            if (policy.Name != null && policy.Name.Equals("Cleanup Rule"))
                            {
                                NewFortigateAnalizStatistic._cleanupServicesRuleCount++;
                            }
                            if (policy.Comments != "")
                            {
                                NewFortigateAnalizStatistic._uncommentedServicesRulesCount++;
                            }
                            if(policy.Enabled == false)
                            {
                                NewFortigateAnalizStatistic._disabledServicesRulesCount++;
                            }
                        }
                    }
                    foreach (var policy in _cpPackages[0].ParentLayer.Rules)
                    {
                        full += 1;
                        bool any_fl = true;
                        if (policy.Destination.Count > 0 && policy.Destination.First().Name.Equals("Any"))
                        {
                            de_count++;
                            if (any_fl)
                            {
                                all++;
                                any_fl = false;
                            }

                        }
                        if (policy.Source.Count > 0 && policy.Source.First().Name.Equals("Any"))
                        {
                            so_count++;
                            if (any_fl)
                            {
                                all++;
                                any_fl = false;
                            }

                        }
                        if (policy.Service.Count > 0 && policy.Service.First().Name.Equals("Any"))
                        {
                            se_count++;
                            if (any_fl)
                            {
                                all++;
                                any_fl = false;
                            }

                        }
                        if (policy.Track == CheckPoint_Rule.TrackTypes.None)
                        {
                            NewFortigateAnalizStatistic._nonServicesLoggingServicesRulesCount++;
                        }
                        if (policy.Time.Count > 0)
                        {
                            NewFortigateAnalizStatistic._timesServicesRulesCount++;
                        }
                        if (policy.Name != null && policy.Name.Equals("Cleanup Rule"))
                        {
                            NewFortigateAnalizStatistic._cleanupServicesRuleCount++;
                        }
                        if (policy.Comments != "")
                        {
                            NewFortigateAnalizStatistic._uncommentedServicesRulesCount++;
                        }
                        if (policy.Enabled == false)
                        {
                            NewFortigateAnalizStatistic._disabledServicesRulesCount++;
                        }
                    }
                    NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnyDestinationCount = de_count;
                    NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnyServiceCount = se_count;
                    NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnySourceCount = so_count;
                    NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnyCount = all;
                    NewFortigateAnalizStatistic._totalServicesRulesCount = full;

                    foreach (var sub_policy in _cpPackages[1].SubPolicies)
                    {
                        optimazed_count += sub_policy.Rules.Count();
                    }
                    optimazed_count += _cpPackages[1].ParentLayer.Rules.Count();
                    _rulesInOptConvertedPackage += optimazed_count;
                    NewFortigateAnalizStatistic._totalServicesRulesOptCount = optimazed_count;

                }
                if(_cpPackages.Count > 0)
                {
                    this.OptimizationPotential = RulesInConvertedPackage() > 0 ? ((RulesInConvertedPackage() - RulesInConvertedOptimizedPackage()) * 100 / (float)RulesInConvertedPackage()) : 0;
                    NewFortigateAnalizStatistic.CalculateCorrectAll(_cpNetworks, _cpNetworkGroups, _cpHosts, _cpRanges, _cpTcpServices, _cpUdpServices, _cpSctpServices, _cpIcmpServices, _cpDceRpcServices, _cpOtherServices, _cpServiceGroups);
                    ExportManagmentReport();
                    OptimizationPotential = -1;
                    TotalRules += NewFortigateAnalizStatistic._totalServicesRulesCount;
                }

            }
        }

        public override void ExportManagmentReport()
        {
            NewFortigateAnalizStatistic._totalFileRules += NewFortigateAnalizStatistic._totalServicesRulesCount;
            NewFortigateAnalizStatistic._totalFileRulesOpt += NewFortigateAnalizStatistic._totalServicesRulesOptCount;
            var potentialCount = NewFortigateAnalizStatistic._totalServicesRulesCount - NewFortigateAnalizStatistic._totalServicesRulesOptCount;
            var potentialPersent = NewFortigateAnalizStatistic._totalServicesRulesCount > 0 ? (potentialCount * 100 / (float)NewFortigateAnalizStatistic._totalServicesRulesCount) : 0;
            NewFortigateAnalizStatistic._fullrullPackageCount += NewFortigateAnalizStatistic._fullrullPackcount;
            NewFortigateAnalizStatistic._totalrullPackageCount += NewFortigateAnalizStatistic._totalServicesRulesCount;
            using (var file = new StreamWriter(VendorManagmentReportHtmlFile))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("<style>");
                file.WriteLine("  body { font-family: Arial; }");
                file.WriteLine("  .report_table { border-collapse: separate;border-spacing: 0px; font-family: Lucida Console;}");
                file.WriteLine("  td {padding: 5px; vertical-align: top}");
                file.WriteLine("  .line_number {background: lightgray;}");
                file.WriteLine("  .unhandeled {color: Fuchsia;}");
                file.WriteLine("  .notimportant {color: Gray;}");
                file.WriteLine("  .converterr {color: Red;}");
                file.WriteLine("  .convertinfo {color: Blue;}");
                file.WriteLine("  .err_title {color: Red;}");
                file.WriteLine("  .info_title {color: Blue;}");
                file.WriteLine("</style>");
                file.WriteLine("</head>");

                file.WriteLine("<body>");
                file.WriteLine("<h2>FortiGate managment report file</h2>");
                file.WriteLine("<h3>OBJECTS DATABASE</h3>");

                file.WriteLine("<table style='margin-bottom: 30px; background: rgb(250,250,250);'>");
                file.WriteLine($"   <tr><td style='font-size: 14px;'></td> <td style='font-size: 14px;'>STATUS</td> <td style='font-size: 14px;'>COUNT</td> <td style='font-size: 14px;'>PERCENT</td> <td style='font-size: 14px;'>REMEDIATION</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Total Network Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.TotalNetworkObjectsPercent, 100, 100)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._totalNetworkObjectsCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.TotalNetworkObjectsPercent}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Unused Network Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.UnusedNetworkObjectsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._unusedNetworkObjectsCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.UnusedNetworkObjectsPercent.ToString("F")}%</td> <td style='font-size: 14px;'>{(NewFortigateAnalizStatistic._unusedNetworkObjectsCount > 0 ? "Consider deleting these objects." : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Duplicate Network Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.DuplicateNetworkObjectsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._duplicateNetworkObjectsCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.DuplicateNetworkObjectsPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Nested Network Groups</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.NestedNetworkGroupsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._nestedNetworkGroupsCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.NestedNetworkGroupsPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine("</table>");

                file.WriteLine("<h3>SERVICES DATABASE</h3>");
                file.WriteLine("<table style='margin-bottom: 30px; background: rgb(250,250,250);'>");
                file.WriteLine($"   <tr><td style='font-size: 14px;'></td> <td style='font-size: 14px;'>STATUS</td> <td style='font-size: 14px;'>COUNT</td> <td style='font-size: 14px;'>PERCENT</td> <td style='font-size: 14px;'>REMEDIATION</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Total Services Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.TotalServicesObjectsPercent, 100, 100)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._totalServicesObjectsCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.TotalServicesObjectsPercent}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Unused Services Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.UnusedServicesObjectsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._unusedServicesObjectsCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.UnusedServicesObjectsPercent.ToString("F")}%</td> <td style='font-size: 14px;'>{(NewFortigateAnalizStatistic._unusedServicesObjectsCount > 0 ? "Consider deleting these objects." : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Duplicate Services Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.DuplicateServicesObjectsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._duplicateServicesObjectsCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.DuplicateServicesObjectsPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Nested Services Groups</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.NestedServicesGroupsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._nestedServicesGroupsCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.NestedServicesGroupsPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine("</table>");

                file.WriteLine("<h3>POLICY ANALYSIS</h3>");
                file.WriteLine("<table style='margin-bottom: 30px; background: rgb(250,250,250);'>");
                file.WriteLine($"   <tr><td style='font-size: 14px;'></td> <td style='font-size: 14px;'>STATUS</td> <td style='font-size: 14px;'>COUNT</td> <td style='font-size: 14px;'>PERCENT</td> <td style='font-size: 14px;'>REMEDIATION</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Total Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.TotalServicesRulesPercent, 100, 100)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._totalServicesRulesCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.TotalServicesRulesPercent}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Rules utilizing \"Any\"</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.RulesServicesutilizingServicesAnyPercent, 5, 15)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnyCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.RulesServicesutilizingServicesAnyPercent.ToString("F")}%</td> <td style='font-size: 14px;'>- ANY in Source: {NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnySourceCount}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'>- ANY in Destination: {NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnyDestinationCount} </td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'>- ANY in Service: {NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnyServiceCount}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Disabled Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.DisabledServicesRulesPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._disabledServicesRulesCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.DisabledServicesRulesPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td> {(NewFortigateAnalizStatistic._disabledServicesRulesCount > 0 ? "Check if rules are required." : "")}</tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Times Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.TimesServicesRulesPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._timesServicesRulesCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.TimesServicesRulesPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Non Logging Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.NonServicesLoggingServicesRulesPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._nonServicesLoggingServicesRulesCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.NonServicesLoggingServicesRulesPercent.ToString("F")}%</td> <td style='font-size: 14px;'> {(NewFortigateAnalizStatistic._nonServicesLoggingServicesRulesCount > 0 ? "Enable logging for these rules for better tracking and change management." : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Cleanup Rule</td> <td style='font-size: 14px;'>{(NewFortigateAnalizStatistic._cleanupServicesRuleCount > 0 ? HtmlGoodImageTagManagerReport : HtmlSeriosImageTagManagerReport)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._cleanupServicesRuleCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.CleanupServicesRulePercent.ToString("F")}%</td> <td style='font-size: 14px;'>{(NewFortigateAnalizStatistic._cleanupServicesRuleCount > 0 ? "Found" : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Uncommented Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewFortigateAnalizStatistic.UncommentedServicesRulesPercent, 25, 100)}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic._uncommentedServicesRulesCount}</td> <td style='font-size: 14px;'>{NewFortigateAnalizStatistic.UncommentedServicesRulesPercent.ToString("F")}%</td> <td style='font-size: 14px;'>{(NewFortigateAnalizStatistic._uncommentedServicesRulesCount > 0 ? "Comment rules for better tracking and change management compliance." : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Optimization Potential</td> <td style='font-size: 14px;'>{(potentialCount > 0 ? HtmlGoodImageTagManagerReport : HtmlAttentionImageTagManagerReport)}</td> <td style='font-size: 14px;'>{potentialCount}</td> <td style='font-size: 14px;'>{(potentialCount > 0 ? potentialPersent : 0).ToString("F")}%</td> <td style='font-size: 14px;'>{GetOptPhraze(potentialCount > 0 ? (int)potentialPersent : 0)}</td></tr>");
                file.WriteLine("</table>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        public void ExportPolicyPackagesAsHtmlConfig()
        {
            const string ruleIdPrefix = "rule_";

            foreach (CheckPoint_Package package in _cpPackages)
            {
                string filename = _targetFolder + "\\" + package.Name + ".html";

                using (var file = new StreamWriter(filename, false))
                {
                    var rulesWithConversionErrors = new Dictionary<string, CheckPoint_Rule>();
                    var rulesWithConversionInfos = new Dictionary<string, CheckPoint_Rule>();
                    var rulesWithInspection = new Dictionary<string, List<CheckPoint_Rule>>();

                    GeneratePackageHtmlReportHeaders(file, package.Name, package.ConversionIncidentType != ConversionIncidentType.None);

                    // Generate the report body
                    file.WriteLine("<table>");
                    file.WriteLine("   <tr>");
                    file.WriteLine("      <th colspan='2'>No.</th> <th>Name</th> <th>Source</th> <th>Destination</th> <th>Service</th> <th>Action</th> <th>Time</th> <th>Track</th> <th>Comments</th> <th>Conversion Comments</th>");
                    file.WriteLine("   </tr>");

                    int ruleNumber = 1;

                    foreach (CheckPoint_Rule rule in package.ParentLayer.Rules)
                    {
                        bool isSubPolicy = false;
                        string action = "";
                        string actionStyle = "";
                        var dummy = ConversionIncidentType.None;

                        switch (rule.Action)
                        {
                            case CheckPoint_Rule.ActionType.Accept:
                            case CheckPoint_Rule.ActionType.Drop:
                                action = rule.Action.ToString();
                                actionStyle = rule.Action.ToString().ToLower();
                                break;

                            case CheckPoint_Rule.ActionType.SubPolicy:
                                isSubPolicy = true;
                                action = "Sub-policy: " + rule.SubPolicyName;
                                actionStyle = "";
                                break;
                        }

                        string curParentRuleId = string.Format("{0}{1}", ruleIdPrefix, ruleNumber);

                        if (rule.Enabled)
                        {
                            file.WriteLine("  <tr class='parent_rule' id=\"" + curParentRuleId + "\">");
                            if (isSubPolicy)
                            {
                                file.WriteLine("      <td class='rule_number' colspan='2' onclick='toggleSubRules(this)'>" +
                                    string.Format(HtmlSubPolicyArrowImageTagFormat, curParentRuleId + "_img", HtmlDownArrowImageSourceData) + ruleNumber + "</td>");
                            }
                            else
                            {
                                file.WriteLine("      <td class='rule_number' colspan='2' style='padding-left:22px;'>" + ruleNumber + "</td>");
                            }
                        }
                        else
                        {
                            file.WriteLine("  <tr class='parent_rule_disabled' id=\"" + curParentRuleId + "\">");
                            if (isSubPolicy)
                            {
                                file.WriteLine("      <td class='rule_number' colspan='2' onclick='toggleSubRules(this)'>" +
                                    string.Format(HtmlSubPolicyArrowImageTagFormat, curParentRuleId + "_img", HtmlDownArrowImageSourceData) + ruleNumber + HtmlDisabledImageTag + "</td>");
                            }
                            else
                            {
                                file.WriteLine("      <td class='rule_number' colspan='2' style='padding-left:22px;'>" + ruleNumber + HtmlDisabledImageTag + "</td>");
                            }
                        }
                        file.WriteLine("      <td>" + rule.Name + "</td>");
                        file.WriteLine("      <td>" + RuleItemsList2Html(rule.Source, rule.SourceNegated, CheckPointObject.Any, ref dummy) + "</td>");
                        file.WriteLine("      <td>" + RuleItemsList2Html(rule.Destination, rule.DestinationNegated, CheckPointObject.Any, ref dummy) + "</td>");
                        file.WriteLine("      <td>" + RuleItemsList2Html(rule.Service, false, CheckPointObject.Any, ref dummy) + "</td>");
                        file.WriteLine("      <td class='" + actionStyle + "'>" + action + "</td>");
                        file.WriteLine("      <td>" + RuleItemsList2Html(rule.Time, false, CheckPointObject.Any, ref dummy) + "</td>");
                        file.WriteLine("      <td>" + rule.Track.ToString() + "</td>");
                        file.WriteLine("      <td>" + rule.Comments + "</td>");
                        file.WriteLine("      <td>" + rule.ConversionComments + "</td>");
                        file.WriteLine("  </tr>");

                        if (isSubPolicy)
                        {
                            foreach (CheckPoint_Layer subPolicy in package.SubPolicies)
                            {
                                int subRuleNumber = 1;

                                foreach (CheckPoint_Rule subRule in subPolicy.Rules)
                                {
                                    if (subRule.Layer == rule.SubPolicyName)
                                    {
                                        var ruleConversionIncidentType = ConversionIncidentType.None;
                                        bool isInspectedRule = !string.IsNullOrEmpty(subRule.Tag);
                                        string curRuleNumber = ruleNumber + "." + subRuleNumber;
                                        string curRuleId = ruleIdPrefix + curRuleNumber;

                                        if (subRule.Enabled)
                                        {
                                            file.WriteLine("  <tr id=\"" + curRuleId + "\">");
                                        }
                                        else
                                        {
                                            file.WriteLine("  <tr class='disabled_rule' id=\"" + curRuleId + "\">");
                                        }

                                        var sbCurRuleNumberColumnTag = new StringBuilder();
                                        sbCurRuleNumberColumnTag.Append("      <td class='indent_rule_number'/>");
                                        sbCurRuleNumberColumnTag.Append("      <td class='rule_number'>");
                                        sbCurRuleNumberColumnTag.Append(curRuleNumber);
                                        if (isInspectedRule)
                                        {
                                            sbCurRuleNumberColumnTag.Append(BuildInspectedRuleInfo(subRule.Tag));
                                        }
                                        if (subRule.ConversionIncidentType != ConversionIncidentType.None)
                                        {
                                            sbCurRuleNumberColumnTag.Append(BuildConversionIncidentLinkTag(subRule.ConvertedCommandId));
                                            ruleConversionIncidentType = subRule.ConversionIncidentType;
                                        }
                                        if (!subRule.Enabled)
                                        {
                                            sbCurRuleNumberColumnTag.Append(HtmlDisabledImageTag);
                                        }
                                        sbCurRuleNumberColumnTag.Append("</td>");
                                        file.WriteLine(sbCurRuleNumberColumnTag.ToString());

                                        file.WriteLine("      <td>" + subRule.Name + "</td>");
                                        file.WriteLine("      <td>" + RuleItemsList2Html(subRule.Source, subRule.SourceNegated, CheckPointObject.Any, ref ruleConversionIncidentType) + "</td>");
                                        file.WriteLine("      <td>" + RuleItemsList2Html(subRule.Destination, subRule.DestinationNegated, CheckPointObject.Any, ref ruleConversionIncidentType) + "</td>");
                                        file.WriteLine("      <td>" + RuleItemsList2Html(subRule.Service, false, CheckPointObject.Any, ref ruleConversionIncidentType) + "</td>");
                                        file.WriteLine("      <td class='" + subRule.Action.ToString().ToLower() + "'>" + subRule.Action.ToString() + "</td>");
                                        file.WriteLine("      <td>" + RuleItemsList2Html(subRule.Time, false, CheckPointObject.Any, ref ruleConversionIncidentType) + "</td>");
                                        file.WriteLine("      <td>" + subRule.Track.ToString() + "</td>");
                                        file.WriteLine("      <td class='comments'>" + subRule.Comments + "</td>");
                                        file.WriteLine("      <td class='comments'>" + subRule.ConversionComments + "</td>");
                                        file.WriteLine("  </tr>");

                                        subRuleNumber++;

                                        if (package.ConversionIncidentType != ConversionIncidentType.None && ruleConversionIncidentType != ConversionIncidentType.None)
                                        {
                                            if (ruleConversionIncidentType == ConversionIncidentType.ManualActionRequired)
                                            {
                                                rulesWithConversionErrors.Add(curRuleId, subRule);
                                            }
                                            else
                                            {
                                                rulesWithConversionInfos.Add(curRuleId, subRule);
                                            }
                                        }

                                        if (isInspectedRule)
                                        {
                                            string[] fortiClassMapNames = subRule.Tag.Split(',');   // there may be several class-maps matching the same fw rule...
                                            subRule.Tag = curRuleId;   // replace class-map name (it is now the key of this dic) by curRuleId...

                                            foreach (var classMapName in fortiClassMapNames)
                                            {
                                                if (!rulesWithInspection.ContainsKey(classMapName))
                                                {
                                                    var inspectedRules = new List<CheckPoint_Rule>();
                                                    rulesWithInspection.Add(classMapName, inspectedRules);
                                                }
                                                rulesWithInspection[classMapName].Add(subRule);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        ruleNumber++;
                    }

                    file.WriteLine("</table>");

                    if (rulesWithConversionErrors.Count > 0 || rulesWithConversionInfos.Count > 0 || rulesWithInspection.Count > 0)
                    {
                        file.WriteLine("<div id=\"PolicyConversionIncidents\" style='margin-left: 20px;'><h2>Policy Conversion Issues</h2></div>");
                    }

                    // Generate the errors report
                    if (rulesWithConversionErrors.Count > 0)
                    {
                        file.WriteLine("<script>");
                        file.WriteLine("   errorsCounter = " + rulesWithConversionErrors.Count + ";");
                        file.WriteLine("</script>");

                        file.WriteLine("<div id=\"PolicyConversionErrors\" style='margin-left: 20px;'><h3>Conversion Errors</h3></div>");
                        file.WriteLine("<table style='background-color: rgb(255,255,150);'>");
                        file.WriteLine("   <tr>");
                        file.WriteLine("      <th class='errors_header'>No.</th> <th class='errors_header'>Name</th> <th class='errors_header'>Source</th> <th class='errors_header'>Destination</th> <th class='errors_header'>Service</th> <th class='errors_header'>Action</th> <th class='errors_header'>Time</th> <th class='errors_header'>Track</th> <th class='errors_header'>Comments</th> <th class='errors_header'>Conversion Comments</th>");
                        file.WriteLine("   </tr>");

                        foreach (var ruleEntry in rulesWithConversionErrors)
                        {
                            var dummy = ConversionIncidentType.None;

                            if (ruleEntry.Value.Enabled)
                            {
                                file.WriteLine("  <tr>");
                            }
                            else
                            {
                                file.WriteLine("  <tr class='disabled_rule'>");
                            }

                            var sbCurRuleNumberColumnTag = new StringBuilder();
                            sbCurRuleNumberColumnTag.Append("      <td class='rule_number'>");
                            sbCurRuleNumberColumnTag.Append("<a href=\"#");
                            sbCurRuleNumberColumnTag.Append(ruleEntry.Key);
                            sbCurRuleNumberColumnTag.Append("\">");
                            sbCurRuleNumberColumnTag.Append(ruleEntry.Key.Replace(ruleIdPrefix, ""));
                            sbCurRuleNumberColumnTag.Append("</a>");
                            if (ruleEntry.Value.ConversionIncidentType != ConversionIncidentType.None)
                            {
                                sbCurRuleNumberColumnTag.Append(BuildConversionIncidentLinkTag(ruleEntry.Value.ConvertedCommandId));
                            }
                            if (!ruleEntry.Value.Enabled)
                            {
                                sbCurRuleNumberColumnTag.Append(HtmlDisabledImageTag);
                            }
                            sbCurRuleNumberColumnTag.Append("</td>");
                            file.WriteLine(sbCurRuleNumberColumnTag.ToString());

                            file.WriteLine("      <td>" + ruleEntry.Value.Name + "</td>");
                            file.WriteLine("      <td>" + RuleItemsList2Html(ruleEntry.Value.Source, ruleEntry.Value.SourceNegated, CheckPointObject.Any, ref dummy) + "</td>");
                            file.WriteLine("      <td>" + RuleItemsList2Html(ruleEntry.Value.Destination, ruleEntry.Value.DestinationNegated, CheckPointObject.Any, ref dummy) + "</td>");
                            file.WriteLine("      <td>" + RuleItemsList2Html(ruleEntry.Value.Service, false, CheckPointObject.Any, ref dummy) + "</td>");
                            file.WriteLine("      <td class='" + ruleEntry.Value.Action.ToString().ToLower() + "'>" + ruleEntry.Value.Action.ToString() + "</td>");
                            file.WriteLine("      <td>" + RuleItemsList2Html(ruleEntry.Value.Time, false, CheckPointObject.Any, ref dummy) + "</td>");
                            file.WriteLine("      <td>" + ruleEntry.Value.Track.ToString() + "</td>");
                            file.WriteLine("      <td class='comments'>" + ruleEntry.Value.Comments + "</td>");
                            file.WriteLine("      <td class='comments'>" + ruleEntry.Value.ConversionComments + "</td>");
                            file.WriteLine("  </tr>");
                        }

                        file.WriteLine("</table>");
                    }

                    if (rulesWithConversionInfos.Count > 0 || rulesWithInspection.Count > 0)
                    {
                        int counter = (rulesWithInspection.Count > 0) ? 1 : 0;
                        counter += rulesWithConversionInfos.Count;

                        file.WriteLine("<script>");
                        file.WriteLine("   infosCounter = " + counter + ";");
                        file.WriteLine("</script>");
                        file.WriteLine("<div id=\"PolicyConversionInfos\" style='margin-left: 20px;'><h3>Conversion Notifications</h3></div>");
                    }

                    // Generate the information report
                    if (rulesWithConversionInfos.Count > 0)
                    {
                        file.WriteLine("<table style='background-color: rgb(220,240,247);'>");
                        file.WriteLine("   <tr>");
                        file.WriteLine("      <th class='errors_header'>No.</th> <th class='errors_header'>Name</th> <th class='errors_header'>Source</th> <th class='errors_header'>Destination</th> <th class='errors_header'>Service</th> <th class='errors_header'>Action</th> <th class='errors_header'>Time</th> <th class='errors_header'>Track</th> <th class='errors_header'>Comments</th> <th class='errors_header'>Conversion Comments</th>");
                        file.WriteLine("   </tr>");

                        foreach (var ruleEntry in rulesWithConversionInfos)
                        {
                            var dummy = ConversionIncidentType.None;

                            if (ruleEntry.Value.Enabled)
                            {
                                file.WriteLine("  <tr>");
                            }
                            else
                            {
                                file.WriteLine("  <tr class='disabled_rule'>");
                            }

                            var sbCurRuleNumberColumnTag = new StringBuilder();
                            sbCurRuleNumberColumnTag.Append("      <td class='rule_number'>");
                            sbCurRuleNumberColumnTag.Append("<a href=\"#");
                            sbCurRuleNumberColumnTag.Append(ruleEntry.Key);
                            sbCurRuleNumberColumnTag.Append("\">");
                            sbCurRuleNumberColumnTag.Append(ruleEntry.Key.Replace(ruleIdPrefix, ""));
                            sbCurRuleNumberColumnTag.Append("</a>");
                            if (ruleEntry.Value.ConversionIncidentType != ConversionIncidentType.None)
                            {
                                sbCurRuleNumberColumnTag.Append(BuildConversionIncidentLinkTag(ruleEntry.Value.ConvertedCommandId));
                            }
                            if (!ruleEntry.Value.Enabled)
                            {
                                sbCurRuleNumberColumnTag.Append(HtmlDisabledImageTag);
                            }
                            sbCurRuleNumberColumnTag.Append("</td>");
                            file.WriteLine(sbCurRuleNumberColumnTag.ToString());

                            file.WriteLine("      <td>" + ruleEntry.Value.Name + "</td>");
                            file.WriteLine("      <td>" + RuleItemsList2Html(ruleEntry.Value.Source, ruleEntry.Value.SourceNegated, CheckPointObject.Any, ref dummy) + "</td>");
                            file.WriteLine("      <td>" + RuleItemsList2Html(ruleEntry.Value.Destination, ruleEntry.Value.DestinationNegated, CheckPointObject.Any, ref dummy) + "</td>");
                            file.WriteLine("      <td>" + RuleItemsList2Html(ruleEntry.Value.Service, false, CheckPointObject.Any, ref dummy) + "</td>");
                            file.WriteLine("      <td class='" + ruleEntry.Value.Action.ToString().ToLower() + "'>" + ruleEntry.Value.Action.ToString() + "</td>");
                            file.WriteLine("      <td>" + RuleItemsList2Html(ruleEntry.Value.Time, false, CheckPointObject.Any, ref dummy) + "</td>");
                            file.WriteLine("      <td>" + ruleEntry.Value.Track.ToString() + "</td>");
                            file.WriteLine("      <td class='comments'>" + ruleEntry.Value.Comments + "</td>");
                            file.WriteLine("      <td class='comments'>" + ruleEntry.Value.ConversionComments + "</td>");
                            file.WriteLine("  </tr>");
                        }

                        file.WriteLine("</table>");
                    }

                    file.WriteLine("</body>");
                    file.WriteLine("</html>");
                }
            }
        }

        public string BuildInspectedRuleInfo(string fortiClassMapName)
        {
            string inspectTooltip = "Rule traffic is affected by FortiGate inspect policy. [class-map objects: " + fortiClassMapName + "]";
            string htmlInspectedImageTag = string.Format(HtmlAlertImageTagFormat, inspectTooltip);
            return htmlInspectedImageTag;
        }

        //Catalog is Root file if VDOM exists
        public void CreateCatalogObjects()
        {
            string filename = this.ObjectsHtmlFile;

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VDOMs Objects for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vDomName in _vDomNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vDomName + "\\" + vDomName + "_objects.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vDomName + "\\" + vDomName + "_objects.html" + "\">" + "<h2>" + vDomName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vDomName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //Catalog is Root file if VDOM exists
        public void CreateCatalogPolicies()
        {
            string filename = this.PolicyHtmlFile;

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VDOMs Policies for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vDomName in _vDomNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vDomName + "\\" + vDomName + "_policy.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vDomName + "\\" + vDomName + "_policy.html" + "\">" + "<h2>" + vDomName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vDomName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //Catalog is Root file if VDOM exists
        public void CreateCatalogOptPolicies()
        {
            string filename = this.PolicyOptimizedHtmlFile;

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VDOMs Policies for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vDomName in _vDomNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vDomName + "\\" + vDomName + "_policy_opt.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vDomName + "\\" + vDomName + "_policy_opt.html" + "\">" + "<h2>" + vDomName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vDomName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //Catalog is Root file if VDOM exists
        public void CreateCatalogNATs()
        {
            string filename = this.NatHtmlFile;

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VDOMs NATs for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vDomName in _vDomNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vDomName + "\\" + vDomName + "_NAT.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vDomName + "\\" + vDomName + "_NAT.html" + "\">" + "<h2>" + vDomName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vDomName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //Catalog is Root file if VDOM exists
        public void CreateCatalogErrors()
        {
            string filename = this._targetFolder + "\\" + _vendorFileName + "_errors.html";

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VDOMs Errors for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vDomName in _vDomNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vDomName + "\\" + vDomName + "_errors.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vDomName + "\\" + vDomName + "_errors.html" + "\">" + "<h2>" + vDomName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vDomName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //Catalog is Root file if VDOM exists
        public void CreateCatalogWarnings()
        {
            string filename = this._targetFolder + "\\" + _vendorFileName + "_warnings.html";

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VDOMs Warnings for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vDomName in _vDomNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vDomName + "\\" + vDomName + "_warnings.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vDomName + "\\" + vDomName + "_warnings.html" + "\">" + "<h2>" + vDomName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vDomName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        public void CreateCatalogExportManagment()
        {
            string filename = this._targetFolder + "\\" + _vendorFileName + "_managment_report.html";

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of Device Group Warnings for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vDomName in _vDomNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vDomName + "\\" + vDomName + "_managment_report.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vDomName + "\\" + vDomName + "_managment_report.html" + "\">" + "<h2>" + vDomName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vDomName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //report about Errors
        public void CreateErrorsReport(string vDomName)
        {
            if (_errorsList.Count > 0)
            {
                // if (OutputFormat == "text") {
                string filename = _targetFolder + "\\" + vDomName + "_errors.html";

                using (var file = new StreamWriter(filename, false))
                {
                    file.WriteLine("<html>");
                    file.WriteLine("<head>");
                    file.WriteLine("</head>");
                    file.WriteLine("<body>");
                    file.WriteLine("<h1>List of " + vDomName + " Errors</h1>");
                    file.WriteLine("<table border='1' style='border-collapse: collapse;'>");
                    for (int i = 0; i < _errorsList.Count; i++)
                    {
                        file.WriteLine("<tr>");
                        file.WriteLine("<td>");
                        file.WriteLine(i);
                        file.WriteLine("</td>");
                        file.WriteLine("<td>");
                        file.WriteLine(_errorsList[i]);
                        file.WriteLine("</td>");
                        file.WriteLine("</tr>");
                    }
                    file.WriteLine("</table>");
                    file.WriteLine("</body>");
                    file.WriteLine("</html>");
                }
                /*}else
                {
                    string filename = _targetFolder + "\\" + vDomName + "_errors.json";

                    using (var file = new StreamWriter(filename, false))
                    {
                        FgJsonOutputReportsList fgJsonOutput = new FgJsonOutputReportsList();
                        fgJsonOutput.header = vDomName;
                        for (int i = 0; i < _errorsList.Count; i++)
                        {
                            fgJsonOutput.reports.Add(i, _errorsList[i]);
                        }
                        file.WriteLine(JsonConvert.SerializeObject(fgJsonOutput, Formatting.Indented));
                    }

                }*/
            }
        }

        //report about Warnings
        public void CreateWarningsReport(string vDomName)
        {
            if (_errorsList.Count > 0)
            {
                string filename = _targetFolder + "\\" + vDomName + "_warnings.html";

                using (var file = new StreamWriter(filename, false))
                {
                    file.WriteLine("<html>");
                    file.WriteLine("<head>");
                    file.WriteLine("</head>");
                    file.WriteLine("<body>");
                    file.WriteLine("<h1>List of " + vDomName + " Warnings</h1>");
                    file.WriteLine("<table border='1' style='border-collapse: collapse;'>");
                    for (int i = 0; i < _warningsList.Count; i++)
                    {
                        file.WriteLine("<tr>");
                        file.WriteLine("<td>");
                        file.WriteLine(i);
                        file.WriteLine("</td>");
                        file.WriteLine("<td>");
                        file.WriteLine(_warningsList[i]);
                        file.WriteLine("</td>");
                        file.WriteLine("</tr>");
                    }
                    file.WriteLine("</table>");
                    file.WriteLine("</body>");
                    file.WriteLine("</html>");
                }
            }
        }

        #endregion

        #region Converter

        //MAIN method to convert configuration file.
        public override Dictionary<string, int> Convert(bool convertNat)
        {
            string targetFileNameMain = _vendorFileName;
            string targetFolderMain = _targetFolder;

            if (IsConsoleRunning)
                Progress = new ProgressBar();

            LDAP_Account_Unit = LDAPAccoutUnit.Trim();

            if (IsConsoleRunning)
                Progress.SetProgress(5);

            bool isVDom = ConvertVDom(targetFolderMain, _fortiGateParser.FgCommandsList, convertNat);

            if (!isVDom) //if configration file does not conatin any VDOM
            {
                InitSystemInterfaces(_fortiGateParser.FgCommandsList);
                ConvertConfig(targetFolderMain, targetFileNameMain, _fortiGateParser.FgCommandsList, convertNat);
            }
            else //if configuration file contains some VDOM then we can not count Errors, Warnings, Rules and NATs
            {
                //_warningsConvertedPackage = -1;
                //_errorsConvertedPackage = -1;
                _rulesInConvertedPackage = -1;
                _rulesInNatLayer = -1;
                CleanCheckPointObjectsLists();
            }

            if (IsConsoleRunning)
            {
                Console.WriteLine("Optimizing Firewall rulebase ...");
                Progress.SetProgress(72);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(70, "Optimizing Firewall rulebase ...");

            if (IsConsoleRunning)
            {
                Console.WriteLine("Generating CLI scripts ...");
                Progress.SetProgress(80);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(80, "Generating CLI scripts ...");

            ChangeTargetFolder(targetFolderMain, targetFileNameMain); // chaning target folder path to folder contains config file

            if (_vDomNames.Count > 0) // create HTML files which contain links to each report
            {
                CreateCatalogObjects();
                CreateCatalogNATs();
                CreateCatalogPolicies();
                CreateCatalogOptPolicies();
                CreateCatalogErrors();
                CreateCatalogWarnings();
            }

            VendorHtmlFile = _vendorFilePath;

            ObjectsScriptFile = _targetFolder;
            PolicyScriptFile = _targetFolder;

            if (IsConsoleRunning)
            {
                Progress.SetProgress(100);
                Progress.Dispose();
            }

            if (_vDomNames.Count > 0)
                ShowBashOptLink = false;

            return new Dictionary<string, int>() { { "errors", ErrorsInConvertedPackage() }, { "warnings", WarningsInConvertedPackage() } };
        }

        //Convertint VDOMs to each VDOM and then Convert each VDOM as simple Configuration
        public bool ConvertVDom(string targetFolderM, List<FgCommand> fgCommandsList, bool convertNat)
        {
            if (IsConsoleRunning)
            {
                Console.WriteLine("Checking if vdom is present...");
                Progress.SetProgress(10);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(10, "Checking if vdom is present...");

            bool isVDom = false;

            foreach (FgCommand fgCommand in fgCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommand;
                    if (fgCommandConfig.ObjectName.Equals("vdom"))
                    {
                        isVDom = true;

                        if (fgCommandConfig.SubCommandsList[0].GetType() == typeof(FgCommand_Edit))
                        {
                            FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandConfig.SubCommandsList[0];

                            string vdomName = fgCommandEdit.Table;

                            _vDomNames.Add(vdomName);

                            string targetFolderVDom = targetFolderM + "\\" + vdomName;

                            System.IO.Directory.CreateDirectory(targetFolderVDom);

                            ConvertConfig(targetFolderVDom, vdomName, fgCommandEdit.SubCommandsList, convertNat);
                        }
                    }

                    if (fgCommandConfig.ObjectName.Equals("global"))
                    {
                        InitSystemInterfaces(fgCommandConfig.SubCommandsList);
                    }
                }
            }

            return isVDom;
        }

        //Init system Interfaces which is Global
        public void InitSystemInterfaces(List<FgCommand> fgCommandsList)
        {
            if (IsConsoleRunning)
            {
                Console.WriteLine("Init system interfaces...");
                Progress.SetProgress(20);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(20, "Init system interfaces...");

            foreach (FgCommand fgCommand in fgCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommand;

                    if (fgCommandConfig.ObjectName.Equals("system interface"))
                    {
                        foreach (FgCommand fgCommandE in fgCommandConfig.SubCommandsList)
                        {
                            if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                            {
                                FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                                foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                                {
                                    if (fgCommandS.GetType() == typeof(FgCommand_Set))
                                    {
                                        FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                                        if (fgCommandSet.Field.Equals("ip"))
                                        {
                                            string[] ip = fgCommandSet.Value.Split(' ').ToArray();

                                            if (ip.Length > 0)
                                            {
                                                FgInterface fgInterface = new FgInterface();
                                                fgInterface.Name = fgCommandEdit.Table;
                                                fgInterface.Ip = ip[0];
                                                fgInterface.Network = IPNetwork.Parse(ip[0], ip[1]).Network.ToString();
                                                fgInterface.Mask = ip[1];

                                                _interfacesFgDict[fgInterface.Name] = fgInterface;

                                                CheckPoint_Host cpHost = new CheckPoint_Host();
                                                cpHost.Name = GetSafeName(fgCommandEdit.Table + "_intf");
                                                cpHost.IpAddress = ip[0];

                                                List<CheckPoint_Host> cpHostsList = null;

                                                if (_interfacesMapperFgCp.ContainsKey(fgCommandEdit.Table))
                                                {
                                                    cpHostsList = _interfacesMapperFgCp[fgCommandEdit.Table];
                                                }
                                                else
                                                {
                                                    cpHostsList = new List<CheckPoint_Host>();
                                                }

                                                cpHostsList.Add(cpHost);

                                                _warningsList.Add(cpHost.Name + " new host object was created.");

                                                _interfacesMapperFgCp[fgCommandEdit.Table] = cpHostsList;
                                            }
                                        }

                                        if (fgCommandSet.Field.Equals("alias"))
                                        {
                                            if (!_intfAliasNamesMapper.ContainsKey(fgCommandEdit.Table))
                                            {
                                                _intfAliasNamesMapper.Add(fgCommandEdit.Table, fgCommandSet.Value.Trim('"'));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }

        //converting full configuration file or part which is related to VDOM
        public void ConvertConfig(string targetFolderNew, string targetFileNameNew, List<FgCommand> fgCommandsList, bool convertNat)
        {
            if (IsConsoleRunning)
            {
                Console.WriteLine("Convert configuration for VDOM " + targetFileNameNew);
                Console.WriteLine("Convert configuration...");
                Progress.SetProgress(35);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(35, "Convert configuration...");
            if (IsConsoleRunning)
            {
                Console.WriteLine("Convert objects...");
                Progress.SetProgress(40);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(40, "Convert objects...");
            _cpObjects.Initialize();   // must be first!!!
            CleanCheckPointObjectsLists(); // must be first!!!

            //change folder path for writing reports
            //if it is VDOM then each report will be placed to own folder
            //if it is w/o VDOM then report will be in the same folder as config file
            ChangeTargetFolder(targetFolderNew, targetFileNameNew);

            //Validate parsing
            _errorsList.AddRange(ValidateConversion(fgCommandsList));

            if (!OptimizeConf)
            {
                foreach (string fgInterface in _interfacesMapperFgCp.Keys)
                {
                    List<CheckPoint_Host> cpHostsList = _interfacesMapperFgCp[fgInterface];
                    foreach (CheckPoint_Host cpHost in cpHostsList)
                    {
                        AddCheckPointObject(cpHost);
                    }
                }
            }

            //Check if string of configuration section is related to FG Object
            foreach (FgCommand fgCommand in fgCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommand;

                    if (fgCommandConfig.ObjectName.Equals("firewall address"))
                    {
                        Add_ConfigFirewallAddress(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall vip"))
                    {
                        AddFirewallVip(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall vipgrp"))
                    {
                        AddFirewallVipGroups(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall addrgrp"))
                    {
                        Add_AddressGroups(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall service custom"))
                    {
                        AddFirewallServices(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall service group"))
                    {
                        AddFirewallServicesGroups(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall schedule recurring"))
                    {
                        AddFirewallSchedule(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall schedule onetime"))
                    {
                        AddFirewallScheduleOneTime(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall schedule group"))
                    {
                        AddFirewallScheduleGroups(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall ippool"))
                    {
                        AddFirewallIpPool(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("system zone"))
                    {
                        AddSystemZone(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router static"))
                    {
                        AddRoutesStatic(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router rip"))
                    {
                        CheckDynamicRoutesRip(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router ripng"))
                    {
                        CheckDynamicRoutesRipNg(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router ospf"))
                    {
                        CheckDynamicRoutesOspf(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router bgp"))
                    {
                        CheckDynamicRoutesBgp(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router isis"))
                    {
                        CheckDynamicRoutesIsis(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("user group") && ConvertUserConf)
                    {
                        AddUserGroup(fgCommandConfig.SubCommandsList);
                    }
                }
            }

            foreach (FgCommand fgCommand in fgCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommand;

                    if (fgCommandConfig.ObjectName.Equals("firewall policy"))
                    {
                        Add_Package(fgCommandConfig.SubCommandsList, convertNat, "Convert policy...");
                    }
                }
            }

            HashSet<string> cpUsedFirewallObjectNamesList = new HashSet<string>(); //set of names of used firewall objects
            HashSet<string> usedObjInFirewall = CreateUsedInPoliciesObjects(fgCommandsList);
            foreach (string key in _localMapperFgCp.Keys)
            {
                if (key.StartsWith(FG_PREFIX_KEY_user_group)) //already added because Access_Roles are added always
                {
                    continue;
                }

                List<CheckPointObject> cpObjectsList = _localMapperFgCp[key];
                foreach (CheckPointObject cpObject in cpObjectsList)
                {
                    if (!OptimizeConf) //adding objects if Optimized configuration is not required
                        AddCheckPointObject(cpObject);
                    else               //if optimized mode is enabled
                    {
                        foreach (string objectName in usedObjInFirewall)
                        {
                            if (cpObject.Name.Contains(objectName))
                            {
                                if (cpObject.GetType() == typeof(CheckPoint_NetworkGroup))
                                {
                                    CheckPoint_NetworkGroup networkGroup = (CheckPoint_NetworkGroup)cpObject;
                                    foreach (string firewallObject in networkGroup.Members)
                                    {
                                        if (!_skippedNames.Contains(firewallObject))
                                            cpUsedFirewallObjectNamesList.Add(firewallObject);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            //add domains opt
            if (OptimizeConf)
            { //adding objects if Optimized configuration is required
                foreach (string key in _localMapperFgCp.Keys)
                {
                    if (key.StartsWith(FG_PREFIX_KEY_user_group)) //already added because Access_Roles are added always
                    {
                        continue;
                    }

                    List<CheckPointObject> cpObjectsList = _localMapperFgCp[key];
                    foreach (CheckPointObject cpObject in cpObjectsList)
                    {
                        foreach (string firewallObjectName in cpUsedFirewallObjectNamesList)
                        {
                            string firewallObjectCorrectName = firewallObjectName.StartsWith(".") ? firewallObjectName.Substring(1) : firewallObjectName;
                            if (key.Replace(" ", "_").Contains(firewallObjectCorrectName.Replace(" ", "_")))
                                AddCheckPointObject(cpObject);
                        }
                    }
                }
            }

            if(_cpPackages.Count > 0)
            {
                Add_Optimized_Package();
                foreach (var sub_policy in _cpPackages[1].SubPolicies)
                {
                    _rulesInOptConvertedPackage += sub_policy.Rules.Select(x => x.ConversionComments).Where(x => x.Contains("Matched")).Count();
                }
            }

            CreateObjectsScript();
            CreateObjectsHtml();

            CreatePackagesScript();

            CreateErrorsReport(targetFileNameNew);
            CreateWarningsReport(targetFileNameNew);

            ExportNatLayerAsHtml();
            ExportPolicyPackagesAsHtmlConfig();

            _warningsConvertedPackage += _warningsList.Count;
            _errorsConvertedPackage += _errorsList.Count;

            CreateSmartConnector(true, false);      //cp_objects.json
            CreateSmartConnector(true, true);       //cp_objects_opt.json

            // to clean; must be the last!!!
            _cpObjects.ClearRepository();
            CleanSavedData();
        }

        //clean up all data in memmory to converting next VDOM configuration
        public void CleanSavedData()
        {
            _errorsList.Clear();
            _warningsList.Clear();
            _localMapperFgCp.Clear();
            _vipPortForwardEnabledMapper.Clear();
            _localIntrazonesList.Clear();
            _localFgVipGrpsDict.Clear();
            _localFgZoneIntfDict.Clear();
            _localFgRoutesDict.Clear();
            _localFgDynRoutesEnable = false;
            _timeCutterCounter = 0;
            _timeGroupCutterCounter = 0;
        }

        #endregion

        #region Analyzer

        //MAIN method to convert configuration file.
        public override float Analyze()
        {
            string targetFileNameMain = _vendorFileName;
            string targetFolderMain = _targetFolder;
            float optimization_potencial = -1;
            if (IsConsoleRunning)
                Progress = new ProgressBar();

            LDAP_Account_Unit = "";

            if (IsConsoleRunning)
                Progress.SetProgress(5);

            bool isVDom = AnalyzeVDom(targetFolderMain, _fortiGateParser.FgCommandsList);

            if (!isVDom) //if configration file does not conatin any VDOM
            {
                InitSystemInterfaces(_fortiGateParser.FgCommandsList);
                NewFortigateAnalizStatistic = new NewAnalizStatistic(NewFortigateAnalizStatistic._fullrullPackageCount, NewFortigateAnalizStatistic._totalrullPackageCount);
                AnalyzeConfig(targetFolderMain, targetFileNameMain, _fortiGateParser.FgCommandsList, true, true);
                AnalyzeConfig(targetFolderMain, targetFileNameMain, _fortiGateParser.FgCommandsList, true, false);
            }
            else //if configuration file contains some VDOM then we can not count Errors, Warnings, Rules and NATs
            {
                _rulesInConvertedPackage = -1;
                _rulesInNatLayer = -1;
                CleanCheckPointObjectsLists();
            }

            ChangeTargetFolder(targetFolderMain, targetFileNameMain); // chaning target folder path to folder contains config file

            if (_vDomNames.Count > 0) // create HTML files which contain links to each report
            {
               CreateCatalogExportManagment();
            }

            VendorHtmlFile = _vendorFilePath;

            ObjectsScriptFile = _targetFolder;
            PolicyScriptFile = _targetFolder;

            if (IsConsoleRunning)
            {
                Progress.SetProgress(100);
                Progress.Dispose();
            }
            OptimizationPotential = NewFortigateAnalizStatistic._totalFileRules > 0 ? ((NewFortigateAnalizStatistic._totalFileRules - NewFortigateAnalizStatistic._totalFileRulesOpt) * 100 / (float)NewFortigateAnalizStatistic._totalFileRules) : 0;
            return optimization_potencial;
        }

        //Convertint VDOMs to each VDOM and then Convert each VDOM as simple Configuration
        public bool AnalyzeVDom(string targetFolderM, List<FgCommand> fgCommandsList)
        {
            if (IsConsoleRunning)
            {
                Console.WriteLine("Checking if vdom is present...");
                Progress.SetProgress(10);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(10, "Checking if vdom is present...");

            bool isVDom = false;

            foreach (FgCommand fgCommand in fgCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommand;
                    if (fgCommandConfig.ObjectName.Equals("vdom"))
                    {
                        isVDom = true;

                        if (fgCommandConfig.SubCommandsList[0].GetType() == typeof(FgCommand_Edit))
                        {
                            FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandConfig.SubCommandsList[0];

                            string vdomName = fgCommandEdit.Table;

                            _vDomNames.Add(vdomName);

                            string targetFolderVDom = targetFolderM + "\\" + vdomName;

                            System.IO.Directory.CreateDirectory(targetFolderVDom);
                            NewFortigateAnalizStatistic = new NewAnalizStatistic(NewFortigateAnalizStatistic._fullrullPackageCount, NewFortigateAnalizStatistic._totalrullPackageCount);
                            AnalyzeConfig(targetFolderVDom, vdomName, fgCommandEdit.SubCommandsList, true, true);
                            AnalyzeConfig(targetFolderVDom, vdomName, fgCommandEdit.SubCommandsList, true, false);

                        }
                    }

                    if (fgCommandConfig.ObjectName.Equals("global") && isVDom)
                    {
                        InitSystemInterfaces(fgCommandConfig.SubCommandsList);
                    }
                }
            }

            return isVDom;
        }

        public void AnalyzeConfig(string targetFolderNew, string targetFileNameNew, List<FgCommand> fgCommandsList, bool convertNat, bool isOpt)
        {
            OptimizeConf = isOpt;

            _cpObjects.Initialize();   // must be first!!!
            CleanCheckPointObjectsLists(); // must be first!!!


            //change folder path for writing reports
            //if it is VDOM then each report will be placed to own folder
            //if it is w/o VDOM then report will be in the same folder as config file
            ChangeTargetFolder(targetFolderNew, targetFileNameNew);

            //Validate parsing
            _errorsList.AddRange(ValidateConversion(fgCommandsList));

            if (!OptimizeConf)
            {
                foreach (string fgInterface in _interfacesMapperFgCp.Keys)
                {
                    List<CheckPoint_Host> cpHostsList = _interfacesMapperFgCp[fgInterface];
                    foreach (CheckPoint_Host cpHost in cpHostsList)
                    {
                        AddCheckPointObject(cpHost);
                    }
                }
            }

            //Check if string of configuration section is related to FG Object
            foreach (FgCommand fgCommand in fgCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommand;

                    if (fgCommandConfig.ObjectName.Equals("firewall address"))
                    {
                        Add_ConfigFirewallAddress(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall vip"))
                    {
                        AddFirewallVip(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall vipgrp"))
                    {
                        AddFirewallVipGroups(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall addrgrp"))
                    {
                        Add_AddressGroups(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall service custom"))
                    {
                        AddFirewallServices(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall service group"))
                    {
                        AddFirewallServicesGroups(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall schedule recurring"))
                    {
                        AddFirewallSchedule(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall schedule onetime"))
                    {
                        AddFirewallScheduleOneTime(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall schedule group"))
                    {
                        AddFirewallScheduleGroups(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall ippool"))
                    {
                        AddFirewallIpPool(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("system zone"))
                    {
                        AddSystemZone(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router static"))
                    {
                        AddRoutesStatic(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router rip"))
                    {
                        CheckDynamicRoutesRip(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router ripng"))
                    {
                        CheckDynamicRoutesRipNg(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router ospf"))
                    {
                        CheckDynamicRoutesOspf(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router bgp"))
                    {
                        CheckDynamicRoutesBgp(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("router isis"))
                    {
                        CheckDynamicRoutesIsis(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("user group") && ConvertUserConf)
                    {
                        AddUserGroup(fgCommandConfig.SubCommandsList);
                    }
                }
            }

            foreach (FgCommand fgCommand in fgCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommand;

                    if (fgCommandConfig.ObjectName.Equals("firewall policy"))
                    {
                        Add_Package(fgCommandConfig.SubCommandsList, convertNat, "Analyze policy...");
                    }
                }
            }

            HashSet<string> cpUsedFirewallObjectNamesList = new HashSet<string>(); //set of names of used firewall objects
            HashSet<string> usedObjInFirewall = CreateUsedInPoliciesObjects(fgCommandsList);
            foreach (string key in _localMapperFgCp.Keys)
            {
                if (key.StartsWith(FG_PREFIX_KEY_user_group)) //already added because Access_Roles are added always
                {
                    continue;
                }

                List<CheckPointObject> cpObjectsList = _localMapperFgCp[key];
                foreach (CheckPointObject cpObject in cpObjectsList)
                {
                    if (!OptimizeConf) //adding objects if Optimized configuration is not required
                        AddCheckPointObject(cpObject);
                    else               //if optimized mode is enabled
                    {
                        foreach (string objectName in usedObjInFirewall)
                        {
                            if (cpObject.Name.Contains(objectName))
                            {
                                if (cpObject.GetType() == typeof(CheckPoint_NetworkGroup))
                                {
                                    CheckPoint_NetworkGroup networkGroup = (CheckPoint_NetworkGroup)cpObject;
                                    foreach (string firewallObject in networkGroup.Members)
                                    {
                                        if (!_skippedNames.Contains(firewallObject))
                                            cpUsedFirewallObjectNamesList.Add(firewallObject);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            //add domains opt
            if (OptimizeConf)
            { //adding objects if Optimized configuration is required
                foreach (string key in _localMapperFgCp.Keys)
                {
                    if (key.StartsWith(FG_PREFIX_KEY_user_group)) //already added because Access_Roles are added always
                    {
                        continue;
                    }
                    List<CheckPointObject> cpObjectsList = _localMapperFgCp[key];
                    foreach (CheckPointObject cpObject in cpObjectsList)
                    {
                        foreach (string firewallObjectName in cpUsedFirewallObjectNamesList)
                        {
                            string firewallObjectCorrectName = firewallObjectName.StartsWith(".") ? firewallObjectName.Substring(1) : firewallObjectName;
                            if (key.Replace(" ", "_").Contains(firewallObjectCorrectName.Replace(" ", "_")))
                                AddCheckPointObject(cpObject);
                        }
                    }
                }
            }

            if (_cpPackages.Count > 0)
            {
                Add_Optimized_Package();
            }

            ExportManagmentReport(OptimizeConf);
            // to clean; must be the last!!!
            _cpObjects.ClearRepository();
            CleanSavedData();
        }

        #endregion

        #region Parse Static Routes

        public void AddRoutesStatic(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                FgStaticRoute fgStaticRoute = new FgStaticRoute(
                    name: fgCommandEdit.Table.Trim('"').Trim(),
                    network: "0.0.0.0",
                    mask: "255.255.255.255",
                    gateway: null,
                    device: null);

                foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                {
                    if (fgCommandS.GetType() == typeof(FgCommand_Set))
                    {
                        FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                        if (fgCommandSet.Field.Equals("dst"))
                        {
                            string[] destination = fgCommandSet.Value.Trim('"').Trim().Split(new string[] { " " }, StringSplitOptions.None).ToArray();

                            if (destination.Count() == 2)
                            {
                                fgStaticRoute.Network = destination[0];
                                fgStaticRoute.Mask = destination[1];
                            }
                        }
                        if (fgCommandSet.Field.Equals("gateway"))
                        {
                            fgStaticRoute.Gateway = fgCommandSet.Value.Trim('"').Trim();
                        }
                        if (fgCommandSet.Field.Equals("device"))
                        {
                            fgStaticRoute.Device = fgCommandSet.Value.Trim('"').Trim();
                        }
                    }
                }

                List<FgStaticRoute> routesList = null;

                if (fgStaticRoute.Device != null)
                {
                    if (_localFgRoutesDict.ContainsKey(fgStaticRoute.Device))
                    {
                        routesList = _localFgRoutesDict[fgStaticRoute.Device];
                    }
                    else
                    {
                        routesList = new List<FgStaticRoute>();
                    }

                    routesList.Add(fgStaticRoute);

                    _localFgRoutesDict[fgStaticRoute.Device] = routesList;
                }
            }
        }

        #endregion

        #region Parse Dynamic Route

        public void CheckDynamicRoutesRip(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandC in fgCommandsList)
            {
                if (fgCommandC.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommandC;
                    if (fgCommandConfig.ObjectName.Equals("interface"))
                    {
                        _localFgDynRoutesEnable = true;
                    }
                }
            }
        }

        public void CheckDynamicRoutesRipNg(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandC in fgCommandsList)
            {
                if (fgCommandC.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommandC;
                    if (fgCommandConfig.ObjectName.Equals("interface"))
                    {
                        _localFgDynRoutesEnable = true;
                    }
                }
            }
        }

        public void CheckDynamicRoutesOspf(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandS in fgCommandsList)
            {
                if (fgCommandS.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;
                    if (fgCommandSet.Field.Equals("router-id"))
                    {
                        _localFgDynRoutesEnable = true;
                    }
                }
            }
        }

        public void CheckDynamicRoutesBgp(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandC in fgCommandsList)
            {
                if (fgCommandC.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommandC;
                    if (fgCommandConfig.ObjectName.Equals("neighbor"))
                    {
                        _localFgDynRoutesEnable = true;
                    }
                }
            }
        }

        public void CheckDynamicRoutesIsis(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandC in fgCommandsList)
            {
                if (fgCommandC.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommandC;
                    if (fgCommandConfig.ObjectName.Equals("isis-interface"))
                    {
                        _localFgDynRoutesEnable = true;
                    }
                }
            }
        }

        #endregion

        #region Convert Services

        public void AddFirewallServices(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    if (fgCommandEdit.Table.Equals("webproxy"))
                    {
                        _errorsList.Add("FortiGate Service of type webproxy was not created.");
                        continue;
                    }

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                            if (fgCommandSet.Field.Equals("tcp-portrange"))
                            {
                                if (fgCommandSet.Value.Contains(" "))
                                {
                                    string[] portRanges = fgCommandSet.Value.Split(' ').ToArray();
                                    foreach (string portRange in portRanges)
                                    {
                                        AddTcpService(portRange, fgCommandEdit.Table);
                                    }
                                }
                                else
                                {
                                    AddTcpService(fgCommandSet.Value, fgCommandEdit.Table);
                                }
                            }

                            if (fgCommandSet.Field.Equals("udp-portrange"))
                            {
                                if (fgCommandSet.Value.Contains(" "))
                                {
                                    string[] portRanges = fgCommandSet.Value.Split(' ').ToArray();
                                    foreach (string portRange in portRanges)
                                    {
                                        AddUdpService(portRange, fgCommandEdit.Table);
                                    }
                                }
                                else
                                {
                                    AddUdpService(fgCommandSet.Value, fgCommandEdit.Table);
                                }
                            }

                            if (fgCommandSet.Field.Equals("sctp-portrange"))
                            {
                                if (fgCommandSet.Value.Contains(" "))
                                {
                                    string[] portRanges = fgCommandSet.Value.Split(' ').ToArray();
                                    foreach (string portRange in portRanges)
                                    {
                                        AddSctpService(portRange, fgCommandEdit.Table);
                                    }
                                }
                                else
                                {
                                    AddSctpService(fgCommandSet.Value, fgCommandEdit.Table);
                                }
                            }

                            if (fgCommandSet.Field.Equals("protocol") && fgCommandSet.Value.Equals("ICMP"))
                            {
                                AddIcmpService(fgCommandEdit);
                                break;
                            }

                            if (fgCommandSet.Field.Equals("protocol") && fgCommandSet.Value.Equals("IP"))
                            {
                                AddOtherService(fgCommandEdit);
                                break;
                            }
                        }
                    }
                }
            }
        }

        public void AddOtherService(FgCommand_Edit fgCommandEdit)
        {
            string protocolNumber = "";

            foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
            {
                if (fgCommandS.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                    if (fgCommandSet.Field.Equals("protocol-number"))
                    {
                        protocolNumber = fgCommandSet.Value;
                    }
                }
            }

            if (protocolNumber.Equals(""))
                return;

            bool isFound = false;
            string cpServiceName = _cpObjects.GetKnownServiceName("OTHER_" + protocolNumber, out isFound);

            CheckPointObject cpObj;

            if (isFound)
            {
                cpObj = _cpObjects.GetObject(cpServiceName);
            }
            else
            {
                CheckPoint_OtherService cpOtherService = new CheckPoint_OtherService();
                cpOtherService.Name = GetSafeName(fgCommandEdit.Table);
                cpOtherService.IpProtocol = protocolNumber;

                cpObj = cpOtherService;
            }

            AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_service_custom + fgCommandEdit.Table, cpObj);
        }

        public void AddIcmpService(FgCommand_Edit fgCommandEdit)
        {
            string type = "99";
            string code = "";

            foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
            {
                if (fgCommandS.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                    if (fgCommandSet.Field.Equals("icmptype"))
                    {
                        type = fgCommandSet.Value;
                    }

                    if (fgCommandSet.Field.Equals("icmpcode"))
                    {
                        code = fgCommandSet.Value;
                    }
                }
            }

            bool isFound = false;
            string cpServiceName = "";
            if (code.Equals(""))
            {
                cpServiceName = _cpObjects.GetKnownServiceName("ICMP_" + type, out isFound);
            }

            CheckPointObject cpObj;

            if (isFound)
            {
                cpObj = _cpObjects.GetObject(cpServiceName);
            }
            else
            {
                CheckPoint_IcmpService cpIcmpService = new CheckPoint_IcmpService();
                cpIcmpService.Name = GetSafeName(fgCommandEdit.Table);
                cpIcmpService.Type = type;
                if (!code.Equals(""))
                {
                    cpIcmpService.Code = code;
                }

                cpObj = cpIcmpService;
            }

            AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_service_custom + fgCommandEdit.Table, cpObj);
        }

        public void AddTcpService(string portRange, string nameEdit)
        {
            string dest;
            string src;
            if (portRange.Contains(":"))
            {
                dest = portRange.Split(':').ToArray()[0];
                src = portRange.Split(':').ToArray()[1];
            }
            else
            {
                dest = portRange;
                src = "";
            }

            if (src.StartsWith("0"))
            {
                src = "1" + src.Substring(1);
            }

            if (dest.StartsWith("0"))
            {
                dest = "1" + dest.Substring(1);
            }

            bool isFound;
            string cpServiceName = _cpObjects.GetKnownServiceName("TCP_" + dest, out isFound);

            CheckPointObject cpObj;

            if (isFound)
            {
                cpObj = _cpObjects.GetObject(cpServiceName);
            }
            else
            {
                CheckPoint_TcpService cpTcpService = new CheckPoint_TcpService();
                cpTcpService.Name = GetSafeName(nameEdit) + "-" + dest.ToString() + "-tcp";
                cpTcpService.Port = dest;
                if (!src.Equals(""))
                {
                    cpTcpService.SourcePort = src;
                }

                cpObj = cpTcpService;
            }

            AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_service_custom + nameEdit, cpObj);
        }

        public void AddUdpService(string portRange, string nameEdit)
        {
            string dest;
            string src;
            if (portRange.Contains(":"))
            {
                dest = portRange.Split(':').ToArray()[0];
                src = portRange.Split(':').ToArray()[1];
            }
            else
            {
                dest = portRange;
                src = "";
            }

            if (src.StartsWith("0"))
            {
                src = "1" + src.Substring(1);
            }

            if (dest.StartsWith("0"))
            {
                dest = "1" + dest.Substring(1);
            }

            bool isFound;
            string cpServiceName = _cpObjects.GetKnownServiceName("UDP_" + dest, out isFound);

            CheckPointObject cpObj;

            if (isFound)
            {
                cpObj = _cpObjects.GetObject(cpServiceName);
            }
            else
            {
                CheckPoint_UdpService cpUdpService = new CheckPoint_UdpService();
                cpUdpService.Name = GetSafeName(nameEdit) + "-" + dest.ToString() + "-udp";
                cpUdpService.Port = dest;
                if (!src.Equals(""))
                {
                    cpUdpService.SourcePort = src;
                }

                cpObj = cpUdpService;
            }

            AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_service_custom + nameEdit, cpObj);
        }

        public void AddSctpService(string portRange, string nameEdit)
        {
            string dest;
            string src;
            if (portRange.Contains(":"))
            {
                dest = portRange.Split(':').ToArray()[0];
                src = portRange.Split(':').ToArray()[1];
            }
            else
            {
                dest = portRange;
                src = "";
            }

            if (src.StartsWith("0"))
            {
                src = "1" + src.Substring(1);
            }

            if (dest.StartsWith("0"))
            {
                dest = "1" + dest.Substring(1);
            }

            bool isFound;
            string cpServiceName = _cpObjects.GetKnownServiceName("SCTP_" + dest, out isFound);

            CheckPointObject cpObj;

            if (isFound)
            {
                cpObj = _cpObjects.GetObject(cpServiceName);
            }
            else
            {
                CheckPoint_SctpService cpSctpService = new CheckPoint_SctpService();
                cpSctpService.Name = GetSafeName(nameEdit);
                cpSctpService.Port = dest;
                if (!src.Equals(""))
                {
                    cpSctpService.SourcePort = src;
                }

                cpObj = cpSctpService;
            }

            AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_service_custom + nameEdit, cpObj);
        }

        #endregion

        #region Convert Services Groups

        public void AddFirewallServicesGroups(List<FgCommand> fgCommandsList)
        {
            Dictionary<string, CheckPoint_ServiceGroup> checkingSrvGrps = new Dictionary<string, CheckPoint_ServiceGroup>();

            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    CheckPoint_ServiceGroup cpServiceGroup = new CheckPoint_ServiceGroup();
                    cpServiceGroup.Name = GetSafeName(fgCommandEdit.Table);

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;
                            if (fgCommandSet.Field.Equals("member"))
                            {
                                string[] members = fgCommandSet.Value.Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();
                                foreach (string member in members)
                                {
                                    string memberC = member.Trim('"');

                                    cpServiceGroup.Members.Add(memberC);
                                }
                            }

                            if (fgCommandSet.Field.Equals("comment") || fgCommandSet.Field.Equals("comments"))
                            {
                                cpServiceGroup.Comments = fgCommandSet.Value.Trim('"');
                            }
                        }
                    }

                    checkingSrvGrps.Add(fgCommandEdit.Table, cpServiceGroup);
                }
            }

            while (checkingSrvGrps.Keys.Count > 0)
            {
                AddFirewallServicesGroupsRecurs(checkingSrvGrps.Keys.First(), checkingSrvGrps);
            }
        }

        public void AddFirewallServicesGroupsRecurs(string cpSrvGrpName, Dictionary<string, CheckPoint_ServiceGroup> checkingSrvGrps)
        {
            List<string> errorsList = new List<string>();

            CheckPoint_ServiceGroup cpSrvGrp = checkingSrvGrps[cpSrvGrpName];

            checkingSrvGrps.Remove(cpSrvGrpName);

            CheckPoint_ServiceGroup cpSrvGrpAdd = new CheckPoint_ServiceGroup();

            cpSrvGrpAdd.Name = cpSrvGrp.Name;

            for (int i = 0; i < cpSrvGrp.Members.Count; i++)
            {
                string member = cpSrvGrp.Members[i];

                if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_service_custom + member))
                {
                    List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_service_custom + member];

                    if (list.Count > 0)
                    {
                        cpSrvGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                    }
                }
                else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_service_group + member))
                {
                    List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_service_group + member];
                    if (list.Count > 0)
                    {
                        cpSrvGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                    }
                }
                else if (checkingSrvGrps.ContainsKey(member))
                {
                    AddFirewallServicesGroupsRecurs(member, checkingSrvGrps);

                    cpSrvGrpAdd.Members.Add(member);
                }
                else
                {
                    errorsList.Add(cpSrvGrpAdd.Name + " service group " +
                        "can not been converted becuase it contains non-existing member: " + member);
                }

                if (checkingSrvGrps.ContainsKey(member))
                {
                    checkingSrvGrps.Remove(member);
                }
            }

            if (errorsList.Count == 0)
            {
                //AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_service_group + cpSrvGrpAdd.Name, cpSrvGrpAdd);
                AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_service_group + cpSrvGrpName, cpSrvGrpAdd);
            }
            else
            {
                _errorsList.AddRange(errorsList);
            }
        }

        #endregion

        #region Convert Schedules

        public void AddFirewallSchedule(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    if (fgCommandEdit.Table.Equals("always"))
                    {
                        if (!_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_schedule_recurring + "always"))
                        {
                            AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_schedule_recurring + "always", _cpObjects.GetObject(CheckPointObject.Any));
                        }
                        continue;
                    }

                    CheckPoint_Time cpTime = new CheckPoint_Time();

                    cpTime.Name = fgCommandEdit.Table;

                    cpTime.StartNow = true;
                    cpTime.EndNever = true;

                    string timeStart = null;
                    string timeEnd = null;

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                            if (fgCommandSet.Field.Equals("day"))
                            {
                                List<CheckPoint_Time.Weekdays> cpDays = new List<CheckPoint_Time.Weekdays>();
                                string[] days = fgCommandSet.Value.Split(' ');
                                foreach (string day in days)
                                {
                                    switch (day)
                                    {
                                        case "sunday":
                                            cpDays.Add(CheckPoint_Time.Weekdays.Sun);
                                            break;
                                        case "monday":
                                            cpDays.Add(CheckPoint_Time.Weekdays.Mon);
                                            break;
                                        case "tuesday":
                                            cpDays.Add(CheckPoint_Time.Weekdays.Tue);
                                            break;
                                        case "wednesday":
                                            cpDays.Add(CheckPoint_Time.Weekdays.Wed);
                                            break;
                                        case "thursday":
                                            cpDays.Add(CheckPoint_Time.Weekdays.Thu);
                                            break;
                                        case "friday":
                                            cpDays.Add(CheckPoint_Time.Weekdays.Fri);
                                            break;
                                        case "saturday":
                                            cpDays.Add(CheckPoint_Time.Weekdays.Sat);
                                            break;
                                    }
                                }
                                cpTime.RecurrenceWeekdays = cpDays;
                            }

                            if (fgCommandSet.Field.Equals("start"))
                            {
                                timeStart = fgCommandSet.Value;
                            }

                            if (fgCommandSet.Field.Equals("end"))
                            {
                                timeEnd = fgCommandSet.Value;
                            }

                            if (fgCommandSet.Field.Equals("comment") || fgCommandSet.Field.Equals("comments"))
                            {
                                cpTime.Comments = fgCommandSet.Value.Trim('"');
                            }
                        }
                    }

                    //...
                    if (timeStart != null || timeEnd != null)
                    {
                        if (timeStart == null)
                        {
                            timeStart = "00:00";
                        }
                        if (timeEnd == null)
                        {
                            timeEnd = "00:00";
                        }
                        if (TimeSpan.Parse(timeStart) <= TimeSpan.Parse(timeEnd))
                        {
                            cpTime.HoursRangesEnabled_1 = true;
                            cpTime.HoursRangesFrom_1 = timeStart;
                            cpTime.HoursRangesTo_1 = timeEnd;
                        }
                        else
                        {
                            cpTime.HoursRangesEnabled_1 = true;
                            cpTime.HoursRangesFrom_1 = timeStart;
                            cpTime.HoursRangesTo_1 = "23:59";

                            cpTime.HoursRangesEnabled_2 = true;
                            cpTime.HoursRangesFrom_2 = "00:00";
                            cpTime.HoursRangesTo_2 = timeEnd;
                        }
                    }

                    AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_schedule_recurring + fgCommandEdit.Table, cpTime);
                }
            }
        }

        public void AddFirewallScheduleOneTime(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    CheckPoint_Time cpTime = new CheckPoint_Time();

                    cpTime.Name = fgCommandEdit.Table;

                    cpTime.StartNow = false;
                    cpTime.EndNever = false;

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                            if (fgCommandSet.Field.Equals("start"))
                            {
                                DateTime date = DateTime.ParseExact(fgCommandSet.Value.Trim('"'), "HH:mm yyyy/MM/dd", System.Globalization.CultureInfo.InvariantCulture);

                                cpTime.StartDate = date.ToString("dd-MMM-yyyy", CultureInfo.InvariantCulture);
                                cpTime.StartTime = date.ToString("HH:mm");
                            }

                            if (fgCommandSet.Field.Equals("end"))
                            {
                                DateTime date = DateTime.ParseExact(fgCommandSet.Value.Trim('"'), "HH:mm yyyy/MM/dd", System.Globalization.CultureInfo.InvariantCulture);

                                cpTime.EndDate = date.ToString("dd-MMM-yyyy", CultureInfo.InvariantCulture);
                                cpTime.EndTime = date.ToString("HH:mm");
                            }

                            if (fgCommandSet.Field.Equals("comment") || fgCommandSet.Field.Equals("comments"))
                            {
                                cpTime.Comments = fgCommandSet.Value.Trim('"');
                            }
                        }
                    }

                    AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_schedule_onetime + fgCommandEdit.Table, cpTime);
                }
            }
        }

        #endregion

        #region Convert Schedules Groups

        public void AddFirewallScheduleGroups(List<FgCommand> fgCommandsList)
        {
            Dictionary<string, CheckPoint_TimeGroup> checkingTimeGrps = new Dictionary<string, CheckPoint_TimeGroup>();

            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    CheckPoint_TimeGroup cpTimeGroup = new CheckPoint_TimeGroup();
                    cpTimeGroup.Name = GetSafeName(fgCommandEdit.Table);

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;
                            if (fgCommandSet.Field.Equals("member"))
                            {
                                string[] members = fgCommandSet.Value.Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();
                                foreach (string member in members)
                                {
                                    string memberC = member.Trim('"');
                                    cpTimeGroup.Members.Add(memberC);
                                }
                            }

                            if (fgCommandSet.Field.Equals("comment") || fgCommandSet.Field.Equals("comments"))
                            {
                                cpTimeGroup.Comments = fgCommandSet.Value.Trim('"');
                            }
                        }
                    }

                    checkingTimeGrps.Add(fgCommandEdit.Table, cpTimeGroup);
                }
            }

            while (checkingTimeGrps.Keys.Count > 0)
            {
                AddFirewallScheduleGroupsRecurs(checkingTimeGrps.Keys.First(), checkingTimeGrps);
            }
        }

        public void AddFirewallScheduleGroupsRecurs(string cpTimeGrpName, Dictionary<string, CheckPoint_TimeGroup> checkingTimeGrps)
        {
            List<string> errorsList = new List<string>();

            CheckPoint_TimeGroup cpTimeGrp = checkingTimeGrps[cpTimeGrpName];

            checkingTimeGrps.Remove(cpTimeGrpName);

            CheckPoint_TimeGroup cpTimeGrpAdd = new CheckPoint_TimeGroup();

            cpTimeGrpAdd.Name = cpTimeGrp.Name;

            for (int i = 0; i < cpTimeGrp.Members.Count; i++)
            {
                string member = cpTimeGrp.Members[i];

                if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_schedule_recurring + member))
                {
                    List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_schedule_recurring + member];
                    if (list.Count > 0)
                    {
                        cpTimeGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                    }
                }
                else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_schedule_onetime + member))
                {
                    List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_schedule_onetime + member];
                    if (list.Count > 0)
                    {
                        cpTimeGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                    }
                }
                else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_schedule_group + member))
                {
                    List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_schedule_group + member];
                    if (list.Count > 0)
                    {
                        cpTimeGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                    }
                }
                else if (checkingTimeGrps.ContainsKey(member))
                {
                    AddFirewallScheduleGroupsRecurs(member, checkingTimeGrps);

                    cpTimeGrpAdd.Members.Add(member);
                }
                else
                {
                    errorsList.Add(cpTimeGrpAdd.Name + " schedule group " +
                            "can not been converted becuase it contains non-existing member: " + member);
                }

                if (checkingTimeGrps.ContainsKey(member))
                {
                    checkingTimeGrps.Remove(member);
                }
            }

            if (errorsList.Count == 0)
            {
                //AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_schedule_group + cpTimeGrp.Name, cpTimeGrpAdd);
                AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_schedule_group + cpTimeGrpName, cpTimeGrpAdd);
            }
            else
            {
                _errorsList.AddRange(errorsList);
            }
        }

        #endregion

        #region Convert IpPool

        public void AddFirewallIpPool(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    CheckPoint_Range cpRange = new CheckPoint_Range();
                    cpRange.Name = GetSafeName(fgCommandEdit.Table);
                    cpRange.RangeFrom = "";
                    cpRange.RangeTo = "";

                    CheckPoint_Range cpRangeSrc = new CheckPoint_Range();
                    cpRangeSrc.Name = GetSafeName(fgCommandEdit.Table);
                    cpRangeSrc.RangeFrom = "";
                    cpRangeSrc.RangeTo = "";

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                            switch (fgCommandSet.Field)
                            {
                                case "startip":
                                    cpRange.RangeFrom = fgCommandSet.Value;
                                    break;
                                case "endip":
                                    cpRange.RangeTo = fgCommandSet.Value;
                                    break;
                                case "source-startip":
                                    cpRangeSrc.RangeFrom = fgCommandSet.Value;
                                    break;
                                case "source-endip":
                                    cpRangeSrc.RangeTo = fgCommandSet.Value;
                                    break;
                            }
                        }
                    }

                    if (!string.IsNullOrEmpty(cpRange.RangeFrom) && !string.IsNullOrEmpty(cpRange.RangeTo))
                    {
                        AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_ippool + fgCommandEdit.Table, cpRange);
                    }

                    if (!string.IsNullOrEmpty(cpRangeSrc.RangeFrom) && !string.IsNullOrEmpty(cpRangeSrc.RangeTo))
                    {
                        //AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_ippool_source + fgCommandEdit.Table, cpRangeSrc);
                        AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_ippool + fgCommandEdit.Table, cpRangeSrc);
                    }
                }
            }
        }

        #endregion

        #region Convert System Zone

        public void AddSystemZone(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    CheckPoint_Zone cpZone = new CheckPoint_Zone();
                    cpZone.Name = GetSafeName(fgCommandEdit.Table);

                    bool isIntraZone = false;

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                            if (fgCommandSet.Field.Equals("intrazone") && fgCommandSet.Value.Equals("allow"))
                            {
                                isIntraZone = true;
                            }

                            if (fgCommandSet.Field.Equals("interface"))
                            {
                                string[] zoneInterfaces = fgCommandSet.Value.Trim('"').Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();

                                _localFgZoneIntfDict[fgCommandEdit.Table] = zoneInterfaces.ToList();

                                foreach (string zoneInterface in zoneInterfaces)
                                {
                                    if (_interfacesMapperFgCp.ContainsKey(zoneInterface))
                                    {
                                        List<CheckPoint_Host> cpObjsList = _interfacesMapperFgCp[zoneInterface];
                                        foreach (CheckPoint_Host cpObj in cpObjsList)
                                        {
                                            AddCpObjectToLocalMapper(FG_PREFIX_KEY_system_zone_host + fgCommandEdit.Table, cpObj);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (isIntraZone)
                    {
                        _localIntrazonesList.Add(cpZone);
                    }

                    AddCpObjectToLocalMapper(FG_PREFIX_KEY_system_zone + fgCommandEdit.Table, cpZone);
                }
            }
        }

        #endregion

        #region Convert Users Groups

        public void AddUserGroup(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    bool isFSSOService = false;

                    string membersStr = "";

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                            if (fgCommandSet.Field.Equals("group-type") && fgCommandSet.Value.Equals("fsso-service"))
                            {
                                isFSSOService = true;
                            }

                            if (fgCommandSet.Field.Equals("member"))
                            {
                                membersStr = fgCommandSet.Value.Trim('"');
                            }
                        }
                    }

                    if (isFSSOService)
                    {
                        CheckPoint_AccessRole cpAccessRole = new CheckPoint_AccessRole();
                        cpAccessRole.Name = GetSafeName(fgCommandEdit.Table);

                        string[] members = membersStr.Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();
                        foreach (string member in members)
                        {
                            if (string.IsNullOrWhiteSpace(member))
                                continue;

                            if (member.Contains(","))
                            {
                                List<string> values = new List<string>();
                                member.Split(new string[] { "," }, StringSplitOptions.None).ToList().ForEach(x => values.Add(x.Trim().Substring(x.IndexOf("=") + 1)));

                                AccessRoleUser arUser = new AccessRoleUser();
                                arUser.Name = values[0];
                                arUser.BaseDn = member;

                                cpAccessRole.Users.Add(arUser);
                            }
                            else if (member.Contains("\\"))
                            {
                                AccessRoleUser arUser = new AccessRoleUser();
                                arUser.Name = member.Substring(member.IndexOf("\\") + 1);

                                cpAccessRole.Users.Add(arUser);
                            }
                            else
                            {
                                AccessRoleUser arUser = new AccessRoleUser();
                                arUser.Name = member;

                                cpAccessRole.Users.Add(arUser);
                            }
                        }

                        if (cpAccessRole.Users.Count > 0)
                        {
                            AddCpObjectToLocalMapper(FG_PREFIX_KEY_user_group + fgCommandEdit.Table, cpAccessRole);
                            AddCheckPointObject(cpAccessRole);
                        }
                    }
                }
            }
        }

        #endregion

        #region Convert Addresses

        public void Add_ConfigFirewallAddress(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommand in fgCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommand;

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            CheckPointObject cpObject = null;

                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                            if (fgCommandSet.Field.Equals("type"))
                            {
                                switch (fgCommandSet.Value)
                                {
                                    case "fqdn":
                                        cpObject = Add_Domain(fgCommandEdit, false);
                                        break;
                                    case "wildcard-fqdn":
                                        cpObject = Add_Domain(fgCommandEdit, true);
                                        break;
                                    case "iprange":
                                        cpObject = Add_IpRange(fgCommandEdit);
                                        break;
                                }
                            }
                            else if (fgCommandSet.Field.Equals("subnet"))
                            {
                                cpObject = Add_Subnet(fgCommandEdit);
                            }

                            if (cpObject != null)
                            {
                                AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_address + fgCommandEdit.Table, cpObject);
                            }
                        }
                    }
                }
            }
        }

        public CheckPointObject Add_Domain(FgCommand_Edit fgCommandEdit, bool isSubDomain)
        {
            CheckPoint_Domain cpDomain = new CheckPoint_Domain();
            cpDomain.IsSubDomain = isSubDomain;

            string comment = "";

            foreach (FgCommand fgCommand in fgCommandEdit.SubCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommand;
                    if (fgCommandSet.Field.Equals("fqdn"))
                    {
                        cpDomain.Name = GetSafeName("." + fgCommandSet.Value);
                    }
                    else if (fgCommandSet.Field.Equals("wildcard-fqdn"))
                    {
                        int indStar = fgCommandSet.Value.Trim('"').LastIndexOf("*");

                        string subDomain = fgCommandSet.Value.Trim('"').Substring(indStar + 1);
                        if (!subDomain.StartsWith("."))
                        {
                            subDomain = "." + subDomain;
                        }

                        cpDomain.Name = GetSafeName(subDomain);
                    }

                    if (fgCommandSet.Field.Equals("comment") || fgCommandSet.Field.Equals("comments"))
                    {
                        comment = fgCommandSet.Value.Trim('"');
                    }
                }
            }

            cpDomain.Comments = comment;

            return cpDomain;
        }

        public CheckPointObject Add_IpRange(FgCommand_Edit fgCommandEdit)
        {
            CheckPoint_Range cpRange = new CheckPoint_Range();
            cpRange.Name = GetSafeName(fgCommandEdit.Table);

            string comment = "";

            foreach (FgCommand fgCommand in fgCommandEdit.SubCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommand;
                    if (fgCommandSet.Field.Equals("start-ip"))
                    {
                        cpRange.RangeFrom = fgCommandSet.Value;
                    }
                    if (fgCommandSet.Field.Equals("end-ip"))
                    {
                        cpRange.RangeTo = fgCommandSet.Value;
                    }
                    if (fgCommandSet.Field.Equals("comment") || fgCommandSet.Field.Equals("comments"))
                    {
                        comment = fgCommandSet.Value.Trim('"');
                    }
                }
            }

            cpRange.Comments = comment;

            if (!string.IsNullOrEmpty(cpRange.RangeFrom) && !string.IsNullOrEmpty(cpRange.RangeTo))
            {
                return cpRange;
            }
            else
            {
                _warningsList.Add(cpRange.Name + " network range can not been converted becuase it contains wrong start ot end points values");
                _skippedNames.Add(cpRange.Name);
                return null;
            }
        }

        public CheckPointObject Add_Subnet(FgCommand_Edit fgCommandEdit)
        {
            CheckPointObject cpObjectRet = null;
            string comment = "";

            foreach (FgCommand fgCommand in fgCommandEdit.SubCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommand;
                    if (fgCommandSet.Field.Equals("subnet"))
                    {
                        string ipAddress = fgCommandSet.Value.Substring(0, fgCommandSet.Value.IndexOf(" ")).Trim();
                        string ipMask = fgCommandSet.Value.Substring(fgCommandSet.Value.IndexOf(" ")).Trim();

                        if (ipMask.Equals("255.255.255.255"))
                        {
                            CheckPoint_Host cpHost = new CheckPoint_Host();
                            cpHost.Name = GetSafeName(fgCommandEdit.Table);
                            cpHost.IpAddress = ipAddress;
                            cpObjectRet = cpHost;
                        }
                        else
                        {
                            CheckPoint_Network cpNetwork = new CheckPoint_Network();
                            cpNetwork.Name = GetSafeName(fgCommandEdit.Table);
                            cpNetwork.Subnet = ipAddress;
                            cpNetwork.Netmask = ipMask;
                            cpObjectRet = cpNetwork;
                        }
                    }
                    if (fgCommandSet.Field.Equals("comment") || fgCommandSet.Field.Equals("comments"))
                    {
                        comment = fgCommandSet.Value.Trim('"');
                    }
                }
            }

            cpObjectRet.Comments = comment;

            return cpObjectRet;
        }

        #endregion

        #region Convert VIP

        public void AddFirewallVip(List<FgCommand> fgCommandsList)
        {
            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    bool isPortForwardEnabled = false;
                    string protocol = "tcp";

                    string portExt = "";
                    string portMap = "";

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                            if (fgCommandSet.Field.Equals("extip"))
                            {
                                string[] addressesArray = fgCommandSet.Value.Trim('"').Split('-').ToArray();
                                if (addressesArray.Length == 1)
                                {
                                    CheckPoint_Host cpHost = new CheckPoint_Host();
                                    cpHost.Name = GetSafeName(fgCommandEdit.Table + "_vip_extip");
                                    cpHost.IpAddress = addressesArray[0];

                                    _warningsList.Add(cpHost.Name + " new host was created from " + fgCommandEdit.Table + " VIP (ext-ip).");

                                    AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_vip_extip + fgCommandEdit.Table, cpHost);
                                }
                                else
                                {
                                    CheckPoint_Range cpRange = new CheckPoint_Range();
                                    cpRange.Name = GetSafeName(fgCommandEdit.Table + "_vip_extip");

                                    _warningsList.Add(cpRange.Name + " new range was created from " + fgCommandEdit.Table + " VIP (ext-ip).");

                                    cpRange.RangeFrom = addressesArray[0];
                                    cpRange.RangeTo = addressesArray[1];

                                    if (!string.IsNullOrEmpty(cpRange.RangeFrom) && !string.IsNullOrEmpty(cpRange.RangeTo))
                                    {
                                        AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_vip_extip + fgCommandEdit.Table, cpRange);
                                    }
                                    else
                                    {
                                        _errorsList.Add(cpRange.Name + " network range can not been converted becuase it contains wrong start ot end points values");
                                        _skippedNames.Add(cpRange.Name);
                                    }
                                }
                            }

                            if (fgCommandSet.Field.Equals("mappedip"))
                            {
                                string[] addressesArray = fgCommandSet.Value.Trim('"').Split('-').ToArray();
                                if (addressesArray.Length == 1)
                                {
                                    CheckPoint_Host cpHost = new CheckPoint_Host();
                                    cpHost.Name = GetSafeName(fgCommandEdit.Table + "_vip_mappedip");

                                    _warningsList.Add(cpHost.Name + " new host was created from " + fgCommandEdit.Table + " VIP (mapped-ip).");

                                    cpHost.IpAddress = addressesArray[0];

                                    AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_vip_mappedip + fgCommandEdit.Table, cpHost);
                                }
                                else
                                {
                                    CheckPoint_Range cpRange = new CheckPoint_Range();
                                    cpRange.Name = GetSafeName(fgCommandEdit.Table + "_vip_mappedip");

                                    _warningsList.Add(cpRange.Name + " new range was created from " + fgCommandEdit.Table + " VIP (mapped-ip).");

                                    cpRange.RangeFrom = addressesArray[0];
                                    cpRange.RangeTo = addressesArray[1];

                                    if (!string.IsNullOrEmpty(cpRange.RangeFrom) && !string.IsNullOrEmpty(cpRange.RangeTo))
                                    {
                                        AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_vip_mappedip + fgCommandEdit.Table, cpRange);
                                    }
                                    else
                                    {
                                        _errorsList.Add(cpRange.Name + " network range can not been converted becuase it contains wrong start ot end points values");
                                        _skippedNames.Add(cpRange.Name);
                                    }
                                }
                            }

                            if (fgCommandSet.Field.Equals("portforward") && fgCommandSet.Value.Equals("enable"))
                            {
                                isPortForwardEnabled = true;
                                _vipPortForwardEnabledMapper[fgCommandEdit.Table] = true;
                            }

                            if (fgCommandSet.Field.Equals("extport"))
                            {
                                portExt = fgCommandSet.Value;
                            }

                            if (fgCommandSet.Field.Equals("mappedport"))
                            {
                                portMap = fgCommandSet.Value;
                            }

                            if (fgCommandSet.Field.Equals("protocol"))
                            {
                                protocol = fgCommandSet.Value;
                            }
                        }
                    }


                    if (isPortForwardEnabled)
                    {
                        string nameVipE = "VIPe_" + fgCommandEdit.Table;
                        string nameVipM = "VIPm_" + fgCommandEdit.Table;
                        switch (protocol)
                        {
                            case "tcp":
                                if (!portExt.Equals(""))
                                {
                                    AddTcpService(portExt, nameVipE);
                                }
                                if (!portMap.Equals(""))
                                {
                                    AddTcpService(portMap, nameVipM);
                                }
                                break;
                            case "udp":
                                if (!portExt.Equals(""))
                                {
                                    AddUdpService(portExt, nameVipE);
                                }
                                if (!portMap.Equals(""))
                                {
                                    AddUdpService(portMap, nameVipM);
                                }
                                break;
                            case "sctp":
                                if (!portExt.Equals(""))
                                {
                                    AddSctpService(portExt, nameVipE);
                                }
                                if (!portMap.Equals(""))
                                {
                                    AddSctpService(portMap, nameVipM);
                                }
                                break;
                            case "icmp":
                                string type = "99";

                                bool isFound = false;
                                string cpServiceName = _cpObjects.GetKnownServiceName("ICMP_" + type, out isFound);

                                CheckPointObject cpObj = _cpObjects.GetObject(cpServiceName);

                                AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_service_custom + nameVipE, cpObj);
                                AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_service_custom + nameVipM, cpObj);
                                break;
                        }
                    }
                }
            }
        }

        #endregion

        #region Convert VIP Groups

        public void AddFirewallVipGroups(List<FgCommand> fgCommandsList)
        {
            Dictionary<string, CheckPoint_NetworkGroup> checkingVipGrps = new Dictionary<string, CheckPoint_NetworkGroup>();

            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    CheckPoint_NetworkGroup cpVipGroup = new CheckPoint_NetworkGroup();
                    cpVipGroup.Name = GetSafeName(fgCommandEdit.Table);

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;
                            if (fgCommandSet.Field.Equals("member"))
                            {
                                string[] members = fgCommandSet.Value.Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();
                                foreach (string member in members)
                                {
                                    string memberC = member.Trim('"');
                                    cpVipGroup.Members.Add(memberC);
                                }
                            }

                            if (fgCommandSet.Field.Equals("comment") || fgCommandSet.Field.Equals("comments"))
                            {
                                cpVipGroup.Comments = fgCommandSet.Value.Trim('"');
                            }
                        }
                    }

                    checkingVipGrps.Add(fgCommandEdit.Table, cpVipGroup);

                    _localFgVipGrpsDict[fgCommandEdit.Table] = cpVipGroup.Members;
                }
            }

            while (checkingVipGrps.Keys.Count > 0)
            {
                Add_VipGroupsRecurs(checkingVipGrps.Keys.First(), checkingVipGrps);
            }
        }

        public void Add_VipGroupsRecurs(string cpVipGrpName, Dictionary<string, CheckPoint_NetworkGroup> checkingVipGrps)
        {
            List<string> errorsList = new List<string>();

            CheckPoint_NetworkGroup cpVipGrp = checkingVipGrps[cpVipGrpName];

            checkingVipGrps.Remove(cpVipGrpName);

            CheckPoint_NetworkGroup cpVipGrpAdd = new CheckPoint_NetworkGroup();

            cpVipGrpAdd.Name = cpVipGrp.Name;

            for (int i = 0; i < cpVipGrp.Members.Count; i++)
            {
                string member = cpVipGrp.Members[i];

                if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_extip + member) || _localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_mappedip + member))
                {
                    if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_extip + member))
                    {
                        List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_vip_extip + member];

                        if (list.Count > 0)
                        {
                            cpVipGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                        }
                    }

                    if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_mappedip + member))
                    {
                        List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_vip_mappedip + member];

                        if (list.Count > 0)
                        {
                            cpVipGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                        }
                    }
                }
                else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_grp + member))
                {
                    List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_vip_grp + member];

                    if (list.Count > 0)
                    {
                        cpVipGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                    }
                }
                else if (checkingVipGrps.ContainsKey(member))
                {
                    Add_VipGroupsRecurs(member, checkingVipGrps);

                    cpVipGrpAdd.Members.Add(member);
                }
                else
                {
                    errorsList.Add(cpVipGrpAdd.Name + " network group " +
                        "can not been converted becuase it contains non-existing member: " + member);
                }

                if (checkingVipGrps.ContainsKey(member))
                {
                    checkingVipGrps.Remove(member);
                }
            }

            if (errorsList.Count == 0)
            {
                //AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_vip_grp + cpVipGrp.Name, cpVipGrpAdd);
                AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_vip_grp + cpVipGrpName, cpVipGrpAdd);
            }
            else
            {
                _errorsList.AddRange(errorsList);
            }
        }

        #endregion

        #region Convert Addresses Groups

        public void Add_AddressGroups(List<FgCommand> fgCommandsList)
        {
            Dictionary<string, CheckPoint_NetworkGroup> checkingAddrGrps = new Dictionary<string, CheckPoint_NetworkGroup>();

            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                    CheckPoint_NetworkGroup cpAddrGroup = new CheckPoint_NetworkGroup();
                    cpAddrGroup.Name = GetSafeName(fgCommandEdit.Table);

                    foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;
                            if (fgCommandSet.Field.Equals("member"))
                            {
                                string[] members = fgCommandSet.Value.Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();
                                foreach (string member in members)
                                {
                                    string memberC = member.Trim('"');
                                    cpAddrGroup.Members.Add(memberC);
                                }
                            }

                            if (fgCommandSet.Field.Equals("comment") || fgCommandSet.Field.Equals("comments"))
                            {
                                cpAddrGroup.Comments = fgCommandSet.Value.Trim('"');
                            }
                        }
                    }

                    checkingAddrGrps.Add(fgCommandEdit.Table, cpAddrGroup);
                }
            }

            while (checkingAddrGrps.Keys.Count > 0)
            {
                Add_AddressGroupsRecurs(checkingAddrGrps.Keys.First(), checkingAddrGrps);
            }
        }

        public void Add_AddressGroupsRecurs(string cpAddrGrpName, Dictionary<string, CheckPoint_NetworkGroup> checkingAddrGrps)
        {
            List<string> errorsList = new List<string>();

            CheckPoint_NetworkGroup cpAddrGrp = checkingAddrGrps[cpAddrGrpName];

            checkingAddrGrps.Remove(cpAddrGrpName);

            CheckPoint_NetworkGroup cpAddrGrpAdd = new CheckPoint_NetworkGroup();

            cpAddrGrpAdd.Name = cpAddrGrp.Name;

            for (int i = 0; i < cpAddrGrp.Members.Count; i++)
            {
                string member = cpAddrGrp.Members[i];

                if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_address + member))
                {
                    List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_address + member];

                    if (list.Count > 0)
                    {
                        cpAddrGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                    }
                }
                else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_addrgrp + member))
                {
                    List<CheckPointObject> list = _localMapperFgCp[FG_PREFIX_KEY_firewall_addrgrp + member];

                    if (list.Count > 0)
                    {
                        cpAddrGrpAdd.Members.AddRange((from o in list select o.Name).ToList());
                    }
                }
                else if (checkingAddrGrps.ContainsKey(member))
                {
                    Add_AddressGroupsRecurs(member, checkingAddrGrps);

                    cpAddrGrpAdd.Members.Add(member);
                }
                else
                {
                    errorsList.Add(cpAddrGrpAdd.Name + " address group " +
                        "can not been converted becuase it contains non-existing member: " + member);
                }

                if (checkingAddrGrps.ContainsKey(member))
                {
                    checkingAddrGrps.Remove(member);
                }
            }

            if (errorsList.Count == 0)
            {
                //AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_addrgrp + cpAddrGrp.Name, cpAddrGrpAdd);
                AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_addrgrp + cpAddrGrpName, cpAddrGrpAdd);
            }
            else
            {
                _errorsList.AddRange(errorsList);
            }
        }

        #endregion

        #region Convert Policy Rules && prepare for NATs converting
        private void Add_Optimized_Package()
        {
            CheckPoint_Package regularPackage = _cpPackages[0];

            var optimizedPackage = new CheckPoint_Package();
            optimizedPackage.Name = _policyPackageOptimizedName;
            optimizedPackage.ParentLayer.Name = optimizedPackage.NameOfAccessLayer;
            optimizedPackage.ConversionIncidentType = regularPackage.ConversionIncidentType;

            var regular2OptimizedLayers = new Dictionary<string, string>();

            foreach (CheckPoint_Layer layer in regularPackage.SubPolicies)
            {
                string optimizedSubPolicyName = layer.Name + "_opt";

                CheckPoint_Layer optimizedLayer = RuleBaseOptimizer.Optimize(layer, optimizedSubPolicyName);
                foreach (CheckPoint_Rule subSubRule in optimizedLayer.Rules)
                {
                    if (subSubRule.SubPolicyName.Equals(GlobalRulesSubpolicyName))
                    {
                        //The Global sub-sub rule subpolicy name should also be renamed for consistency
                        subSubRule.SubPolicyName += "_opt";
                    }
                }
                if (!regular2OptimizedLayers.ContainsKey(layer.Name))
                {
                    regular2OptimizedLayers.Add(layer.Name, optimizedSubPolicyName);
                    optimizedPackage.SubPolicies.Add(optimizedLayer);
                    validatePackage(optimizedPackage);
                }
            }

            foreach (CheckPoint_Rule rule in regularPackage.ParentLayer.Rules)
            {
                CheckPoint_Rule newRule = rule.Clone();
                if (newRule.Action == CheckPoint_Rule.ActionType.SubPolicy)
                {
                    newRule.SubPolicyName = regular2OptimizedLayers[rule.SubPolicyName];
                }
                newRule.Layer = optimizedPackage.ParentLayer.Name;
                newRule.ConversionComments = rule.ConversionComments;

                optimizedPackage.ParentLayer.Rules.Add(newRule);
            }

            AddCheckPointObject(optimizedPackage);
        }


        public void Add_Package(List<FgCommand> fgCommandsList, bool convertNat, string commentPhraze)
        {
            if (IsConsoleRunning) {
                Console.WriteLine(commentPhraze);
                Progress.SetProgress(70);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(70, commentPhraze);

            var cpPackage = new CheckPoint_Package();
            cpPackage.Name = _policyPackageName;

            Add_ParentLayer(cpPackage, fgCommandsList, convertNat);

            AddCheckPointObject(cpPackage);
        }

        public void Add_ParentLayer(CheckPoint_Package package, List<FgCommand> fgCommandsList, bool convertNat)
        {
            this._rulesInConvertedPackage = 0;
            package.ParentLayer.Name = package.NameOfAccessLayer;

            List<CheckPoint_Rule> rootRulesList = new List<CheckPoint_Rule>();
            Dictionary<string, CheckPoint_Layer> rootLayersMap = new Dictionary<string, CheckPoint_Layer>();
            Dictionary<string, CheckPoint_Zone> extraZonesMap = new Dictionary<string, CheckPoint_Zone>();
            List<string> extraZonesWarnMsgsList = new List<string>();
            List<CheckPoint_Rule> realRulesList = new List<CheckPoint_Rule>(); //is used if 'plain' policy should be converted

            //add main rule from Intrazone
            //add sub policy layer
            //add rule from Intrazone

            foreach (CheckPoint_Zone cpZoneIntra in _localIntrazonesList)
            {
                string warnMessage = CheckZoneForReservedWords(cpZoneIntra);

                if (warnMessage != null)
                {
                    _warningsList.Add(warnMessage);
                }

                AddCheckPointObject(cpZoneIntra);

                CheckPoint_Rule cpRuleZone = new CheckPoint_Rule();
                cpRuleZone.Name = GetSafeName(cpZoneIntra.Name); //"Intrazone_" + cpZoneIntra.Name;
                cpRuleZone.Layer = package.NameOfAccessLayer;
                cpRuleZone.Source.Add(cpZoneIntra);
                cpRuleZone.Destination.Add(cpZoneIntra);
                cpRuleZone.Action = CheckPoint_Rule.ActionType.SubPolicy;
                cpRuleZone.Track = CheckPoint_Rule.TrackTypes.Log;
                cpRuleZone.Time.Add(_cpObjects.GetObject(CheckPointObject.Any));
                cpRuleZone.Service.Add(_cpObjects.GetObject(CheckPointObject.Any));
                cpRuleZone.SubPolicyName = GetSafeName(cpZoneIntra.Name + "_internal");

                package.ParentLayer.Rules.Add(cpRuleZone);

                CheckPoint_Layer cpRuleLayer = new CheckPoint_Layer();
                cpRuleLayer.Name = cpRuleZone.SubPolicyName;

                package.SubPolicies.Add(cpRuleLayer);
                validatePackage(package);

                CheckPoint_Rule cpSubRuleZone = new CheckPoint_Rule();
                cpSubRuleZone.Name = ""; //"intrazone_sr_" + cpZoneIntra.Name;
                cpSubRuleZone.Layer = cpRuleLayer.Name;
                cpSubRuleZone.Source.Add(_cpObjects.GetObject(CheckPointObject.Any));
                cpSubRuleZone.Destination.Add(_cpObjects.GetObject(CheckPointObject.Any));
                cpSubRuleZone.Action = CheckPoint_Rule.ActionType.Accept;
                cpSubRuleZone.Track = CheckPoint_Rule.TrackTypes.Log;
                cpSubRuleZone.Time.Add(_cpObjects.GetObject(CheckPointObject.Any));
                cpSubRuleZone.Service.Add(_cpObjects.GetObject(CheckPointObject.Any));

                cpRuleLayer.Rules.Add(cpSubRuleZone);
            }

            bool isIntfContainsAny = false;

            NewFortigateAnalizStatistic._fullrullPackcount = fgCommandsList.Count;
            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommand_Edit = (FgCommand_Edit)fgCommandE;

                    var cpRule = new CheckPoint_Rule();

                    cpRule.ConversionComments = "Matched rule " + fgCommand_Edit.Table;

                    string[] fgSrcIntfs = new string[] { };
                    string[] fgDstIntfs = new string[] { };

                    cpRule.Track = CheckPoint_Rule.TrackTypes.Log;

                    List<string> errorsList = new List<string>();

                    bool isNatEnabled = false;
                    bool isIpPoolEnabled = false;

                    List<string> fgDstAddrList = new List<string>();

                    List<CheckPointObject> cpUsersGroupsList = new List<CheckPointObject>();

                    bool in_service = false;

                    foreach (FgCommand fgCommandS in fgCommand_Edit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommand_Set = (FgCommand_Set)fgCommandS;

                            if (fgCommand_Set.Field.Equals("name"))
                            {
                                cpRule.Name = GetSafeName(fgCommand_Set.Value);
                            }

                            if (fgCommand_Set.Field.Equals("action") && fgCommand_Set.Value.Equals("accept") && (cpRule.Action == CheckPoint_Rule.ActionType.Drop))
                            {
                                cpRule.Action = CheckPoint_Rule.ActionType.Accept;
                            }

                            if (fgCommand_Set.Field.Equals("status") && fgCommand_Set.Value.Trim().ToLower().Equals("disable"))
                            {
                                cpRule.Enabled = false;
                            }

                            if (fgCommand_Set.Field.Equals("learning-mode") && fgCommand_Set.Value.Equals("enable"))
                            {
                                cpRule.Action = CheckPoint_Rule.ActionType.Accept;
                            }

                            if (fgCommand_Set.Field.Equals("srcintf"))
                            {
                                fgSrcIntfs = fgCommand_Set.Value.Trim('"').Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();

                                if (Array.IndexOf(fgSrcIntfs.Select(s => s.ToLowerInvariant()).ToArray(), "any") > -1)
                                {
                                    isIntfContainsAny = true;
                                }
                            }

                            if (fgCommand_Set.Field.Equals("dstintf"))
                            {
                                fgDstIntfs = fgCommand_Set.Value.Trim('"').Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();

                                if (Array.IndexOf(fgDstIntfs.Select(s => s.ToLowerInvariant()).ToArray(), "any") > -1)
                                {
                                    isIntfContainsAny = true;
                                }
                            }


                            if (fgCommand_Set.Field.Equals("srcaddr"))
                            {
                                if (fgCommand_Set.Value.Equals("all"))
                                {
                                    NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnySourceCount++;
                                    in_service = true;

                                    cpRule.Source.Add(_cpObjects.GetObject(CheckPointObject.Any));
                                }
                                else
                                {
                                    List<string> list = fgCommand_Set.Value.Split(new string[] { "\" \"" }, StringSplitOptions.None).ToList();
                                    foreach (string str in list)
                                    {
                                        string name = str.Trim('"');

                                        bool isAdded = false;

                                        string[] fgPrefixes = new string[]
                                                    {
                                                        FG_PREFIX_KEY_firewall_address,
                                                        FG_PREFIX_KEY_firewall_addrgrp,
                                                        FG_PREFIX_KEY_firewall_vip_extip,
                                                        FG_PREFIX_KEY_firewall_vip_grp
                                                    };

                                        foreach (string fgPrefix in fgPrefixes)
                                        {
                                            if (_localMapperFgCp.ContainsKey(fgPrefix + name))
                                            {
                                                List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + name];

                                                foreach (CheckPointObject cpObj in cpObjsList)
                                                {
                                                    cpRule.Source.Add(cpObj);
                                                    isAdded = true;
                                                    if (OptimizeConf)
                                                    {
                                                        AddCheckPointObject(cpObj);
                                                    }
                                                }
                                            }
                                        }

                                        if (!isAdded)
                                        {
                                            errorsList.Add("policy rule " + fgCommand_Edit.Table + " contains 'srcaddr' field with non-existing reference to: " + name + " and was not created.");
                                        }
                                    }
                                }
                            }

                            if (fgCommand_Set.Field.Equals("dstaddr"))
                            {
                                if (fgCommand_Set.Value.Equals("all"))
                                {
                                    NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnyDestinationCount++;
                                    in_service = true;

                                    cpRule.Destination.Add(_cpObjects.GetObject(CheckPointObject.Any));
                                    fgDstAddrList.Add("all");
                                }
                                else
                                {
                                    List<string> list = fgCommand_Set.Value.Split(new string[] { "\" \"" }, StringSplitOptions.None).ToList();
                                    foreach (string str in list)
                                    {
                                        string name = str.Trim('"');

                                        bool isAdded = false;

                                        string[] fgPrefixes = new string[]
                                                    {
                                                        FG_PREFIX_KEY_firewall_address,
                                                        FG_PREFIX_KEY_firewall_addrgrp,
                                                        FG_PREFIX_KEY_firewall_vip_extip,
                                                        FG_PREFIX_KEY_firewall_vip_grp
                                                    };

                                        foreach (string fgPrefix in fgPrefixes)
                                        {
                                            if (_localMapperFgCp.ContainsKey(fgPrefix + name))
                                            {
                                                List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + name];

                                                foreach (CheckPointObject cpObj in cpObjsList)
                                                {
                                                    cpRule.Destination.Add(cpObj);
                                                    isAdded = true;
                                                    if (OptimizeConf)
                                                    {
                                                        AddCheckPointObject(cpObj);
                                                    }
                                                }
                                            }
                                        }

                                        if (!isAdded)
                                        {
                                            errorsList.Add("policy rule " + fgCommand_Edit.Table + " contains 'dstaddr' field with non-existing reference to: " + name + " and was not created.");
                                        }

                                        fgDstAddrList.Add(name);
                                    }
                                }
                            }

                            if (fgCommand_Set.Field.Equals("internet-service") && fgCommand_Set.Value.Equals("enable"))
                            {
                                errorsList.Add("policy rule " + fgCommand_Edit.Table + " contains 'internet-service' field as destination" + " and was not created.");
                            }

                            if (fgCommand_Set.Field.Equals("internet-service-id"))
                            {
                                errorsList.Add("policy rule " + fgCommand_Edit.Table + " contains 'internet-service' field with " + fgCommand_Set.Value + " id" + " and was not created.");
                            }
                            if (fgCommand_Set.Field.Equals("schedule"))
                            {
                                string fgScheduleRule = fgCommand_Set.Value.Trim('"');

                                if(!fgScheduleRule.Equals("always"))
                                {
                                    NewFortigateAnalizStatistic._timesServicesRulesCount++;
                                }

                                bool isAdded = false;

                                string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_schedule_recurring, FG_PREFIX_KEY_firewall_schedule_onetime, FG_PREFIX_KEY_firewall_schedule_group };

                                foreach (string fgPrefix in fgPrefixes)
                                {
                                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgScheduleRule))
                                    {
                                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgScheduleRule];
                                        foreach (CheckPointObject cpObj in cpObjsList)
                                        {
                                            cpRule.Time.Add(cpObj);
                                            if (OptimizeConf)
                                            {
                                                AddCheckPointObject(cpObj);
                                            }
                                            isAdded = true;
                                        }
                                    }
                                }

                                if (!isAdded)
                                {
                                    errorsList.Add("policy rule " + fgCommand_Edit.Table + " contains 'schedule' field with unrecognized value: " + fgScheduleRule + " and was not created");
                                }
                            }
                            if (fgCommand_Set.Field.Equals("service"))
                            {
                                string[] fgServicesNames = fgCommand_Set.Value.Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();
                                foreach (string fgServiceName in fgServicesNames)
                                {
                                    string fgSrvName = fgServiceName.Trim('"');

                                    if (fgSrvName.ToUpper().Equals("ALL"))
                                    {
                                        NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnyServiceCount++;
                                        in_service = true;

                                        cpRule.Service.Add(_cpObjects.GetObject(CheckPointObject.Any));
                                    }
                                    else
                                    {
                                        string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_service_custom, FG_PREFIX_KEY_firewall_service_group };

                                        bool isAdded = false;

                                        foreach (string fgPrefix in fgPrefixes)
                                        {
                                            if (_localMapperFgCp.ContainsKey(fgPrefix + fgSrvName))
                                            {
                                                List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgSrvName];
                                                foreach (CheckPointObject cpObj in cpObjsList)
                                                {
                                                    cpRule.Service.Add(cpObj);
                                                    if (OptimizeConf)
                                                    {
                                                        AddCheckPointObject(cpObj);
                                                    }
                                                    isAdded = true;
                                                }
                                            }
                                        }

                                        if (!isAdded)
                                        {
                                            errorsList.Add("policy rule " + fgCommand_Edit.Table + " contains 'service' field with unrecognized value: " + fgSrvName + " and was not created");
                                        }
                                    }
                                }
                            }

                            if (fgCommand_Set.Field.Equals("groups"))
                            {
                                string[] fgGroups = fgCommand_Set.Value.Trim('"').Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();

                                foreach (string fgGroup in fgGroups)
                                {
                                    if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_user_group + fgGroup))
                                    {
                                        List<CheckPointObject> cpObjsList = _localMapperFgCp[FG_PREFIX_KEY_user_group + fgGroup];
                                        if (cpObjsList != null && cpObjsList.Count > 0)
                                        {
                                            cpUsersGroupsList.AddRange(cpObjsList);
                                        }
                                    }
                                }
                            }

                            if (fgCommand_Set.Field.Equals("logtraffic") && fgCommand_Set.Value.Equals("disable"))
                            {
                                cpRule.Track = CheckPoint_Rule.TrackTypes.None;
                            }

                            if (fgCommand_Set.Field.Equals("comment") || fgCommand_Set.Field.Equals("comments"))
                            {
                                cpRule.Comments = fgCommand_Set.Value;
                                NewFortigateAnalizStatistic._uncommentedServicesRulesCount++;
                            }

                            if (fgCommand_Set.Field.Equals("nat") && fgCommand_Set.Value.Equals("enable"))
                            {
                                isNatEnabled = true;
                            }

                            if (fgCommand_Set.Field.Equals("ippool") && fgCommand_Set.Value.Equals("enable"))
                            {
                                isIpPoolEnabled = true;
                            }
                        }
                    }

                    if (errorsList.Count == 0)
                    {
                        CheckPoint_Layer rootLayer = null;

                        string rootLayerName = "";

                        List<CheckPointObject> fgSrcIntfsList = new List<CheckPointObject>();
                        List<CheckPointObject> fgDstIntfsList = new List<CheckPointObject>();

                        foreach (string fgSrcIntf in fgSrcIntfs)
                        {
                            string fgSrcIntf_Appendix = "";

                            if (_intfAliasNamesMapper.ContainsKey(fgSrcIntf))
                            {
                                fgSrcIntf_Appendix = _intfAliasNamesMapper[fgSrcIntf] + "_";
                            }

                            rootLayerName += fgSrcIntf_Appendix + fgSrcIntf + "_";

                            if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_system_zone + fgSrcIntf))
                            {
                                fgSrcIntfsList.AddRange(_localMapperFgCp[FG_PREFIX_KEY_system_zone + fgSrcIntf]);
                            }
                            else if (extraZonesMap.ContainsKey(FG_PREFIX_KEY_system_zone + fgSrcIntf))
                            {
                                fgSrcIntfsList.Add(extraZonesMap[FG_PREFIX_KEY_system_zone + fgSrcIntf]);
                            }
                            else
                            {
                                CheckPoint_Zone cpZoneSrc = new CheckPoint_Zone();
                                cpZoneSrc.Name = GetSafeName(fgSrcIntf_Appendix + fgSrcIntf);

                                string warnMessage = CheckZoneForReservedWords(cpZoneSrc);
                                if (warnMessage != null)
                                {
                                    extraZonesWarnMsgsList.Add(warnMessage);
                                }

                                fgSrcIntfsList.Add(cpZoneSrc);

                                extraZonesMap.Add(FG_PREFIX_KEY_system_zone + fgSrcIntf, cpZoneSrc);
                            }
                        }

                        rootLayerName += "_";

                        foreach (string fgDstIntf in fgDstIntfs)
                        {
                            string fgDstIntf_Appendix = "";

                            if (_intfAliasNamesMapper.ContainsKey(fgDstIntf))
                            {
                                fgDstIntf_Appendix = _intfAliasNamesMapper[fgDstIntf] + "_";
                            }

                            rootLayerName += fgDstIntf_Appendix + fgDstIntf + "_";

                            if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_system_zone + fgDstIntf))
                            {
                                fgDstIntfsList.AddRange(_localMapperFgCp[FG_PREFIX_KEY_system_zone + fgDstIntf]);
                            }
                            else if (extraZonesMap.ContainsKey(FG_PREFIX_KEY_system_zone + fgDstIntf))
                            {
                                fgDstIntfsList.Add(extraZonesMap[FG_PREFIX_KEY_system_zone + fgDstIntf]);
                            }
                            else
                            {
                                CheckPoint_Zone cpZoneDst = new CheckPoint_Zone();
                                cpZoneDst.Name = GetSafeName(fgDstIntf_Appendix + fgDstIntf);

                                string warnMessage = CheckZoneForReservedWords(cpZoneDst);
                                if (warnMessage != null)
                                {
                                    extraZonesWarnMsgsList.Add(warnMessage);
                                }

                                fgDstIntfsList.Add(cpZoneDst);

                                extraZonesMap.Add(FG_PREFIX_KEY_system_zone + fgDstIntf, cpZoneDst);
                            }
                        }

                        rootLayerName = GetSafeName(rootLayerName.Substring(0, (rootLayerName.Length - 1)));

                        //---

                        if (rootLayersMap.ContainsKey(rootLayerName))
                        {
                            rootLayer = rootLayersMap[rootLayerName];
                        }
                        else
                        {
                            CheckPoint_Rule rootRule = new CheckPoint_Rule();
                            rootRule.Name = rootLayerName;
                            rootRule.Layer = package.NameOfAccessLayer;
                            rootRule.Source.AddRange(fgSrcIntfsList);
                            rootRule.Destination.AddRange(fgDstIntfsList);
                            rootRule.Action = CheckPoint_Rule.ActionType.SubPolicy;
                            rootRule.Track = CheckPoint_Rule.TrackTypes.Log;
                            rootRule.Time.Add(_cpObjects.GetObject(CheckPointObject.Any));
                            rootRule.Service.Add(_cpObjects.GetObject(CheckPointObject.Any));
                            rootRule.SubPolicyName = rootLayerName;

                            rootRulesList.Add(rootRule);

                            rootLayer = new CheckPoint_Layer();
                            rootLayer.Name = rootLayerName;

                            rootLayersMap.Add(rootLayerName, rootLayer);
                        }

                        cpRule.Layer = rootLayer.Name;

                        //add rule for Users Groups

                        CheckPoint_Rule cpRuleUG = null;

                        if (cpUsersGroupsList.Count > 0)
                        {
                            cpRuleUG = cpRule.Clone();
                            cpRuleUG.Name += "_UG";
                            cpRuleUG.Source.Clear();
                            cpRuleUG.Source.AddRange(cpUsersGroupsList);

                            cpRule.Enabled = false;
                            cpRule.Comments = "Disabled for reason it is replaced by the same rule with Users Groups";

                        }

                        rootLayer.Rules.Add(cpRule);
                        realRulesList.Add(cpRule);

                        NewFortigateAnalizStatistic._totalServicesRulesCount++;
                        if(in_service) NewFortigateAnalizStatistic._rulesServicesutilizingServicesAnyCount++;
                        _rulesInConvertedPackage += 1;

                        if (cpRuleUG != null)
                        {
                            rootLayer.Rules.Add(cpRuleUG);

                            NewFortigateAnalizStatistic._totalServicesRulesCount++;
                            _rulesInConvertedPackage += 1;
                        }

                        rootLayersMap[rootLayer.Name] = rootLayer;

                        //NAT conversion reagrding design which is described in other doc

                        if (convertNat)
                        {
                            int counterNatRules = -1;

                            foreach (string fgDstAddr in fgDstAddrList)
                            {
                                if (isNatEnabled)
                                {
                                    if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_grp + fgDstAddr))
                                    {
                                        List<CheckPointObject> cpVipGrpsList = _localMapperFgCp[FG_PREFIX_KEY_firewall_vip_grp + fgDstAddr];
                                        foreach (CheckPointObject cpVipGrpI in cpVipGrpsList)
                                        {
                                            if (cpVipGrpI.GetType() == typeof(CheckPoint_NetworkGroup))
                                            {
                                                CheckPoint_NetworkGroup cpVipGrp = (CheckPoint_NetworkGroup)cpVipGrpI;

                                                List<string> cpVipMembersOrig = GetVipGroupMembers(fgDstAddr);

                                                foreach (string cpVipI in cpVipMembersOrig)
                                                {
                                                    if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_extip + cpVipI) ||
                                                        _localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_mappedip + cpVipI))
                                                    {
                                                        counterNatRules = AddNatRuleVipNatEnable(fgCommand_Edit, cpVipI, counterNatRules);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_extip + fgDstAddr) ||
                                            _localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_mappedip + fgDstAddr))
                                    {
                                        counterNatRules = AddNatRuleVipNatEnable(fgCommand_Edit, fgDstAddr, counterNatRules);
                                    }
                                    else if (isIpPoolEnabled)
                                    {
                                        counterNatRules = AddNatRuleIpPool(fgCommand_Edit, fgDstAddr, counterNatRules);
                                    }
                                    else
                                    {
                                        counterNatRules = AddNatRuleSimple(fgCommand_Edit, fgDstAddr, counterNatRules);
                                    }
                                }
                                else
                                {
                                    if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_grp + fgDstAddr))
                                    {
                                        List<CheckPointObject> cpVipGrpsList = _localMapperFgCp[FG_PREFIX_KEY_firewall_vip_grp + fgDstAddr];
                                        foreach (CheckPointObject cpVipGrpI in cpVipGrpsList)
                                        {
                                            if (cpVipGrpI.GetType() == typeof(CheckPoint_NetworkGroup))
                                            {
                                                CheckPoint_NetworkGroup cpVipGrp = (CheckPoint_NetworkGroup)cpVipGrpI;

                                                List<string> cpVipMembersOrig = GetVipGroupMembers(fgDstAddr);

                                                foreach (string cpVipI in cpVipMembersOrig)
                                                {
                                                    if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_extip + cpVipI) ||
                                                        _localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_mappedip + cpVipI))
                                                    {
                                                        counterNatRules = AddNatRuleVipNatDisable(fgCommand_Edit, cpVipI, counterNatRules);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_extip + fgDstAddr) ||
                                            _localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_mappedip + fgDstAddr))
                                    {
                                        counterNatRules = AddNatRuleVipNatDisable(fgCommand_Edit, fgDstAddr, counterNatRules);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {

                        foreach (string error in errorsList)
                        {
                            _errorsList.Add(error);
                        }
                    }
                }
            }

            //if Src or Dst Intf DO NOT contain ANY then we create sub-layers
            //otherwise policy is plain
            if (!isIntfContainsAny)
            {
                package.ParentLayer.Rules.AddRange(rootRulesList);

                foreach (string key in extraZonesMap.Keys)
                {
                    AddCpObjectToLocalMapper(key, extraZonesMap[key]);
                    AddCheckPointObject(extraZonesMap[key]);
                }

                _warningsList.AddRange(extraZonesWarnMsgsList);

                foreach (string key in rootLayersMap.Keys)
                {
                    CheckPoint_Layer cpLayer = rootLayersMap[key];

                    CheckPoint_Rule cpRuleCU = new CheckPoint_Rule();
                    if(!OptimizeConf) NewFortigateAnalizStatistic._cleanupServicesRuleCount++;
                    NewFortigateAnalizStatistic._totalServicesRulesCount++;
                    cpRuleCU.Name = "Sub-Policy Cleanup";
                    cpRuleCU.Layer = cpLayer.Name;

                    cpLayer.Rules.Add(cpRuleCU);

                    package.SubPolicies.Add(cpLayer);
                    validatePackage(package);
                }
            }
            else
            {
                foreach (CheckPoint_Rule ruleAdd in realRulesList)
                {
                    ruleAdd.Layer = package.ParentLayer.Name;
                    package.ParentLayer.Rules.Add(ruleAdd);
                }
            }

            var cpRuleFake = new CheckPoint_Rule();
            cpRuleFake.Name = "Cleanup rule"; //the last rule which is created by default by CheckPoint script importer. It is for report only.
            package.ParentLayer.Rules.Add(cpRuleFake);
        }

        #endregion

        #region Converting NATs

        public List<CheckPointObject> GetFgSrcAddrsList(FgCommand_Set fgCommandSet)
        {
            List<CheckPointObject> fgSrcAddrsList = new List<CheckPointObject>();

            string[] fgSrcAddrsNames = fgCommandSet.Value.Trim('"').Split(new string[] { "\" \"" }, StringSplitOptions.None).ToArray();
            foreach (string fgSrcAddrName in fgSrcAddrsNames)
            {
                string fgSrcAddr = fgSrcAddrName.Trim('"');

                if (fgSrcAddr.ToLower().Equals("all"))
                {
                    fgSrcAddrsList.Add(_cpObjects.GetObject(CheckPointObject.Any));
                    continue;
                }

                string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_address, FG_PREFIX_KEY_firewall_addrgrp };
                foreach (string fgPrefix in fgPrefixes)
                {
                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgSrcAddr))
                    {
                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgSrcAddr];
                        if (cpObjsList != null && cpObjsList.Count > 0)
                        {
                            fgSrcAddrsList.AddRange(cpObjsList);
                        }
                    }
                }
            }

            return fgSrcAddrsList;
        }

        public List<CheckPointObject> GetFgDstAddrsAsVipExtIpList(string fgDstAddr)
        {
            List<CheckPointObject> fgDstAddrsList = new List<CheckPointObject>();

            if (fgDstAddr.ToLower().Equals("all"))
            {
                fgDstAddrsList.Add(_cpObjects.GetObject(CheckPointObject.Any));
            }
            else
            {
                string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_vip_extip };

                foreach (string fgPrefix in fgPrefixes)
                {
                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgDstAddr))
                    {
                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgDstAddr];
                        if (cpObjsList != null && cpObjsList.Count > 0)
                        {
                            fgDstAddrsList.AddRange(cpObjsList);
                        }
                    }
                }
            }

            return fgDstAddrsList;
        }

        public List<CheckPointObject> GetFgDstAddrsAsVipMappedIpList(string fgDstAddr)
        {
            List<CheckPointObject> fgDstAddrsList = new List<CheckPointObject>();

            if (fgDstAddr.ToLower().Equals("all"))
            {
                fgDstAddrsList.Add(_cpObjects.GetObject(CheckPointObject.Any));
            }
            else
            {
                string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_vip_mappedip };

                foreach (string fgPrefix in fgPrefixes)
                {
                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgDstAddr))
                    {
                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgDstAddr];
                        if (cpObjsList != null && cpObjsList.Count > 0)
                        {
                            fgDstAddrsList.AddRange(cpObjsList);
                        }
                    }
                }
            }

            return fgDstAddrsList;
        }

        public List<CheckPointObject> GetFgDstAddrToOSAsVipExtIpList(string fgDstAddr)
        {
            List<CheckPointObject> fgDstAddrsList = new List<CheckPointObject>();

            if (fgDstAddr.Equals("all"))
            {
                fgDstAddrsList.Add(_cpObjects.GetObject(CheckPointObject.Any));
            }
            else
            {
                string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_service_custom_vipe_ };

                foreach (string fgPrefix in fgPrefixes)
                {
                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgDstAddr))
                    {
                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgDstAddr];
                        if (cpObjsList != null && cpObjsList.Count > 0)
                        {
                            fgDstAddrsList.AddRange(cpObjsList);
                        }
                    }
                }
            }

            return fgDstAddrsList;
        }

        public List<CheckPointObject> GetFgDstAddrToOSAsVipMapIpList(string fgDstAddr)
        {
            List<CheckPointObject> fgDstAddrsList = new List<CheckPointObject>();
            if (fgDstAddr.Equals("all"))
            {
                fgDstAddrsList.Add(_cpObjects.GetObject(CheckPointObject.Any));
            }
            else
            {
                string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_service_custom_vipm_ };

                foreach (string fgPrefix in fgPrefixes)
                {
                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgDstAddr))
                    {
                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgDstAddr];
                        if (cpObjsList != null && cpObjsList.Count > 0)
                        {
                            fgDstAddrsList.AddRange(cpObjsList);
                        }
                    }
                }
            }

            return fgDstAddrsList;
        }

        public List<CheckPointObject> GetFgServicesList(FgCommand_Set fgCommandSet)
        {
            List<CheckPointObject> fgServicesList = new List<CheckPointObject>();

            List<string> fgServicesNames = fgCommandSet.Value.Trim('"').Split(new string[] { "\" \"" }, StringSplitOptions.None).ToList();
            for (int i = 0; i < fgServicesNames.Count; i++)
            {
                string fgServiceName = fgServicesNames[i];

                string fgSrvName = fgServiceName.Trim('"');

                if (fgSrvName.ToLower().Equals("all"))
                {
                    fgServicesList.Add(_cpObjects.GetObject(CheckPointObject.Any));
                    continue;
                }

                string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_service_custom, FG_PREFIX_KEY_firewall_service_group };
                foreach (string fgPrefix in fgPrefixes)
                {
                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgSrvName))
                    {
                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgSrvName];
                        if (cpObjsList != null && cpObjsList.Count > 0)
                        {
                            foreach (CheckPointObject cpObj in cpObjsList)
                            {
                                //to skip illegal services for NAT
                                //---
                                // predefined CheckPoint services are not skipped. Sorry, current API does not allow to do that!!!!!!!!!!!!!!!
                                //---
                                if ((cpObj.GetType() == typeof(CheckPoint_IcmpService)) ||
                                    (cpObj.GetType() == typeof(CheckPoint_SctpService)) ||
                                    (cpObj.GetType() == typeof(CheckPoint_OtherService)))
                                {
                                    continue;
                                }

                                if (cpObj.GetType() == typeof(CheckPoint_ServiceGroup))
                                {
                                    CheckPoint_ServiceGroup cpServGrp = (CheckPoint_ServiceGroup)cpObj;
                                    foreach (string member in cpServGrp.Members)
                                    {
                                        if (!fgServicesNames.Contains(member))
                                        {
                                            fgServicesNames.Add(member);
                                        }
                                    }
                                    continue;
                                }
                                fgServicesList.Add(cpObj);
                            }
                        }
                    }
                }
            }

            return fgServicesList;
        }

        public int AddNatRuleSimple(FgCommand_Edit fgCommandEdit, string fgDstAddr, int counterNatRules)
        {
            string cpNatRuleId = fgCommandEdit.Table;
            string cpNatRuleName = "";

            string cpNatRuleComments = "";
            bool isNatEnable = true;

            List<CheckPointObject> fgDstIntfsList = new List<CheckPointObject>();

            List<CheckPointObject> fgSrcAddrsList = new List<CheckPointObject>();

            List<CheckPointObject> fgDstAddrsList = new List<CheckPointObject>();

            if (fgDstAddr.Equals("all"))
            {
                fgDstAddrsList.Add(_cpObjects.GetObject(CheckPointObject.Any));
            }
            else
            {
                string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_address, FG_PREFIX_KEY_firewall_addrgrp };

                foreach (string fgPrefix in fgPrefixes)
                {
                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgDstAddr))
                    {
                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgDstAddr];
                        if (cpObjsList != null && cpObjsList.Count > 0)
                        {
                            fgDstAddrsList.AddRange(cpObjsList);
                        }
                    }
                }
            }

            foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
            {
                if (fgCommandS.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                    if (fgCommandSet.Field.Equals("name"))
                    {
                        cpNatRuleName = fgCommandSet.Value.Trim('"');
                    }
                    if (fgCommandSet.Field.Equals("dstintf"))
                    {
                        if (_interfacesMapperFgCp.ContainsKey(fgCommandSet.Value.Trim('"')))
                        {
                            fgDstIntfsList.AddRange(_interfacesMapperFgCp[fgCommandSet.Value.Trim('"')]);
                        }
                        else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_system_zone_host + fgCommandSet.Value.Trim('"'))) //if FG dstintf is Zone
                        {
                            if (fgDstAddr.Equals("all"))
                            {
                                continue; //don't process "all" for FG dstaddr because we can't route for "all" addresses
                            }
                            if (fgDstAddrsList.Count != 1)
                            {
                                continue; //don't process "multi" FG objects
                            }

                            //get destaddr Object to get its IP address
                            string fgDstAddrChecking = null;
                            CheckPointObject checkPointObject = fgDstAddrsList[0];

                            if (checkPointObject.GetType() == typeof(CheckPoint_Range))
                            {
                                fgDstAddrChecking = ((CheckPoint_Range)checkPointObject).RangeFrom;
                            }
                            else if (checkPointObject.GetType() == typeof(CheckPoint_Host))
                            {
                                fgDstAddrChecking = ((CheckPoint_Host)checkPointObject).IpAddress;
                            }
                            else if (checkPointObject.GetType() == typeof(CheckPoint_Network))
                            {
                                fgDstAddrChecking = ((CheckPoint_Network)checkPointObject).Subnet;
                            }
                            if (fgDstAddrChecking == null)
                            {
                                continue;
                            }
                            IPAddress ipaddress = IPAddress.Parse(fgDstAddrChecking);
                            //get FG Interface(s) object(s) for checked Zone
                            List<CheckPointObject> cpObjsList = _localMapperFgCp[FG_PREFIX_KEY_system_zone_host + fgCommandSet.Value.Trim('"')];
                            //if Zone contains only one Interface : it is simple because dstaddr will be route via that Interface
                            if (cpObjsList.Count == 1)
                            {
                                fgDstIntfsList.AddRange(cpObjsList);
                            }
                            //if Zone contains multi Interface: we should to check:
                            // 1) if dynamic routing is disable
                            // 2) to check which Interface contains network for destaddr
                            // 3) if noone Interface contains network for dstaddr, then we should to use interface with default routing (if default routing exists for some Interface)
                            else if (cpObjsList.Count > 1 && !_localFgDynRoutesEnable)
                            {
                                string intfName = null;
                                int netCidr = -1;
                                string intfNameDefault = null;
                                string zoneName = fgCommandSet.Value.Trim('"').Trim();
                                foreach (string interfaceNameFg in _localFgZoneIntfDict[zoneName]) //check each interface in Zone
                                {
                                    if (_interfacesFgDict.ContainsKey(interfaceNameFg))
                                    {
                                        FgInterface interfaceFg = _interfacesFgDict[interfaceNameFg];
                                        IPNetwork ipnetwork = IPNetwork.Parse(interfaceFg.Ip, interfaceFg.Mask);
                                        if (IPNetwork.Contains(ipnetwork, ipaddress) && netCidr < ipnetwork.Cidr) //check if interface from Zone contains dstaddr network
                                        {
                                            intfName = interfaceNameFg;
                                            netCidr = ipnetwork.Cidr;
                                        }
                                    }

                                    if (_localFgRoutesDict.ContainsKey(interfaceNameFg)) //check static route
                                    {
                                        foreach (FgStaticRoute fgStaticRoute in _localFgRoutesDict[interfaceNameFg])
                                        {
                                            if (fgStaticRoute.Network.Equals("0.0.0.0") && intfNameDefault == null)
                                            {
                                                intfNameDefault = fgStaticRoute.Device;
                                                continue;
                                            }
                                            IPNetwork ipnetwork = IPNetwork.Parse(fgStaticRoute.Network, fgStaticRoute.Mask);
                                            if (IPNetwork.Contains(ipnetwork, ipaddress) && netCidr < ipnetwork.Cidr)
                                            {
                                                intfName = interfaceNameFg;
                                                netCidr = ipnetwork.Cidr;
                                            }
                                        }
                                    }
                                }
                                if (intfName == null)
                                {
                                    intfName = intfNameDefault;
                                }
                                if (intfName != null)
                                {
                                    if (_interfacesMapperFgCp.ContainsKey(intfName))
                                    {
                                        fgDstIntfsList.AddRange(_interfacesMapperFgCp[intfName]);
                                    }
                                }
                            }
                        }
                    }

                    if (fgCommandSet.Field.Equals("srcaddr"))
                    {
                        fgSrcAddrsList.AddRange(GetFgSrcAddrsList(fgCommandSet));
                    }

                    if (fgCommandSet.Field.Equals("comments"))
                    {
                        cpNatRuleComments = fgCommandSet.Value.Trim('"');
                    }

                    if (fgCommandSet.Field.Equals("status") && fgCommandSet.Value.Equals("disable"))
                    {
                        isNatEnable = false;
                    }
                }
            }
            foreach (CheckPointObject cpObjDstIntf in fgDstIntfsList)
            {
                foreach (CheckPointObject cpObjSrcAddr in fgSrcAddrsList)
                {
                    //don't create NAT Rule for Domain objects
                    if (cpObjSrcAddr.GetType() == typeof(CheckPoint_Domain))
                    {
                        _warningsList.Add("NAT rule with matched rule " + cpNatRuleId + " was not created for " + cpObjSrcAddr.Name + " domain object.");
                        continue;
                    }

                    foreach (CheckPointObject cpObjDstAddr in fgDstAddrsList)
                    {
                        //don't create NAT Rule for Domain objects
                        if (cpObjDstAddr.GetType() == typeof(CheckPoint_Domain))
                        {
                            _warningsList.Add("NAT rule with matched rule " + cpNatRuleId + " was not created for " + cpObjDstAddr.Name + " domain object.");
                            continue;
                        }

                        CheckPoint_NAT_Rule cpNatRule = new CheckPoint_NAT_Rule();

                        cpNatRule.Name = GetSafeName(cpNatRuleName + ((++counterNatRules > 0) ? "_" + counterNatRules : ""));
                        cpNatRule.Comments = "Matched rule ID: " + cpNatRuleId + ". ";

                        cpNatRule.Comments += cpNatRuleComments;
                        cpNatRule.Enabled = isNatEnable;

                        cpNatRule.Source = cpObjSrcAddr;
                        cpNatRule.Destination = cpObjDstAddr;
                        cpNatRule.Service = _cpObjects.GetObject(CheckPointObject.Any); // we change all nat hide rules service field to Any for simplicity
                        cpNatRule.TranslatedSource = cpObjDstIntf;
                        cpNatRule.TranslatedDestination = null;
                        cpNatRule.TranslatedService = null;
                        cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Hide;

                        _cpNatRules.Add(cpNatRule);
                        _rulesInNatLayer += 1;

                        if (OptimizeConf)
                        {
                            _cpObjects.AddObject(cpObjSrcAddr);
                            _cpObjects.AddObject(cpObjDstAddr);
                            _cpObjects.AddObject(cpObjDstIntf);
                        }
                    }
                }
            }
            return counterNatRules;
        }

        public int AddNatRuleIpPool(FgCommand_Edit fgCommandEdit, string fgDstAddr, int counterNatRules)
        {
            string cpNatRuleId = fgCommandEdit.Table;
            string cpNatRuleName = "";

            string cpNatRuleComments = "";
            bool isNatEnable = true;

            List<CheckPointObject> fgDstIntfsList = new List<CheckPointObject>();

            List<CheckPointObject> fgSrcAddrsList = new List<CheckPointObject>();
            List<CheckPointObject> fgDstAddrsList = new List<CheckPointObject>();

            foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
            {
                if (fgCommandS.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                    if (fgCommandSet.Field.Equals("name"))
                    {
                        cpNatRuleName = fgCommandSet.Value.Trim('"');
                    }

                    if (fgCommandSet.Field.Equals("poolname"))
                    {
                        string fgDstIntf = fgCommandSet.Value.Trim('"');

                        string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_ippool };
                        foreach (string fgPrefix in fgPrefixes)
                        {
                            if (_localMapperFgCp.ContainsKey(fgPrefix + fgDstIntf))
                            {
                                List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgDstIntf];
                                if (cpObjsList != null && cpObjsList.Count > 0)
                                {
                                    fgDstIntfsList.AddRange(cpObjsList);
                                }
                            }
                        }
                    }

                    if (fgCommandSet.Field.Equals("srcaddr"))
                    {
                        fgSrcAddrsList.AddRange(GetFgSrcAddrsList(fgCommandSet));
                    }

                    if (fgCommandSet.Field.Equals("comments"))
                    {
                        cpNatRuleComments = fgCommandSet.Value.Trim('"');
                    }

                    if (fgCommandSet.Field.Equals("status") && fgCommandSet.Value.Equals("disable"))
                    {
                        isNatEnable = false;
                    }
                }
            }

            if (fgDstAddr.Equals("all"))
            {
                fgDstAddrsList.Add(_cpObjects.GetObject(CheckPointObject.Any));
            }
            else
            {
                foreach (string fgPrefix in (new string[] { FG_PREFIX_KEY_firewall_address, FG_PREFIX_KEY_firewall_addrgrp }))
                {
                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgDstAddr))
                    {
                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgDstAddr];
                        if (cpObjsList != null && cpObjsList.Count > 0)
                        {
                            fgDstAddrsList.AddRange(cpObjsList);
                        }
                    }
                }
            }

            foreach (CheckPointObject cpObjDstIntf in fgDstIntfsList)
            {
                foreach (CheckPointObject cpObjSrcAddr in fgSrcAddrsList)
                {
                    //don't create NAT Rule for Domain objects
                    if (cpObjSrcAddr.GetType() == typeof(CheckPoint_Domain))
                    {
                        _warningsList.Add("NAT rule with matched rule " + cpNatRuleId + " was not created for " + cpObjSrcAddr.Name + " domain object.");
                        continue;
                    }

                    foreach (CheckPointObject cpObjDstAddr in fgDstAddrsList)
                    {
                        //don't create NAT Rule for Domain objects
                        if (cpObjDstAddr.GetType() == typeof(CheckPoint_Domain))
                        {
                            _warningsList.Add("NAT rule with matched rule " + cpNatRuleId + " was not created for " + cpObjDstAddr.Name + " Domain object.");
                            continue;
                        }

                        CheckPoint_NAT_Rule cpNatRule = new CheckPoint_NAT_Rule();

                        cpNatRule.Name = GetSafeName(cpNatRuleName + ((++counterNatRules > 0) ? "_" + counterNatRules : ""));
                        cpNatRule.Comments = "Matched rule ID: " + cpNatRuleId + ". ";

                        cpNatRule.Comments += cpNatRuleComments;
                        cpNatRule.Enabled = isNatEnable;

                        cpNatRule.Source = cpObjSrcAddr;
                        cpNatRule.Destination = cpObjDstAddr;
                        cpNatRule.Service = _cpObjects.GetObject(CheckPointObject.Any); // we change all nat hide rules service field to Any for simplicity
                        cpNatRule.TranslatedSource = cpObjDstIntf;
                        cpNatRule.TranslatedDestination = null;
                        cpNatRule.TranslatedService = null;
                        cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Hide;

                        _cpNatRules.Add(cpNatRule);
                        _rulesInNatLayer += 1;

                        if (OptimizeConf)
                        {
                            _cpObjects.AddObject(cpObjSrcAddr);
                            _cpObjects.AddObject(cpObjDstAddr);
                            _cpObjects.AddObject(cpObjDstIntf);
                        }
                    }
                }
            }
            return counterNatRules;
        }

        public int AddNatRuleVipNatEnable(FgCommand_Edit fgCommandEdit, string fgDstAddr, int counterNatRules)
        {
            string cpNatRuleId = fgCommandEdit.Table;
            string cpNatRuleName = "";

            string cpNatRuleComments = "";
            bool isNatEnable = true;

            bool isIpPoolEnabled = false;

            List<CheckPointObject> fgDstIntfsList = new List<CheckPointObject>();

            List<CheckPointObject> fgSrcAddrsList = new List<CheckPointObject>();

            List<CheckPointObject> fgServicesList = new List<CheckPointObject>();

            foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
            {
                if (fgCommandS.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                    if (fgCommandSet.Field.Equals("name"))
                    {
                        cpNatRuleName = fgCommandSet.Value.Trim('"');
                    }

                    if (fgCommandSet.Field.Equals("dstintf"))
                    {
                        if (!isIpPoolEnabled)
                        {
                            if (_interfacesMapperFgCp.ContainsKey(fgCommandSet.Value.Trim('"')))
                            {
                                fgDstIntfsList.AddRange(_interfacesMapperFgCp[fgCommandSet.Value.Trim('"')]);
                            }
                            else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_system_zone_host + fgCommandSet.Value.Trim('"'))) //if FG dstintf is Zone
                            {
                                if (fgDstAddr.Equals("all"))
                                {
                                    continue; //don't process "all" for FG dstaddr because we can't route for "all" addresses
                                }

                                List<CheckPointObject> fgDstAddrsList = new List<CheckPointObject>();

                                fgDstAddrsList.AddRange(GetFgDstAddrsAsVipExtIpList(fgDstAddr));
                                fgDstAddrsList.AddRange(GetFgDstAddrsAsVipMappedIpList(fgDstAddr));

                                if (fgDstAddrsList.Count != 1)
                                {
                                    continue; //don't process "multi" FG objects
                                }

                                //get destaddr Object to get its IP address
                                string fgDstAddrChecking = null;
                                CheckPointObject checkPointObject = fgDstAddrsList[0];

                                if (checkPointObject.GetType() == typeof(CheckPoint_Range))
                                {
                                    fgDstAddrChecking = ((CheckPoint_Range)checkPointObject).RangeFrom;
                                }
                                else if (checkPointObject.GetType() == typeof(CheckPoint_Host))
                                {
                                    fgDstAddrChecking = ((CheckPoint_Host)checkPointObject).IpAddress;
                                }
                                else if (checkPointObject.GetType() == typeof(CheckPoint_Network))
                                {
                                    fgDstAddrChecking = ((CheckPoint_Network)checkPointObject).Subnet;
                                }
                                if (fgDstAddrChecking == null)
                                {
                                    continue;
                                }
                                IPAddress ipaddress = IPAddress.Parse(fgDstAddrChecking);
                                //get FG Interface(s) object(s) for checked Zone
                                List<CheckPointObject> cpObjsList = _localMapperFgCp[FG_PREFIX_KEY_system_zone_host + fgCommandSet.Value.Trim('"')];
                                //if Zone contains only one Interface : it is simple because dstaddr will be route via that Interface
                                if (cpObjsList.Count == 1)
                                {
                                    fgDstIntfsList.AddRange(cpObjsList);
                                }
                                //if Zone contains multi Interface: we should to check:
                                // 1) if dynamic routing is disable
                                // 2) to check which Interface contains network for destaddr
                                // 3) if noone Interface contains network for dstaddr, then we should to use interface with default routing (if default routing exists for some Interface)
                                else if (cpObjsList.Count > 1 && !_localFgDynRoutesEnable)
                                {
                                    string intfName = null;
                                    int netCidr = -1;
                                    string intfNameDefault = null;
                                    string zoneName = fgCommandSet.Value.Trim('"').Trim();
                                    foreach (string interfaceNameFg in _localFgZoneIntfDict[zoneName]) //check each interface in Zone
                                    {
                                        if (_interfacesFgDict.ContainsKey(interfaceNameFg))
                                        {
                                            FgInterface interfaceFg = _interfacesFgDict[interfaceNameFg];
                                            IPNetwork ipnetwork = IPNetwork.Parse(interfaceFg.Ip, interfaceFg.Mask);
                                            if (IPNetwork.Contains(ipnetwork, ipaddress) && netCidr < ipnetwork.Cidr) //check if interface from Zone contains dstaddr network
                                            {
                                                intfName = interfaceNameFg;
                                                netCidr = ipnetwork.Cidr;
                                            }
                                        }

                                        if (_localFgRoutesDict.ContainsKey(interfaceNameFg)) //check static route
                                        {
                                            foreach (FgStaticRoute fgStaticRoute in _localFgRoutesDict[interfaceNameFg])
                                            {
                                                if (fgStaticRoute.Network.Equals("0.0.0.0") && intfNameDefault == null)
                                                {
                                                    intfNameDefault = fgStaticRoute.Device;
                                                    continue;
                                                }
                                                IPNetwork ipnetwork = IPNetwork.Parse(fgStaticRoute.Network, fgStaticRoute.Mask);
                                                if (IPNetwork.Contains(ipnetwork, ipaddress) && netCidr < ipnetwork.Cidr)
                                                {
                                                    intfName = interfaceNameFg;
                                                    netCidr = ipnetwork.Cidr;
                                                }
                                            }
                                        }
                                    }
                                    if (intfName == null)
                                    {
                                        intfName = intfNameDefault;
                                    }
                                    if (intfName != null)
                                    {
                                        if (_interfacesMapperFgCp.ContainsKey(intfName))
                                        {
                                            fgDstIntfsList.AddRange(_interfacesMapperFgCp[intfName]);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (fgCommandSet.Field.Equals("srcaddr"))
                    {
                        fgSrcAddrsList.AddRange(GetFgSrcAddrsList(fgCommandSet));
                    }

                    if (fgCommandSet.Field.Equals("service"))
                    {
                        fgServicesList.AddRange(GetFgServicesList(fgCommandSet));
                    }

                    if (fgCommandSet.Field.Equals("comments"))
                    {
                        cpNatRuleComments = fgCommandSet.Value.Trim('"');
                    }

                    if (fgCommandSet.Field.Equals("status") && fgCommandSet.Value.Equals("disable"))
                    {
                        isNatEnable = false;
                    }

                    if (fgCommandSet.Field.Equals("ippool") && fgCommandSet.Value.Equals("enable"))
                    {
                        isIpPoolEnabled = true;
                    }

                    if (fgCommandSet.Field.Equals("poolname"))
                    {
                        string fgDstIntf = fgCommandSet.Value.Trim('"');

                        fgDstIntfsList.Clear();

                        string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_ippool };
                        foreach (string fgPrefix in fgPrefixes)
                        {
                            if (_localMapperFgCp.ContainsKey(fgPrefix + fgDstIntf))
                            {
                                List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgDstIntf];
                                if (cpObjsList != null && cpObjsList.Count > 0)
                                {
                                    fgDstIntfsList.AddRange(cpObjsList);
                                }
                            }
                        }
                    }
                }
            }

            if (isIpPoolEnabled)
            {
                foreach (CheckPointObject cpObjDstIntf in fgDstIntfsList)
                {
                    foreach (CheckPointObject cpObjSrcAddr in fgSrcAddrsList)
                    {
                        //don't create NAT Rule for Domain objects
                        if (cpObjSrcAddr.GetType() == typeof(CheckPoint_Domain))
                        {
                            _warningsList.Add("NAT rule with matched rule " + cpNatRuleId + " was not created for " + cpObjSrcAddr.Name + " domain object.");
                            continue;
                        }

                        List<CheckPointObject> fgDstAddrsVipExtIpList = new List<CheckPointObject>();
                        List<CheckPointObject> fgDstAddrsVipMappedIpList = new List<CheckPointObject>();

                        fgDstAddrsVipExtIpList.AddRange(GetFgDstAddrsAsVipExtIpList(fgDstAddr));
                        fgDstAddrsVipMappedIpList.AddRange(GetFgDstAddrsAsVipMappedIpList(fgDstAddr));

                        bool isPortForwardEnabled = false;

                        if (_vipPortForwardEnabledMapper.ContainsKey(fgDstAddr))
                        {
                            isPortForwardEnabled = _vipPortForwardEnabledMapper[fgDstAddr];
                        }

                        foreach (CheckPointObject cpObjDstAddrVipExtIp in fgDstAddrsVipExtIpList)
                        {
                            foreach (CheckPointObject cpObjDstAddrVipMappedIp in fgDstAddrsVipMappedIpList)
                            {
                                if (isPortForwardEnabled)
                                {
                                    List<CheckPointObject> listOrigSrv = GetFgDstAddrToOSAsVipExtIpList(fgDstAddr);
                                    List<CheckPointObject> listTransSrv = GetFgDstAddrToOSAsVipMapIpList(fgDstAddr);
                                    foreach (CheckPointObject cpOrigSrv in listOrigSrv)
                                    {
                                        foreach (CheckPointObject cpTransSrv in listTransSrv)
                                        {
                                            CheckPoint_NAT_Rule cpNatRule = new CheckPoint_NAT_Rule();

                                            cpNatRule.Name = GetSafeName(cpNatRuleName + ((++counterNatRules > 0) ? "_" + counterNatRules : ""));
                                            cpNatRule.Comments = "Matched rule ID: " + cpNatRuleId + ". ";

                                            cpNatRule.Comments += cpNatRuleComments;
                                            cpNatRule.Enabled = isNatEnable;

                                            cpNatRule.Source = cpObjSrcAddr;
                                            cpNatRule.Destination = cpObjDstAddrVipExtIp;

                                            cpNatRule.Service = cpOrigSrv;

                                            cpNatRule.TranslatedSource = cpObjDstIntf;

                                            cpNatRule.TranslatedDestination = cpObjDstAddrVipMappedIp;

                                            cpNatRule.TranslatedService = cpTransSrv;

                                            cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Hide;

                                            _cpNatRules.Add(cpNatRule);

                                            _rulesInNatLayer += 1;

                                            if (OptimizeConf)
                                            {
                                                _cpObjects.AddObject(cpObjSrcAddr);
                                                _cpObjects.AddObject(cpObjDstAddrVipExtIp);
                                                _cpObjects.AddObject(cpObjDstAddrVipMappedIp);
                                                _cpObjects.AddObject(cpOrigSrv);
                                                _cpObjects.AddObject(cpTransSrv);
                                                _cpObjects.AddObject(cpObjDstIntf);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    foreach (CheckPointObject cpObjSrv in fgServicesList)
                                    {
                                        CheckPoint_NAT_Rule cpNatRule = new CheckPoint_NAT_Rule();

                                        cpNatRule.Name = GetSafeName(cpNatRuleName + ((++counterNatRules > 0) ? "_" + counterNatRules : ""));
                                        cpNatRule.Comments = "Matched rule ID: " + cpNatRuleId + ". ";

                                        cpNatRule.Comments += cpNatRuleComments;
                                        cpNatRule.Enabled = isNatEnable;

                                        cpNatRule.Source = cpObjSrcAddr;
                                        cpNatRule.Destination = cpObjDstAddrVipExtIp;

                                        cpNatRule.Service = cpObjSrv;

                                        cpNatRule.TranslatedSource = cpObjDstIntf;
                                        cpNatRule.TranslatedDestination = cpObjDstAddrVipMappedIp;

                                        cpNatRule.TranslatedService = null;

                                        cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Hide;

                                        _cpNatRules.Add(cpNatRule);
                                        _rulesInNatLayer += 1;

                                        if (OptimizeConf)
                                        {
                                            _cpObjects.AddObject(cpObjSrcAddr);
                                            _cpObjects.AddObject(cpObjDstAddrVipExtIp);
                                            _cpObjects.AddObject(cpObjDstAddrVipMappedIp);
                                            _cpObjects.AddObject(cpObjSrv);
                                            _cpObjects.AddObject(cpObjDstIntf);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                foreach (CheckPointObject cpObjDstIntf in fgDstIntfsList)
                {
                    foreach (CheckPointObject cpObjSrcAddr in fgSrcAddrsList)
                    {
                        //don't create NAT Rule for Domain objects
                        if (cpObjSrcAddr.GetType() == typeof(CheckPoint_Domain))
                        {
                            _warningsList.Add("NAT rule with matched rule " + cpNatRuleId + " was not created for " + cpObjSrcAddr.Name + " domain object.");
                            continue;
                        }

                        List<CheckPointObject> fgDstAddrsVipExtIpList = new List<CheckPointObject>();
                        List<CheckPointObject> fgDstAddrsVipMappedIpList = new List<CheckPointObject>();

                        fgDstAddrsVipExtIpList.AddRange(GetFgDstAddrsAsVipExtIpList(fgDstAddr));
                        fgDstAddrsVipMappedIpList.AddRange(GetFgDstAddrsAsVipMappedIpList(fgDstAddr));

                        bool isPortForwardEnabled = false;

                        if (_vipPortForwardEnabledMapper.ContainsKey(fgDstAddr))
                        {
                            isPortForwardEnabled = _vipPortForwardEnabledMapper[fgDstAddr];
                        }

                        foreach (CheckPointObject cpObjDstAddrVipExtIp in fgDstAddrsVipExtIpList)
                        {
                            foreach (CheckPointObject cpObjDstAddrVipMappedIp in fgDstAddrsVipMappedIpList)
                            {
                                if (isPortForwardEnabled)
                                {
                                    List<CheckPointObject> listOrigSrv = GetFgDstAddrToOSAsVipExtIpList(fgDstAddr);
                                    List<CheckPointObject> listTransSrv = GetFgDstAddrToOSAsVipMapIpList(fgDstAddr);
                                    foreach (CheckPointObject cpOrigSrv in listOrigSrv)
                                    {
                                        foreach (CheckPointObject cpTransSrv in listTransSrv)
                                        {
                                            CheckPoint_NAT_Rule cpNatRule = new CheckPoint_NAT_Rule();

                                            cpNatRule.Name = GetSafeName(cpNatRuleName + ((++counterNatRules > 0) ? "_" + counterNatRules : ""));
                                            cpNatRule.Comments = "Matched rule ID: " + cpNatRuleId + ". ";

                                            cpNatRule.Comments += cpNatRuleComments;
                                            cpNatRule.Enabled = isNatEnable;

                                            cpNatRule.Source = cpObjSrcAddr;
                                            cpNatRule.Destination = cpObjDstAddrVipExtIp;

                                            cpNatRule.Service = cpOrigSrv;

                                            cpNatRule.TranslatedSource = cpObjDstIntf;

                                            cpNatRule.TranslatedDestination = cpObjDstAddrVipMappedIp;

                                            cpNatRule.TranslatedService = cpTransSrv;

                                            cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Hide;

                                            _cpNatRules.Add(cpNatRule);

                                            _rulesInNatLayer += 1;

                                            if (OptimizeConf)
                                            {
                                                _cpObjects.AddObject(cpObjSrcAddr);
                                                _cpObjects.AddObject(cpObjDstAddrVipExtIp);
                                                _cpObjects.AddObject(cpObjDstAddrVipMappedIp);
                                                _cpObjects.AddObject(cpOrigSrv);
                                                _cpObjects.AddObject(cpTransSrv);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    foreach (CheckPointObject cpObjSrv in fgServicesList)
                                    {
                                        CheckPoint_NAT_Rule cpNatRule = new CheckPoint_NAT_Rule();

                                        cpNatRule.Name = GetSafeName(cpNatRuleName + ((++counterNatRules > 0) ? "_" + counterNatRules : ""));
                                        cpNatRule.Comments = "Matched rule ID: " + cpNatRuleId + ". ";

                                        cpNatRule.Comments += cpNatRuleComments;
                                        cpNatRule.Enabled = isNatEnable;

                                        cpNatRule.Source = cpObjSrcAddr;
                                        cpNatRule.Destination = cpObjDstAddrVipExtIp;

                                        cpNatRule.Service = cpObjSrv;

                                        cpNatRule.TranslatedSource = cpObjDstIntf;
                                        cpNatRule.TranslatedDestination = cpObjDstAddrVipMappedIp;

                                        cpNatRule.TranslatedService = null;

                                        cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Hide;

                                        _cpNatRules.Add(cpNatRule);
                                        _rulesInNatLayer += 1;

                                        if (OptimizeConf)
                                        {
                                            _cpObjects.AddObject(cpObjSrcAddr);
                                            _cpObjects.AddObject(cpObjDstAddrVipExtIp);
                                            _cpObjects.AddObject(cpObjDstAddrVipMappedIp);
                                            _cpObjects.AddObject(cpObjSrv);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return counterNatRules;
        }

        public int AddNatRuleVipNatDisable(FgCommand_Edit fgCommandEdit, string fgDstAddr, int counterNatRules)
        {
            string cpNatRuleId = fgCommandEdit.Table;
            string cpNatRuleName = "";

            string cpNatRuleComments = "";
            bool isNatEnable = true;

            List<CheckPointObject> fgSrcAddrsList = new List<CheckPointObject>();

            List<CheckPointObject> fgServicesList = new List<CheckPointObject>();

            foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
            {
                if (fgCommandS.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                    if (fgCommandSet.Field.Equals("name"))
                    {
                        cpNatRuleName = fgCommandSet.Value.Trim('"');
                    }

                    if (fgCommandSet.Field.Equals("srcaddr"))
                    {
                        fgSrcAddrsList.AddRange(GetFgSrcAddrsList(fgCommandSet));
                    }

                    if (fgCommandSet.Field.Equals("service"))
                    {
                        fgServicesList.AddRange(GetFgServicesList(fgCommandSet));
                    }

                    if (fgCommandSet.Field.Equals("comments"))
                    {
                        cpNatRuleComments = fgCommandSet.Value.Trim('"');
                    }

                    if (fgCommandSet.Field.Equals("status") && fgCommandSet.Value.Equals("disable"))
                    {
                        isNatEnable = false;
                    }
                }
            }

            foreach (CheckPointObject cpObjSrcAddr in fgSrcAddrsList)
            {
                //don't create NAT Rule for Domain objects
                if (cpObjSrcAddr.GetType() == typeof(CheckPoint_Domain))
                {
                    _warningsList.Add("NAT rule with matched rule " + cpNatRuleId + " was not created for " + cpObjSrcAddr.Name + " domain object.");
                    continue;
                }

                List<CheckPointObject> fgDstAddrsVipExtIpList = new List<CheckPointObject>();
                List<CheckPointObject> fgDstAddrsVipMappedIpList = new List<CheckPointObject>();

                fgDstAddrsVipExtIpList.AddRange(GetFgDstAddrsAsVipExtIpList(fgDstAddr));
                fgDstAddrsVipMappedIpList.AddRange(GetFgDstAddrsAsVipMappedIpList(fgDstAddr));

                bool isPortForwardEnabled = false;

                if (_vipPortForwardEnabledMapper.ContainsKey(fgDstAddr))
                {
                    isPortForwardEnabled = _vipPortForwardEnabledMapper[fgDstAddr];
                }

                foreach (CheckPointObject cpObjDstAddrVipExtIp in fgDstAddrsVipExtIpList)
                {
                    foreach (CheckPointObject cpObjDstAddrVipMappedIp in fgDstAddrsVipMappedIpList)
                    {
                        if (isPortForwardEnabled)
                        {
                            List<CheckPointObject> listOrigSrv = GetFgDstAddrToOSAsVipExtIpList(fgDstAddr);
                            List<CheckPointObject> listTransSrv = GetFgDstAddrToOSAsVipMapIpList(fgDstAddr);
                            foreach (CheckPointObject cpOrigSrv in listOrigSrv)
                            {
                                foreach (CheckPointObject cpTransSrv in listTransSrv)
                                {
                                    CheckPoint_NAT_Rule cpNatRule = new CheckPoint_NAT_Rule();

                                    cpNatRule.Name = GetSafeName(cpNatRuleName + ((++counterNatRules > 0) ? "_" + counterNatRules : ""));
                                    cpNatRule.Comments = "Matched rule ID: " + cpNatRuleId + ". ";

                                    cpNatRule.Comments += cpNatRuleComments;
                                    cpNatRule.Enabled = isNatEnable;

                                    cpNatRule.Source = cpObjSrcAddr;
                                    cpNatRule.Destination = cpObjDstAddrVipExtIp;

                                    cpNatRule.Service = cpOrigSrv;

                                    cpNatRule.TranslatedSource = null;

                                    cpNatRule.TranslatedDestination = cpObjDstAddrVipMappedIp;

                                    cpNatRule.TranslatedService = cpTransSrv;

                                    cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Static;

                                    _cpNatRules.Add(cpNatRule);

                                    _rulesInNatLayer += 1;

                                    if (OptimizeConf)
                                    {
                                        _cpObjects.AddObject(cpObjSrcAddr);
                                        _cpObjects.AddObject(cpObjDstAddrVipExtIp);
                                        _cpObjects.AddObject(cpObjDstAddrVipMappedIp);
                                        _cpObjects.AddObject(cpOrigSrv);
                                        _cpObjects.AddObject(cpTransSrv);
                                    }
                                }
                            }
                        }
                        else
                        {
                            foreach (CheckPointObject cpObjSrv in fgServicesList)
                            {
                                CheckPoint_NAT_Rule cpNatRule = new CheckPoint_NAT_Rule();

                                cpNatRule.Name = GetSafeName(cpNatRuleName + ((++counterNatRules > 0) ? "_" + counterNatRules : ""));
                                cpNatRule.Comments = "Matched rule ID: " + cpNatRuleId + ". ";

                                cpNatRule.Comments += cpNatRuleComments;
                                cpNatRule.Enabled = isNatEnable;

                                cpNatRule.Source = cpObjSrcAddr;
                                cpNatRule.Destination = cpObjDstAddrVipExtIp;

                                cpNatRule.Service = cpObjSrv;

                                cpNatRule.TranslatedSource = null;
                                cpNatRule.TranslatedDestination = cpObjDstAddrVipMappedIp;

                                cpNatRule.TranslatedService = null;

                                cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Static;

                                _cpNatRules.Add(cpNatRule);
                                _rulesInNatLayer += 1;

                                if (OptimizeConf)
                                {
                                    _cpObjects.AddObject(cpObjSrcAddr);
                                    _cpObjects.AddObject(cpObjDstAddrVipExtIp);
                                    _cpObjects.AddObject(cpObjDstAddrVipMappedIp);
                                    _cpObjects.AddObject(cpObjSrv);
                                }
                            }
                        }
                    }
                }
            }
            return counterNatRules;
        }

        #endregion

        #region Converter Common methods

        //method checks if some part of Zone Name contains reservered word
        // return null if not
        // return message if yes

        public string CheckZoneForReservedWords(CheckPoint_Zone inZone)
        {
            string retMessage = null;

            string inZoneNameNew = Validators.ChangeNameAccordingToRules(inZone.Name);

            if (!inZone.Name.Equals(inZoneNameNew))
            {
                retMessage = inZone.Name + " zone was renamed to " + inZoneNameNew + " for solving 'reserved words' issue.";
                inZone.Name = inZoneNameNew;
            }

            return retMessage;
        }

        public void AddCpObjectToLocalMapper(String fgObjectName, CheckPointObject cpObject)
        {
            List<CheckPointObject> cpObjectsList = null;
            if (_localMapperFgCp.ContainsKey(fgObjectName))
            {
                cpObjectsList = _localMapperFgCp[fgObjectName];
            }
            else
            {
                cpObjectsList = new List<CheckPointObject>();
            }

            //check the name of Object
            if (cpObject.GetType() == typeof(CheckPoint_TcpService))
            {
                if (!char.IsLetter(cpObject.Name, 0))
                {
                    string newName = "TCP_" + cpObject.Name;
                    _warningsList.Add(cpObject.Name + " tcp-service was renamed to " + newName);
                    cpObject.Name = newName;
                }
            }
            else if (cpObject.GetType() == typeof(CheckPoint_UdpService))
            {
                if (!char.IsLetter(cpObject.Name, 0))
                {
                    string newName = "UDP_" + cpObject.Name;
                    _warningsList.Add(cpObject.Name + " udp-service was renamed to " + newName);
                    cpObject.Name = newName;
                }
            }
            else if (cpObject.GetType() == typeof(CheckPoint_SctpService))
            {
                if (!char.IsLetter(cpObject.Name, 0))
                {
                    string newName = "SCTP_" + cpObject.Name;
                    _warningsList.Add(cpObject.Name + " sctp-service was renamed to " + newName);
                    cpObject.Name = newName;
                }
            }
            else if (cpObject.GetType() == typeof(CheckPoint_IcmpService))
            {
                if (!char.IsLetter(cpObject.Name, 0))
                {
                    string newName = "ICMP_" + cpObject.Name;
                    _warningsList.Add(cpObject.Name + " icmp-service was renamed to " + newName);
                    cpObject.Name = newName;
                }
            }
            else if (cpObject.GetType() == typeof(CheckPoint_OtherService))
            {
                if (!char.IsLetter(cpObject.Name, 0))
                {
                    string newName = "OTHER_" + cpObject.Name;
                    _warningsList.Add(cpObject.Name + " other-service was renamed to " + newName);
                    cpObject.Name = newName;
                }
            }
            else if (cpObject.GetType() == typeof(CheckPoint_Time))
            {
                string cpTimeName = cpObject.Name;

                if (cpTimeName.Length > 11)
                {
                    cpTimeName = cpTimeName.Substring(0, 6) + "_c" + _timeCutterCounter++;
                }

                if (!cpTimeName.Equals(cpObject.Name))
                {
                    _warningsList.Add(cpObject.Name + " time object was renamed to " + cpTimeName);
                    cpObject.Name = cpTimeName;
                }
            }
            else if (cpObject.GetType() == typeof(CheckPoint_TimeGroup))
            {
                string cpTimeGrpName = cpObject.Name;

                if (cpTimeGrpName.Length > 11)
                {
                    cpTimeGrpName = cpTimeGrpName.Substring(0, 6) + "_c" + _timeGroupCutterCounter++;
                }

                if (!cpTimeGrpName.Equals(cpObject.Name))
                {
                    _warningsList.Add(cpObject.Name + " time group object was renamed to " + cpTimeGrpName);
                    cpObject.Name = cpTimeGrpName;
                }
            }

            bool isNameExist = true;

            int zIndex = 0;

            string cpObjectName = cpObject.Name;

            if (!string.IsNullOrEmpty(cpObjectName))
            {
                while (isNameExist)
                {
                    isNameExist = false;

                    foreach (CheckPointObject cpObj in cpObjectsList)
                    {
                        if (cpObj.Name.Trim().ToLower().Equals(cpObjectName.Trim().ToLower()))
                        {
                            isNameExist = true;

                            zIndex += 1;

                            cpObjectName = cpObject.Name + "_" + zIndex;

                            break;
                        }
                    }
                }


                if (!cpObject.Name.Equals(cpObjectName))
                {
                    _warningsList.Add(cpObject.Name + " object was renamed to " + cpObjectName + " for solving duplicate names issue.");
                    cpObject.Name = cpObjectName;
                }

                cpObjectsList.Add(cpObject);

                _localMapperFgCp[fgObjectName] = cpObjectsList;
            }
        }

        #endregion

        public static string GetSafeName(string name)
        {
            if (name != null && !name.Trim().Equals(""))
            {
                name = Validators.ChangeNameAccordingToRules(name);
                return Regex.Replace(name, @"[^A-Za-z0-9_.-]", "_");
            }
            else
            {
                return name;
            }
        }

        public List<string> GetVipGroupMembers(string vipGrpName)
        {
            List<string> retList = new List<string>();

            List<string> vipGrpMembers = _localFgVipGrpsDict[vipGrpName];

            foreach (string vipGrpMember in vipGrpMembers)
            {
                if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_extip + vipGrpMember) ||
                    _localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_mappedip + vipGrpMember))
                {
                    retList.Add(vipGrpMember);
                }
                else if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_grp + vipGrpMember))
                {
                    retList.AddRange(GetVipGroupMembers(vipGrpMember));
                }
            }

            return retList;
        }

        protected override string GetVendorName()
        {
            return Vendor.FortiGate.ToString();
        }

        /// <summary>
        /// Generate a list of firewall objects names whitch was used in politycs
        /// </summary>
        /// <param name="fgCommandsList">parsed config file</param>
        /// <returns>set of names</returns>
        public HashSet<string> CreateUsedInPoliciesObjects(List<FgCommand> fgCommandsList)
        {
            FgCommand_Config firewall_policy_search = null;
            HashSet<string> UsedObjInFirewall = new HashSet<string>();      //used objects in policies
            foreach (FgCommand fgCommand in fgCommandsList)
            {
                if (fgCommand.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommand;

                    if (fgCommandConfig.ObjectName.Equals("firewall policy"))
                    {
                        firewall_policy_search = fgCommandConfig;
                        break;
                    }

                }
            }
            if (firewall_policy_search != null)
            {
                foreach (FgCommand_Edit subCommand in firewall_policy_search.SubCommandsList)
                {
                    foreach (FgCommand subCommand_addr in subCommand.SubCommandsList)
                    {
                        if (subCommand_addr.GetType() == typeof(FgCommand_Set))
                        {
                            var subCommand_addr_set = (FgCommand_Set)subCommand_addr;
                            if (subCommand_addr_set.Field.Equals("dstaddr") ||
                                subCommand_addr_set.Field.Equals("srcaddr") ||
                                subCommand_addr_set.Field.Equals("srcintf") ||
                                subCommand_addr_set.Field.Equals("dstintf"))
                            {
                                List<string> objects = subCommand_addr_set.Value.Split(' ').ToList();
                                foreach (string obj in objects)
                                    UsedObjInFirewall.Add(obj.Replace('"', ' ').Trim());
                            }
                        }
                    }
                }
                UsedObjInFirewall.Remove("all");
            }
            return UsedObjInFirewall;
        }

        /// <summary>
        /// Validate objects (domains, hosts, members) for any conflicts
        /// </summary>
        /// <param name="fgCommandsList">parsed elements</param>
        /// <returns>List of validation problems. If no problems return list will empty</returns>
        private HashSet<string> ValidateConversion(List<FgCommand> fgCommandsList)
        {
            HashSet<string> output = new HashSet<string>();
            Dictionary<string, string> portsTcp = new Dictionary<string, string>();       //list of used ports for TCP <port, service>
            Dictionary<string, string> portsUdp = new Dictionary<string, string>();       //list of used ports for UDP <port, service>
            HashSet<string> groupNames = new HashSet<string>();                     //set of groups names for check duplicates 

            foreach (FgCommand parsedElement in fgCommandsList)
            {
                //check ports TCP/UDP
                if (parsedElement.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config parsedElementConfig = (FgCommand_Config)parsedElement;
                    if (parsedElementConfig.ObjectName.Contains("firewall service custom"))
                    {
                        foreach (FgCommand_Edit parsedElementService in parsedElementConfig.SubCommandsList)
                        {
                            foreach (FgCommand parsedElementServiceUntypedSet in parsedElementService.SubCommandsList)
                            {
                                FgCommand_Set parsedElementServiceSet;
                                if (parsedElementServiceUntypedSet.GetType() == typeof(FgCommand_Set))
                                    parsedElementServiceSet = (FgCommand_Set)parsedElementServiceUntypedSet;
                                else
                                    continue;
                                //TCP port
                                if (parsedElementServiceSet.Field.Equals("tcp-portrange"))
                                {
                                    string[] ports = parsedElementServiceSet.Value.Split(' ');
                                    foreach (string port in ports)
                                    {
                                        bool isFound;
                                        string cpServiceName = _cpObjects.GetKnownServiceName("TCP_" + port, out isFound);

                                        if (isFound)
                                        {
                                            continue;
                                        }
                                        else
                                        {
                                            if (portsTcp.ContainsKey(port))
                                            {
                                                output.Add($"Conversion validation error: a TCP port {port} already used by service {portsTcp[port]}, but service {parsedElementService.Table} trying to use it");
                                            }
                                            else
                                            {
                                                portsTcp.Add(port, parsedElementService.Table);
                                            }
                                        }
                                    }

                                }
                                //UDP
                                if (parsedElementServiceSet.Field.Equals("udp-portrange"))
                                {
                                    string[] ports = parsedElementServiceSet.Value.Split(' ');
                                    foreach (string port in ports)
                                    {
                                        bool isFound;
                                        string cpServiceName = _cpObjects.GetKnownServiceName("UDP_" + port, out isFound);

                                        if (isFound)
                                        {
                                            continue;
                                        }
                                        else
                                        {
                                            if (portsUdp.ContainsKey(port))
                                            {
                                                output.Add($"Conversion validation error: a UDP port {port} already used by service {portsUdp[port]}, but service {parsedElementService.Table} trying to use it");
                                            }
                                            else
                                            {
                                                portsUdp.Add(port, parsedElementService.Table);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    //check group duplicate members
                    else if (parsedElementConfig.ObjectName.Contains("firewall addrgrp"))
                    {
                        foreach (FgCommand_Edit parsedElementGroup in parsedElementConfig.SubCommandsList)
                        {
                            foreach (FgCommand parsedElementGroupUntypedSet in parsedElementGroup.SubCommandsList)
                            {
                                FgCommand_Set parsedElementGroupSet;
                                if (parsedElementGroupUntypedSet.GetType() == typeof(FgCommand_Set))
                                    parsedElementGroupSet = (FgCommand_Set)parsedElementGroupUntypedSet;
                                else
                                    continue;
                                if (parsedElementGroupSet.Field.Equals("member"))
                                {
                                    string[] members = parsedElementGroupSet.Value.Split(new string[] { @""" """ }, StringSplitOptions.None);
                                    foreach (string member in members)
                                    {
                                        int count = 0;
                                        foreach (string memberCheck in members)
                                        {
                                            if (memberCheck.Equals(member))
                                                ++count;
                                        }
                                        if (count > 1)
                                            output.Add($"At the group {parsedElementGroup.Table} found duplicates for member {member}");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return output;
        }
    }

    public class FgInterface
    {
        public string Name { get; set; }
        public string Ip { get; set; }
        public string Network { get; set; }
        public string Mask { get; set; }
    }

    public class FgStaticRoute
    {
        public FgStaticRoute() { }
        public FgStaticRoute (string name, string network, string mask, string gateway, string device) : this()
        {
            Name = string.IsNullOrEmpty(name) ? string.Empty : name;
            Network = string.IsNullOrEmpty(network) ? string.Empty : network;
            Mask = string.IsNullOrEmpty(mask) ? string.Empty : mask;
            Gateway = string.IsNullOrEmpty(gateway) ? string.Empty : gateway;
            Device = string.IsNullOrEmpty(device) ? string.Empty : device;
        }
        public string Name { get; set; }
        public string Network { get; set; }
        public string Mask { get; set; }
        public string Gateway { get; set; }
        public string Device { get; set; }
    }

    public class FgJsonOutputReportsList
    {
        public string header;
        public Dictionary<int, string> reports;

        public FgJsonOutputReportsList()
        {
            reports = new Dictionary<int, string>();
        }
    }
}


public class NewAnalizStatistic
{
    public int _optPackageCount = 0;
    public int _fullrullPackcount = 0;
    public int _fullrullPackageCount = 0;
    public int _totalrullPackageCount = 0;
    public int _totalNetworkObjectsCount = 0;
    public int _unusedNetworkObjectsCount = 0;
    public int _duplicateNetworkObjectsCount = 0;
    public int _nestedNetworkGroupsCount = 0;
    public int _nestedNetworkGroupsCountAll = 0;

    public int _totalServicesObjectsCount = 0;
    public int _unusedServicesObjectsCount = 0;
    public int _duplicateServicesObjectsCount = 0;
    public int _nestedServicesGroupsCount = 0;
    public int _nestedServicesGroupsCountAll = 0;

    public int _totalServicesRulesCount = 0;
    public int _totalServicesRulesOptCount = 0;
    public int _rulesServicesutilizingServicesAnyCount = 0;
    public int _rulesServicesutilizingServicesAnySourceCount = 0;
    public int _rulesServicesutilizingServicesAnyDestinationCount = 0;
    public int _rulesServicesutilizingServicesAnyServiceCount = 0;
    public int _disabledServicesRulesCount = 0;
    public int _unnamedServicesRulesCount = 0;
    public int _timesServicesRulesCount = 0;
    public int _nonServicesLoggingServicesRulesCount = 0;
    public int _stealthServicesRuleCount = 0;
    public int _cleanupServicesRuleCount = 0;
    public int _uncommentedServicesRulesCount = 0;

    public int _totalFileRules = 0;
    public int _totalFileRulesOpt = 0;


    public int TotalNetworkObjectsPercent { get { return 100; } }
    public float UnusedNetworkObjectsPercent { get { return _totalNetworkObjectsCount > 0 ? ((float)_unusedNetworkObjectsCount / (float)_totalNetworkObjectsCount) * 100 : 0; } }
    public float DuplicateNetworkObjectsPercent { get { return _totalNetworkObjectsCount > 0 ? ((float)_duplicateNetworkObjectsCount / (float)_totalNetworkObjectsCount) * 100 : 0; } }
    public float NestedNetworkGroupsPercent { get { return _nestedNetworkGroupsCountAll > 0 ? ((float)_nestedNetworkGroupsCount / (float)_nestedNetworkGroupsCountAll) * 100 : 0; } }

    public float TotalServicesObjectsPercent { get { return 100; } }
    public float UnusedServicesObjectsPercent { get { return _totalServicesObjectsCount > 0 ? ((float)_unusedServicesObjectsCount / (float)_totalServicesObjectsCount) * 100 : 0; } }
    public float DuplicateServicesObjectsPercent { get { return _totalServicesObjectsCount > 0 ? ((float)_duplicateServicesObjectsCount / (float)_totalServicesObjectsCount) * 100 : 0; } }
    public float NestedServicesGroupsPercent { get { return _nestedServicesGroupsCountAll > 0 ? ((float)_nestedServicesGroupsCount / (float)_nestedServicesGroupsCountAll) * 100 : 0; } }

    public float TotalServicesRulesPercent { get { return 100; } }
    public float RulesServicesutilizingServicesAnyPercent { get { return _totalServicesRulesCount > 0 ? ((float)_rulesServicesutilizingServicesAnyCount / (float)_totalServicesRulesCount) * 100 : 0; } }
    public float DisabledServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_disabledServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
    public float UnnamedServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_unnamedServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
    public float TimesServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_timesServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
    public float NonServicesLoggingServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_nonServicesLoggingServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
    public float StealthServicesRulePercent { get { return _totalServicesRulesCount > 0 ? ((float)_stealthServicesRuleCount / (float)_totalServicesRulesCount) * 100 : 0; } }
    public float CleanupServicesRulePercent { get { return _totalServicesRulesCount > 0 ? ((float)_cleanupServicesRuleCount / (float)_totalServicesRulesCount) * 100 : 0; } }
    public float UncommentedServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_uncommentedServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }

    public NewAnalizStatistic(int fullpackcount, int totalpack)
    {
        _fullrullPackageCount = fullpackcount;
        _totalrullPackageCount = totalpack;
    }

    public void Flush()
    {
        _fullrullPackcount = 0;
        _totalServicesRulesCount = 0;
        _rulesServicesutilizingServicesAnyCount = 0;
        _rulesServicesutilizingServicesAnySourceCount = 0;
        _rulesServicesutilizingServicesAnyDestinationCount = 0;
        _rulesServicesutilizingServicesAnyServiceCount = 0;
        _disabledServicesRulesCount = 0;
        _unnamedServicesRulesCount = 0;
        _timesServicesRulesCount = 0;
        _nonServicesLoggingServicesRulesCount = 0;
        _stealthServicesRuleCount = 0;
        _cleanupServicesRuleCount = 0;
        _uncommentedServicesRulesCount = 0;
    }

    public void CalculateCorrectAll(List<CheckPoint_Network> _cpNetworks,
                                               List<CheckPoint_NetworkGroup> _cpNetworkGroups,
                                               List<CheckPoint_Host> _cpHosts,
                                               List<CheckPoint_Range> _cpRanges,
                                               List<CheckPoint_TcpService> _cpTcpServices,
                                               List<CheckPoint_UdpService> _cpUdpServices,
                                               List<CheckPoint_SctpService> _cpSctpServices,
                                               List<CheckPoint_IcmpService> _cpIcmpServices,
                                               List<CheckPoint_DceRpcService> _cpDceRpcServices,
                                               List<CheckPoint_OtherService> _cpOtherServices,
                                               List<CheckPoint_ServiceGroup> _cpServiceGroups)
    {
        _unusedNetworkObjectsCount = _unusedNetworkObjectsCount >= 0 ? _unusedNetworkObjectsCount : 0;
        _unusedServicesObjectsCount = _unusedServicesObjectsCount >= 0 ? _unusedServicesObjectsCount : 0;
        _uncommentedServicesRulesCount = _totalServicesRulesCount - _uncommentedServicesRulesCount;

        _totalNetworkObjectsCount = _cpNetworks.Count + _cpHosts.Count + _cpNetworkGroups.Count + _cpRanges.Count;

        //DUPLICATE CALCULATION
        foreach (var item in _cpNetworks)
        {
            if (_cpNetworks.Where(nt =>  nt.Netmask == item.Netmask & nt.Subnet == nt.Subnet).Count() > 1) { _duplicateNetworkObjectsCount++; }
        }
        foreach (var item in _cpHosts)
        {
            if (_cpHosts.Where(nt => nt.IpAddress == item.IpAddress).Count() > 1) { _duplicateNetworkObjectsCount++; }
        }
        foreach (var item in _cpRanges)
        {
            if (_cpRanges.Where(nt => nt.RangeFrom == item.RangeFrom & nt.RangeTo == nt.RangeTo).Count() > 1) { _duplicateNetworkObjectsCount++; }
        }
        //
        List<string> vs = new List<string>();
        foreach (var item in _cpNetworkGroups) { vs.AddRange(item.Members); }
        var count = _nestedNetworkGroupsCountAll = vs.Count;
        _nestedNetworkGroupsCount = count - vs.Distinct().Count();
        /////////////////////////////////
        _totalServicesObjectsCount = _cpTcpServices.Count + _cpUdpServices.Count + _cpSctpServices.Count + _cpIcmpServices.Count + _cpDceRpcServices.Count + _cpOtherServices.Count + _cpServiceGroups.Count;
        //
        List<string> allServiceNames = new List<string>();
        _duplicateServicesObjectsCount += _cpTcpServices.Count - _cpTcpServices.Select(n => n.Port).Distinct().Count();
        _duplicateServicesObjectsCount += _cpUdpServices.Count - _cpUdpServices.Select(n => n.Port).Distinct().Count();
        //
        vs = new List<string>();
        foreach (var item in _cpServiceGroups) { vs.AddRange(item.Members); }
        count = _nestedServicesGroupsCountAll = vs.Count;
        _nestedServicesGroupsCount = count - vs.Distinct().Count();
    }
}