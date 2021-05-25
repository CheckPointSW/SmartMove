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

namespace FortiGateMigration
{
    public class FortiGateConverter : VendorConverter
    {
        #region GUI params

        public bool OptimizeConf { get; set; } //check if Optimized configuration is requested
        public bool ConvertUserConf { get; set; } //check if User converion is requested
        public string LDAPAccoutUnit { get; set; } //read LDAP Account Unit Name for gethering users

        #endregion

        #region Private Members

        private FortiGateParser _fortiGateParser;

        private HashSet<string> _vDomNames = new HashSet<string>();

        private List<string> _errorsList = new List<string>(); //storing conversion errors for config or each VDOM
        private List<string> _warningsList = new List<string>(); //storing conversion warnings for config or each VDOM

        private Dictionary<string, List<CheckPointObject>> _localMapperFgCp = new Dictionary<string,List<CheckPointObject>>(); //storing map of FG names to CheckPoint objects

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
        public override void Initialize(VendorParser vendorParser, string vendorFilePath, string toolVersion, string targetFolder, string domainName)
        {
            _fortiGateParser = (FortiGateParser)vendorParser;
            if (_fortiGateParser == null)
            {
                throw new InvalidDataException("Unexpected!!!");
            }
            base.Initialize(vendorParser, vendorFilePath, toolVersion, targetFolder, domainName);
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
            return 0;
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
                    if (File.Exists(this._targetFolder + vDomName + "\\" + vDomName + "_objects.html"))
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
                    if (File.Exists(this._targetFolder + vDomName + "\\" + vDomName + "_policy.html"))
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
                    if (File.Exists(this._targetFolder + vDomName + "\\" + vDomName + "_NAT.html"))
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
                    if (File.Exists(this._targetFolder + vDomName + "\\" + vDomName + "_errors.html"))
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
                    if (File.Exists(this._targetFolder + vDomName + "\\" + vDomName + "_warnings.html"))
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

        //report about Errors
        public void CreateErrorsHtml(string vDomName)
        {
            if (_errorsList.Count > 0)
            {
                string filename = _targetFolder + "//" + vDomName + "_errors.html";

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
            }
        }

        //report about Warnings
        public void CreateWarningsHtml(string vDomName)
        {
            if (_errorsList.Count > 0)
            {
                string filename = _targetFolder + "//" + vDomName + "_warnings.html";

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
        public override void Convert(bool convertNat)
        {
            string targetFileNameMain = _vendorFileName;
            string targetFolderMain = _targetFolder;

            LDAP_Account_Unit = LDAPAccoutUnit.Trim();

            bool isVDom = ConvertVDom(targetFolderMain, _fortiGateParser.FgCommandsList, convertNat);

            if (!isVDom) //if configration file does not conatin any VDOM
            {
                InitSystemInterfaces(_fortiGateParser.FgCommandsList);
                ConvertConfig(targetFolderMain, targetFileNameMain, _fortiGateParser.FgCommandsList, convertNat);
            }
            else //if configuration file contains some VDOM then we can not count Errors, Warnings, Rules and NATs
            {
                _warningsConvertedPackage = -1;
                _errorsConvertedPackage = -1;
                _rulesInConvertedPackage = -1;
                _rulesInNatLayer = -1;
                CleanCheckPointObjectsLists();
            }

            RaiseConversionProgress(70, "Optimizing Firewall rulebase ...");
            RaiseConversionProgress(80, "Generating CLI scripts ...");

            ChangeTargetFolder(targetFolderMain, targetFileNameMain); // chaning target folder path to folder contains config file

            if (_vDomNames.Count > 0) // create HTML files which contain links to each report
            {
                CreateCatalogObjects();
                CreateCatalogNATs();
                CreateCatalogPolicies();
                CreateCatalogErrors();
                CreateCatalogWarnings();
            }

            VendorHtmlFile = _vendorFilePath;
            
            ObjectsScriptFile = _targetFolder;
            PolicyScriptFile = _targetFolder;
        }

        //Convertint VDOMs to each VDOM and then Convert each VDOM as simple Configuration
        public bool ConvertVDom(string targetFolderM, List<FgCommand> fgCommandsList, bool convertNat)
        {
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

                    if (fgCommandConfig.ObjectName.Equals("global") && isVDom)
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
            RaiseConversionProgress(35, "Convert configuration...");
            RaiseConversionProgress(40, "Convert objects...");
            _cpObjects.Initialize();   // must be first!!!
            CleanCheckPointObjectsLists(); // must be first!!!

            //change folder path for writing reports
            //if it is VDOM then each report will be placed to own folder
            //if it is w/o VDOM then report will be in the same folder as config file
            ChangeTargetFolder(targetFolderNew, targetFileNameNew);

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

                    if(fgCommandConfig.ObjectName.Equals("firewall address"))
                    {
                        Add_ConfigFirewallAddress(fgCommandConfig.SubCommandsList);
                    }
                    else if (fgCommandConfig.ObjectName.Equals("firewall vip"))
                    {
                        AddFirewallVip(fgCommandConfig.SubCommandsList);
                    }
                    else if(fgCommandConfig.ObjectName.Equals("firewall vipgrp"))
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
                    else if(fgCommandConfig.ObjectName.Equals("router static"))
                    {
                        AddRoutesStatic(fgCommandConfig.SubCommandsList);
                    }
                    else if(fgCommandConfig.ObjectName.Equals("router rip"))
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
                        Add_Package(fgCommandConfig.SubCommandsList, convertNat);
                    }
                }
            }

            if (!OptimizeConf) //adding objects if Optimized configuration is not required
            {
                foreach (string key in _localMapperFgCp.Keys)
                {
                    if (key.StartsWith(FG_PREFIX_KEY_user_group)) //already added because Access_Roles are added always
                    {
                        continue;
                    }

                    List<CheckPointObject> cpObjectsList = _localMapperFgCp[key];
                    foreach (CheckPointObject cpObject in cpObjectsList)
                    {
                        AddCheckPointObject(cpObject);
                    }
                }
            }

            CreateObjectsScript();
            CreateObjectsHtml();

            CreatePackagesScript();

            CreateErrorsHtml(targetFileNameNew);
            CreateWarningsHtml(targetFileNameNew);

            ExportNatLayerAsHtml();
            ExportPolicyPackagesAsHtmlConfig();

            _warningsConvertedPackage = _warningsList.Count;
            _errorsConvertedPackage = _errorsList.Count;
			
            CreateSmartConnector();

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

        #region Parse Static Routes

        public void AddRoutesStatic(List<FgCommand> fgCommandsList)
        {
            foreach(FgCommand fgCommandE in fgCommandsList)
            {
                FgCommand_Edit fgCommandEdit = (FgCommand_Edit)fgCommandE;

                FgStaticRoute fgStaticRoute = new FgStaticRoute();

                fgStaticRoute.Name = fgCommandEdit.Table.Trim('"').Trim();

                fgStaticRoute.Network = "0.0.0.0";
                fgStaticRoute.Mask = "255.255.255.255";

                foreach (FgCommand fgCommandS in fgCommandEdit.SubCommandsList)
                {
                    if(fgCommandS.GetType() == typeof(FgCommand_Set))
                    {
                        FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;

                        if(fgCommandSet.Field.Equals("dst"))
                        {
                            string[] destination = fgCommandSet.Value.Trim('"').Trim().Split(new string[] { " " }, StringSplitOptions.None).ToArray();

                            if(destination.Count() == 2)
                            {
                                fgStaticRoute.Network = destination[0];
                                fgStaticRoute.Mask = destination[1];
                            }
                        }
                        if (fgCommandSet.Field.Equals("gateway"))
                        {
                            fgStaticRoute.Gateway = fgCommandSet.Value.Trim('"').Trim();
                        }
                        if(fgCommandSet.Field.Equals("device"))
                        {
                            fgStaticRoute.Device = fgCommandSet.Value.Trim('"').Trim();
                        }
                    }
                }

                List<FgStaticRoute> routesList = null;

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

        #endregion

        #region Parse Dynamic Route

        public void CheckDynamicRoutesRip(List<FgCommand> fgCommandsList)
        {
            foreach(FgCommand fgCommandC in fgCommandsList)
            {
                if(fgCommandC.GetType() == typeof(FgCommand_Config))
                {
                    FgCommand_Config fgCommandConfig = (FgCommand_Config)fgCommandC;
                    if(fgCommandConfig.ObjectName.Equals("interface"))
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
            foreach(FgCommand fgCommandS in fgCommandsList)
            {
                if(fgCommandS.GetType() == typeof(FgCommand_Set))
                {
                    FgCommand_Set fgCommandSet = (FgCommand_Set)fgCommandS;
                    if(fgCommandSet.Field.Equals("router-id"))
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
                cpTcpService.Name = GetSafeName(nameEdit);
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
                cpUdpService.Name = GetSafeName(nameEdit);
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

                    if (!cpRange.RangeFrom.Equals("") && !cpRange.RangeTo.Equals(""))
                    {
                        AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_ippool + fgCommandEdit.Table, cpRange);
                    }

                    if (!cpRangeSrc.RangeFrom.Equals("") && !cpRangeSrc.RangeTo.Equals(""))
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
                                    if(_interfacesMapperFgCp.ContainsKey(zoneInterface))
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
            foreach(FgCommand fgCommand in fgCommandsList)
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

            return cpRange;
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

                                    AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_vip_extip + fgCommandEdit.Table, cpRange);
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

                                    AddCpObjectToLocalMapper(FG_PREFIX_KEY_firewall_vip_mappedip + fgCommandEdit.Table, cpRange);
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

        public void Add_Package(List<FgCommand> fgCommandsList, bool convertNat)
        {
            RaiseConversionProgress(70, "Convert policy...");

            var cpPackage = new CheckPoint_Package();
            cpPackage.Name = _policyPackageName;

            Add_ParentLayer(cpPackage, fgCommandsList, convertNat);

            AddCheckPointObject(cpPackage);
        }

        public void Add_ParentLayer(CheckPoint_Package package, List<FgCommand> fgCommandsList, bool convertNat)
        {
            package.ParentLayer.Name = package.NameOfAccessLayer;

            List<CheckPoint_Rule> rootRulesList = new List<CheckPoint_Rule>();
            Dictionary<string, CheckPoint_Layer> rootLayersMap = new Dictionary<string, CheckPoint_Layer>();
            Dictionary<string, CheckPoint_Zone> extraZonesMap = new Dictionary<string, CheckPoint_Zone>();
            List<string> extraZonesWarnMsgsList = new List<string>();
            List<CheckPoint_Rule> realRulesList = new List<CheckPoint_Rule>(); //is used if 'plain' policy should be converted

            //add main rule from Intrazone
            //add sub policy layer
            //add rule from Intrazone

            foreach(CheckPoint_Zone cpZoneIntra in _localIntrazonesList)
            {
                string warnMessage = CheckZoneForReservedWords(cpZoneIntra);

                if(warnMessage != null)
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

            foreach (FgCommand fgCommandE in fgCommandsList)
            {
                if (fgCommandE.GetType() == typeof(FgCommand_Edit))
                {
                    FgCommand_Edit fgCommand_Edit = (FgCommand_Edit)fgCommandE;

                    var cpRule = new CheckPoint_Rule();

                    cpRule.ConversionComments = "Matched rule " + fgCommand_Edit.Table;

                    string[] fgSrcIntfs = new string[]{};
                    string[] fgDstIntfs = new string[]{};

                    cpRule.Track = CheckPoint_Rule.TrackTypes.Log;

                    List<string> errorsList = new List<string>();

                    bool isNatEnabled = false;
                    bool isIpPoolEnabled = false;

                    List<string> fgDstAddrList = new List<string>();

                    List<CheckPointObject> cpUsersGroupsList = new List<CheckPointObject>();

                    foreach (FgCommand fgCommandS in fgCommand_Edit.SubCommandsList)
                    {
                        if (fgCommandS.GetType() == typeof(FgCommand_Set))
                        {
                            FgCommand_Set fgCommand_Set = (FgCommand_Set)fgCommandS;

                            if(fgCommand_Set.Field.Equals("name"))
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

                                if(Array.IndexOf(fgSrcIntfs.Select(s => s.ToLowerInvariant()).ToArray(), "any") > -1)
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

                                        if(!isAdded)
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

                                        if(!isAdded)
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

                                bool isAdded = false;

                                string[] fgPrefixes = new string[] { FG_PREFIX_KEY_firewall_schedule_recurring, FG_PREFIX_KEY_firewall_schedule_onetime, FG_PREFIX_KEY_firewall_schedule_group };

                                foreach (string fgPrefix in fgPrefixes)
                                {
                                    if (_localMapperFgCp.ContainsKey(fgPrefix + fgScheduleRule))
                                    {
                                        List<CheckPointObject> cpObjsList = _localMapperFgCp[fgPrefix + fgScheduleRule];
                                        foreach(CheckPointObject cpObj in cpObjsList) {
                                            cpRule.Time.Add(cpObj);
                                            if (OptimizeConf)
                                            {
                                                AddCheckPointObject(cpObj);
                                            }
                                            isAdded = true;
                                        }
                                    }
                                }

                                if(!isAdded)
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
                            else if(extraZonesMap.ContainsKey(FG_PREFIX_KEY_system_zone + fgSrcIntf))
                            {
                                fgSrcIntfsList.Add(extraZonesMap[FG_PREFIX_KEY_system_zone + fgSrcIntf]);
                            }
                            else
                            {
                                CheckPoint_Zone cpZoneSrc = new CheckPoint_Zone();
                                cpZoneSrc.Name = GetSafeName(fgSrcIntf_Appendix + fgSrcIntf);

                                string warnMessage = CheckZoneForReservedWords(cpZoneSrc);
                                if(warnMessage != null)
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
                            else if(extraZonesMap.ContainsKey(FG_PREFIX_KEY_system_zone + fgDstIntf))
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

                        _rulesInConvertedPackage += 1;
                        
                        if (cpRuleUG != null)
                        {
                            rootLayer.Rules.Add(cpRuleUG);

                            _rulesInConvertedPackage += 1;
                        }

                        rootLayersMap[rootLayer.Name] = rootLayer;

                        //NAT conversion reagrding design which is described in other doc

                        if(convertNat)
                        {
                            int counterNatRules = -1;

                            foreach (string fgDstAddr in fgDstAddrList)
                            {
                                if (isNatEnabled)
                                {
                                    if(_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_grp + fgDstAddr))
                                    {
                                        List<CheckPointObject> cpVipGrpsList = _localMapperFgCp[FG_PREFIX_KEY_firewall_vip_grp + fgDstAddr];
                                        foreach (CheckPointObject cpVipGrpI in cpVipGrpsList)
                                        {
                                            if(cpVipGrpI.GetType() == typeof(CheckPoint_NetworkGroup))
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
                                    else if(_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_extip + fgDstAddr) || 
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
                        
                        foreach(string error in errorsList)
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
            List <CheckPointObject> fgServicesList = new List<CheckPointObject>();

            List<string> fgServicesNames = fgCommandSet.Value.Trim('"').Split(new string[] { "\" \"" }, StringSplitOptions.None).ToList();
            for(int i = 0; i < fgServicesNames.Count; i++)
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
                        if(_interfacesMapperFgCp.ContainsKey(fgCommandSet.Value.Trim('"')))
                        {
                            fgDstIntfsList.AddRange(_interfacesMapperFgCp[fgCommandSet.Value.Trim('"')]);
                        }
                        else if(_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_system_zone_host + fgCommandSet.Value.Trim('"'))) //if FG dstintf is Zone
                        {
                            if (fgDstAddr.Equals("all"))
                            {
                                continue; //don't process "all" for FG dstaddr because we can't route for "all" addresses
                            }
                            if(fgDstAddrsList.Count != 1)
                            {
                                continue; //don't process "multi" FG objects
                            }

                            //get destaddr Object to get its IP address
                            string fgDstAddrChecking = null;
                            CheckPointObject checkPointObject = fgDstAddrsList[0];

                            if(checkPointObject.GetType() == typeof(CheckPoint_Range))
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
                            if(cpObjsList.Count == 1)
                            {
                                fgDstIntfsList.AddRange(cpObjsList);
                            }
                            //if Zone contains multi Interface: we should to check:
                            // 1) if dynamic routing is disable
                            // 2) to check which Interface contains network for destaddr
                            // 3) if noone Interface contains network for dstaddr, then we should to use interface with default routing (if default routing exists for some Interface)
                            else if(cpObjsList.Count > 1 && !_localFgDynRoutesEnable)
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
                                        if(IPNetwork.Contains(ipnetwork, ipaddress) && netCidr < ipnetwork.Cidr) //check if interface from Zone contains dstaddr network
                                        {
                                            intfName = interfaceNameFg;
                                            netCidr = ipnetwork.Cidr;
                                        }
                                    }

                                    if (_localFgRoutesDict.ContainsKey(interfaceNameFg)) //check static route
                                    {
                                        foreach (FgStaticRoute fgStaticRoute in _localFgRoutesDict[interfaceNameFg])
                                        {
                                            if(fgStaticRoute.Network.Equals("0.0.0.0") && intfNameDefault == null)
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
                                if(intfName != null)
                                {
                                    if(_interfacesMapperFgCp.ContainsKey(intfName))
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

                    if(fgCommandSet.Field.Equals("comments"))
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
                    if(cpObjSrcAddr.GetType() == typeof(CheckPoint_Domain))
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

            if(isIpPoolEnabled)
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
                        else {
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

            string inZoneNameNew = "";

            string[] inZoneNameParts = inZone.Name.Split('-').ToArray();

            string[] reservedWords = new string[]
            {
                "all", "All", "and", "any", "Any",
                "apr", "Apr", "april", "April", "aug", "Aug", "august", "August",
                "black", "blackboxs", "blue", "broadcasts", "call", "comment",
                "conn", "date", "day", "debug", "dec", "Dec", "december", "December",
                "deffunc", "define", "delete", "delstate", "direction", "do", "domains",
                "drop", "dst", "dynamic", "else", "expcall", "expires", "export", "fcall",
                "feb", "Feb", "february", "February", "firebrick", "foreground", "forest",
                "format", "fri", "Fri", "friday", "Friday", "from", "fw1", "FW1", "fwline",
                "fwrule", "gateways", "get", "getstate", "gold", "gray", "green", "hashsize",
                "hold", "host", "hosts", "if", "ifaddr", "ifid", "implies", "in", "inbound",
                "instate", "interface", "interfaces", "ipsecdata", "ipsecmethods", "is",
                "jan", "Jan", "january", "January", "jul", "Jul", "july", "July", "jun",
                "Jun", "june", "June", "kbuf", "keep", "limit", "local", "localhost", "log",
                "LOG", "logics", "magenta", "mar", "Mar", "march", "March", "may", "May",
                "mday", "medium", "modify", "mon", "Mon", "monday", "Monday", "month",
                "mortrap", "navy", "netof", "nets", "nexpires", "not", "nov", "Nov",
                "november", "November", "oct", "Oct", "october", "October", "or",
                "orange", "origdport", "origdst", "origsport", "origsrc", "other",
                "outbound", "packet", "packetid", "packetlen", "pass", "r_arg",
                "r_call_counter", "r_cdir", "r_cflags", "r_chandler", "r_client_community",
                "r_client_ifs_grp", "r_community_left", "r_connarg", "r_crule", "r_ctimeout",
                "r_ctype", "r_curr_feature_id", "r_data_offset", "r_dtmatch", "r_dtmflags",
                "r_entry", "r_g_offset", "r_ipv6", "r_mapped_ip", "r_mflags", "r_mhandler",
                "r_mtimeout", "r_oldcdir", "r_pflags", "r_profile_id", "r_ro_client_community",
                "r_ro_dst_sr", "r_ro_server_community", "r_ro_src_sr", "r_scvres",
                "r_server_community", "r_server_ifs_grp", "r_service_id", "r_simple_hdrlen",
                "r_spii_ret", "r_spii_tcpseq", "r_spii_uuid1", "r_spii_uuid2", "r_spii_uuid3",
                "r_spii_uuid4", "r_str_dport", "r_str_dst", "r_str_ipp", "r_str_sport",
                "r_str_src", "r_user", "record", "red", "refresh", "reject", "routers",
                "sat", "Sat", "saturday", "Saturday", "second", "sep", "Sep", "september",
                "September", "set", "setstate", "skipme", "skippeer", "sr", "src", "static",
                "sun", "Sun", "sunday", "Sunday", "switchs", "sync", "targets", "thu", "Thu",
                "thursday", "Thursday", "to", "tod", "tue", "Tue", "tuesday", "Tuesday", "ufp",
                "vanish", "vars", "wasskipped", "wed", "Wed", "wednesday", "Wednesday",
                "while", "xlatedport", "xlatedst", "xlatemethod", "xlatesport", "xlatesrc",
                "xor", "year", "zero", "zero_ip", "mon", "Mon", "monday", "Monday", "tue",
                "Tue", "tuesday", "Tuesday", "wed", "Wed", "wednesday", "Wednesday", "thu",
                "Thu", "thursday", "Thursday", "fri", "Fri", "friday", "Friday", "sat", "Sat",
                "saturday", "Saturday", "sun", "Sun", "sunday", "Sunday", "jan", "Jan",
                "january", "January", "feb", "Feb", "february", "February", "mar", "Mar",
                "march", "March", "apr", "Apr", "april", "April", "may", "May", "jun", "Jun",
                "june", "June", "jul", "Jul", "july", "July", "aug", "Aug", "august", "August",
                "sep", "Sep", "september", "September", "oct", "Oct", "october", "October",
                "nov", "Nov", "november", "November", "dec", "Dec", "december", "December",
                "date", "day", "month", "year", "black", "blue", "cyan", "dark", "firebrick",
                "foreground", "forest", "gold", "gray", "green", "magenta", "medium", "navy",
                "orange", "red", "sienna", "yellow", "dark", "light", "medium"
            };

            foreach(string inZoneNamePart in inZoneNameParts)
            {
                if(reservedWords.Contains(inZoneNamePart))
                {
                    inZoneNameNew += "_" + inZoneNamePart;
                }
                else
                {
                    if(!inZoneNameNew.Equals(""))
                    {
                        inZoneNameNew += "-";
                    }

                    inZoneNameNew += inZoneNamePart;
                }
            }

            if(!inZone.Name.Equals(inZoneNameNew))
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
            if(cpObject.GetType() == typeof(CheckPoint_TcpService))
            {
                if(!char.IsLetter(cpObject.Name, 0))
                {
                    string newName = "TCP_" + cpObject.Name;
                    _warningsList.Add(cpObject.Name + " tcp-service was renamed to " + newName);
                    cpObject.Name = newName;
                }
            }
            else if(cpObject.GetType() == typeof(CheckPoint_UdpService))
            {
                if (!char.IsLetter(cpObject.Name, 0))
                {
                    string newName = "UDP_" + cpObject.Name;
                    _warningsList.Add(cpObject.Name + " udp-service was renamed to " + newName);
                    cpObject.Name = newName;
                }
            }
            else if(cpObject.GetType() == typeof(CheckPoint_SctpService))
            {
                if(!char.IsLetter(cpObject.Name, 0))
                {
                    string newName = "SCTP_" + cpObject.Name;
                    _warningsList.Add(cpObject.Name + " sctp-service was renamed to " + newName);
                    cpObject.Name = newName;
                }
            }
            else if(cpObject.GetType() == typeof(CheckPoint_IcmpService))
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
            else if(cpObject.GetType() == typeof(CheckPoint_Time))
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
            else if(cpObject.GetType() == typeof(CheckPoint_TimeGroup))
            {
                string cpTimeGrpName = cpObject.Name;

                if (cpTimeGrpName.Length > 11)
                {
                    cpTimeGrpName = cpTimeGrpName.Substring(0, 6) + "_c" + _timeGroupCutterCounter++;
                }

                if(!cpTimeGrpName.Equals(cpObject.Name))
                {
                    _warningsList.Add(cpObject.Name + " time group object was renamed to " + cpTimeGrpName);
                    cpObject.Name = cpTimeGrpName;
                }
            }

            bool isNameExist = true;

            int zIndex = 0;

            string cpObjectName = cpObject.Name;

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

            if(!cpObject.Name.Equals(cpObjectName))
            {
                _warningsList.Add(cpObject.Name + " object was renamed to " + cpObjectName + " for solving duplicate names issue.");
                cpObject.Name = cpObjectName;
            }

            cpObjectsList.Add(cpObject);

            _localMapperFgCp[fgObjectName] = cpObjectsList;
        }

        #endregion
        
        public static string GetSafeName(string name)
        {
            if (name != null && !name.Trim().Equals(""))
            {
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

            foreach(string vipGrpMember in vipGrpMembers)
            {
                if (_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_extip + vipGrpMember) || 
                    _localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_mappedip + vipGrpMember))
                {
                    retList.Add(vipGrpMember);
                }
                else if(_localMapperFgCp.ContainsKey(FG_PREFIX_KEY_firewall_vip_grp + vipGrpMember))
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
        public string Name { get; set; }
        public string Network { get; set; }
        public string Mask { get; set; }
        public string Gateway { get; set; }
        public string Device { get; set; }
    }
}
