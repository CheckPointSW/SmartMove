﻿using CheckPointObjects;
using CommonUtils;
using MigrationBase;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PaloAltoMigration
{
    public class PaloAltoConverter : VendorConverter
    {
        #region GUI params

        public bool OptimizeConf { get; set; } //check if Optimized configuration is requested
        public bool ConvertUserConf { get; set; } //check if User converion is requested
        public string LDAPAccoutUnit { get; set; } //read LDAP Account Unit Name for gethering users

        public bool ShowOptBashLink = true;

        #endregion

        #region Private Members

        private PaloAltoParser _paParser;
        private bool _isNatConverted;

        private HashSet<string> _vsysNames = new HashSet<string>();

        private List<string> _errorsList = new List<string>(); //storing conversion errors for config or each VSYS
        private List<string> _warningsList = new List<string>(); //storing conversion warnings for config or each VSYS

        private int _rulesInConvertedPackage = 0; //counter
        private int _rulesInNatLayer = 0; //counter

        private int _warningsConvertedPackage = 0; //counter
        private int _errorsConvertedPackage = 0; //counter

        private HashSet<string> _timesNamesSet = new HashSet<string>();
        private int _timeCutterCounter = 0; //postfix for Time objects

        private HashSet<string> _objectsNamesSet = new HashSet<string>();
        private int _numPostfix = 0;

        private Dictionary<string, string> cpPredefServicesTypes = new Dictionary<string, string>();

        private string outputFormat = "";

        //if total package name over max count of chars (15) do not create *.sh, *.tar.gz, *.zip files
        private bool _isOverMaxLengthPackageName = false;
        private int _maxAllowedpackageNameLength = 15;

        private CheckPoint_Package Add_Optimized_Package()
        {
            CheckPoint_Package regularPackage = _cpPackages[0];

            var optimizedPackage = new CheckPoint_Package();
            string checkOptimizedName = _policyPackageOptimizedName.Replace("_policy_opt", "_opt");
            string pckg_name = checkOptimizedName.Replace("_opt", "");
            if (pckg_name.Length > _maxAllowedpackageNameLength)
            {
                _isOverMaxLengthPackageName = true;
                _errorsList.Add("Package " + pckg_name + " has name length more then " + _maxAllowedpackageNameLength + " chars");
            }
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

            return optimizedPackage;
        }

        public void CreateCatalogOptPolicies()
        {
            string filename = PolicyOptimizedHtmlFile;

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VDOMs Policies for " + _vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vDomName in _vsysNames)
                {
                    if (File.Exists(_targetFolder + "\\" + vDomName + "\\" + vDomName + "_policy_opt.html"))
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

        #endregion

        #region Constants

        private const string LOCAL_DEVICE_ENTRY_NAME = "localhost.localdomain";

        private const string PA_ANY_VALUE = "any";

        private const string CP_OBJECT_TYPE_NAME_ZONE = "zone";
        private const string CP_OBJECT_TYPE_NAME_ADDRESS_HOST = "address host";
        private const string CP_OBJECT_TYPE_NAME_ADDRESS_NETWORK = "address network";
        private const string CP_OBJECT_TYPE_NAME_ADDRESS_RANGE = "address range";
        private const string CP_OBJECT_TYPE_NAME_ADDRESS_GROUP = "addresses group";
        private const string CP_OBJECT_TYPE_NAME_SERVICE_TCP = "tcp service";
        private const string CP_OBJECt_TYPE_NAME_SERVICE_UDP = "udp service";
        private const string CP_OBJECT_TYPE_NAME_SERVICE_GROUP = "services group";
        private const string CP_OBJECT_TYPE_NAME_APPLICATION_GROUP = "application group";
        private const string CP_OBJECT_TYPE_NAME_ACCESS_ROLE = "access-role";

        private const string NETWORK_NETMASK = "32";
        private const string NETWORK_NETMASK_WS = "/32";
        private const string NETWORK_NETMASK_V6 = "128";
        private const string NETWORK_NETMASK_WS_V6 = "/128";

        private const string SERVICE_TYPE_TCP = "TCP";
        private const string SERVICE_TYPE_UDP = "UDP";

        private const string PA_APPLICATIONS_FILE_NAME = "PA_Apps_CP.csv";
        private const string PA_APP_FILTERS_FILE_NAME = "PA_AppFilters_CP.csv";

        private const string PA_APPLICATION_DEFAULT = "application-default";

        private const string PA_INTRAZONE_NAME = "interzone";

        private const string RE_NET_ADDRESS = "^(\\d+\\.){3}\\d+(/\\d{0,2})?"; // 192.168.1.12/24 or 192.168.1.0/32 or 192.168.1.55
        private const string RE_NAME_UNSAFE = @"[^A-Za-z0-9_.-]";

        #endregion

        #region Methods are used for reports

        //count of converted rules.
        // -1 is VSYSs
        public override int RulesInConvertedPackage()
        {
            return _rulesInConvertedPackage;
        }

        //count of warnings of conversion
        // -1 if VSYSs
        public int WarningsInConvertedPackage()
        {
            return _warningsConvertedPackage;
        }

        //count of errors of conversion
        // -1 if VSYSs
        public int ErrorsInConvertedPackage()
        {
            return _errorsConvertedPackage;
        }

        public override int RulesInConvertedOptimizedPackage()
        {
            if (_cpPackages.Count > 1)
                return _cpPackages[1].TotalRules();
            else return 0;
        }

        //count of NAT rules
        // -1 if VSYSs
        public override int RulesInNatLayer()
        {
            return _rulesInNatLayer;
        }

        public override void ExportConfigurationAsHtml()
        {
            //not used as we have VSYSs
        }

        public override void ExportPolicyPackagesAsHtml()
        {
            //not used as we have VSYSs
        }

        protected string RuleItemsList2Html_pa(List<CheckPointObject> ruleItems, List<CheckPointObject> appsItems, bool isCellNegated, string defaultValue, ref ConversionIncidentType ruleConversionIncidentType)
        {
            if (ruleItems.Count == 0 && (appsItems == null || appsItems.Count == 0))
            {
                return defaultValue;
            }

            string res = "";

            if (isCellNegated)
            {
                res += "<div style='text-align: center';>";
                res += "<div style='color: white; background-color: #6e0c0c; font-style: italic; padding-left: 2px; padding-right: 2px; border-radius: 3px; display: inline-block;'>Negated</div>";
                res += "</div>";
            }

            foreach (CheckPointObject item in ruleItems)
            {
                if (_cpObjects.IsKnownService(item.Name))
                {
                    res += "<div>" + item.Name + "</div>";
                }
                else if (item.GetType() == typeof(CheckPoint_PredifinedObject))
                {
                    res += "<div>" + item.Name + "</div>";
                }
                else
                {
                    if (item.ConversionIncidentType != ConversionIncidentType.None)
                    {
                        if (item.ConversionIncidentType > ruleConversionIncidentType)   // Error type overrides information type!!!
                        {
                            ruleConversionIncidentType = item.ConversionIncidentType;
                        }
                        res += "<div>" + BuildConversionIncidentLinkTag(item.ConvertedCommandId) + "<a href='./" + Path.GetFileName(ObjectsHtmlFile) + "#" + item.Name + "' target='_blank'>" + item.Name + "</a></div>";
                    }
                    else
                    {
                        res += "<div><a href='./" + Path.GetFileName(ObjectsHtmlFile) + "#" + item.Name + "' target='_blank'>" + item.Name + "</a></div>";
                    }
                }
            }

            if (appsItems != null)
            {
                foreach (CheckPointObject item in appsItems)
                {
                    res += "<div>" + item.Name + "</div>";
                }
            }

            return res;
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
                        List<CheckPointObject> ruleAppsList = new List<CheckPointObject>();
                        if (rule.GetType() == typeof(CheckPoint_RuleWithApplication))
                        {
                            CheckPoint_RuleWithApplication ruleApp = (CheckPoint_RuleWithApplication)rule;
                            ruleAppsList.AddRange(ruleApp.Application);
                        }

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
                        file.WriteLine("      <td>" + RuleItemsList2Html_pa(rule.Service, ruleAppsList, false, CheckPointObject.Any, ref dummy) + "</td>");
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
                                    List<CheckPointObject> subRuleAppsList = new List<CheckPointObject>();
                                    if (subRule.GetType() == typeof(CheckPoint_RuleWithApplication))
                                    {
                                        CheckPoint_RuleWithApplication subRuleApp = (CheckPoint_RuleWithApplication)subRule;
                                        subRuleAppsList.AddRange(subRuleApp.Application);
                                    }

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
                                        /* */
                                        file.WriteLine("      <td>" + RuleItemsList2Html_pa(subRule.Service, subRuleAppsList, false, CheckPointObject.Any, ref ruleConversionIncidentType) + "</td>");
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

        //Catalog is Root file if VSYSs exist
        public void CreateCatalogObjects()
        {
            string filename = this.ObjectsHtmlFile;

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VSYSs Objects for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vsysName in _vsysNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vsysName + "\\" + vsysName + "_objects.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vsysName + "\\" + vsysName + "_objects.html" + "\">" + "<h2>" + vsysName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vsysName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //Catalog is Root file if VSYSs exist
        public void CreateCatalogPolicies()
        {
            string filename = this.PolicyHtmlFile;

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VSYSs Policies for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vsysName in _vsysNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vsysName + "\\" + vsysName + "_policy.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vsysName + "\\" + vsysName + "_policy.html" + "\">" + "<h2>" + vsysName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vsysName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //Catalog is Root file if VSYSs exist
        public void CreateCatalogNATs()
        {
            string filename = this.NatHtmlFile;

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VSYSs NATs for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vsysName in _vsysNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vsysName + "\\" + vsysName + "_NAT.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vsysName + "\\" + vsysName + "_NAT.html" + "\">" + "<h2>" + vsysName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vsysName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //Catalog is Root file if VSYSs exist
        public void CreateCatalogErrors()
        {
            string filename = this._targetFolder + "\\" + _vendorFileName + "_errors.html";

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VSYSs Errors for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vsysName in _vsysNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vsysName + "\\" + vsysName + "_errors.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vsysName + "\\" + vsysName + "_errors.html" + "\">" + "<h2>" + vsysName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vsysName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //Catalog is Root file if VSYSs exist
        public void CreateCatalogWarnings()
        {
            string filename = this._targetFolder + "\\" + _vendorFileName + "_warnings.html";

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of VSYSs Warnings for " + this._vendorFileName + "</h1>");
                file.WriteLine("<ul>");
                foreach (string vsysName in _vsysNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vsysName + "\\" + vsysName + "_warnings.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vsysName + "\\" + vsysName + "_warnings.html" + "\">" + "<h2>" + vsysName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vsysName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        //report about Errors
        public void CreateErrorsHtml(string vsysName)
        {
            string filename = _targetFolder + "\\" + vsysName + "_errors.html";

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of " + vsysName + " Errors</h1>");
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

        //report about Warnings
        public void CreateWarningsHtml(string vsysName)
        {
            string filename = _targetFolder + "\\" + vsysName + "_warnings.html";

            using (var file = new StreamWriter(filename, false))
            {
                file.WriteLine("<html>");
                file.WriteLine("<head>");
                file.WriteLine("</head>");
                file.WriteLine("<body>");
                file.WriteLine("<h1>List of " + vsysName + " Warnings</h1>");
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

        #endregion

        #region Converter

        public NewAnalizStatistic NewPaloAnalizStatistic = new NewAnalizStatistic(0, 0);

        public override void Initialize(VendorParser vendorParser, string vendorFilePath, string toolVersion, string targetFolder, string domainName, string outputFormat = "json")
        {
            _paParser = (PaloAltoParser)vendorParser;
            if (_paParser == null)
            {
                throw new InvalidDataException("Unexpected!!!");
            }
            this.outputFormat = outputFormat;
            base.Initialize(vendorParser, vendorFilePath, toolVersion, targetFolder, domainName, outputFormat);
        }

        protected override bool AddCheckPointObject(CheckPointObject cpObject)
        {
            if (cpObject != null)
            {
                cpObject.Comments = string.IsNullOrWhiteSpace(cpObject.Comments) ? "" : (" " + cpObject.Comments);
                if (base.AddCheckPointObject(cpObject))
                {
                    string vendor = Vendor.PaloAlto.ToString();
                    if (!cpObject.Tags.Contains(vendor))
                    {
                        cpObject.Tags.Add(vendor);
                    }
                }
            }

            return false;
        }
        public override float Analyze()
        {
            string targetFileNameMain = _vendorFileName;
            string targetFolderMain = _targetFolder;
            _isOverMaxLengthPackageName = false;

            if (IsConsoleRunning)
                Progress = new ProgressBar();

            PA_Config paConfig = _paParser.Config;
            _isNatConverted = true;


            if (paConfig != null)
            {
                List<PA_TagEntry> s_TagEntries = new List<PA_TagEntry>();
                Dictionary<string, CheckPointObject> s_cpAddressesDict = null;
                Dictionary<string, CheckPoint_NetworkGroup> s_cpNetGroupsDict = null;
                Dictionary<string, CheckPointObject> s_cpServicesDict = null;
                Dictionary<string, string> s_paServicesTypesDict = null;
                Dictionary<string, CheckPoint_ServiceGroup> s_cpServicesGroupsDict = null;
                List<string> s_paAppFiltersList = null;
                Dictionary<string, CheckPoint_ApplicationGroup> s_cpAppGroupsDict = null;
                Dictionary<string, List<CheckPoint_Time>> s_cpSchedulesDict = null;

                if (paConfig.Shared != null)
                {
                    if (paConfig.Shared.TagsEntries != null)
                        s_TagEntries.AddRange(paConfig.Shared.TagsEntries);
                    s_cpAddressesDict = ConvertAddresses(paConfig.Shared, null);

                    s_cpNetGroupsDict = ConvertAddressesGroupsWithInspection(paConfig.Shared, s_cpAddressesDict, null, null);

                    s_cpServicesDict = ConvertServices(paConfig.Shared, null);

                    s_paServicesTypesDict = GetServicesTypes(paConfig.Shared, null);

                    s_cpServicesGroupsDict = ConvertServicesGroupsWithInspection(paConfig.Shared, s_cpServicesDict, null);

                    List<string> s_appsMatchList = GetApplicationsMatchList();

                    s_paAppFiltersList = GetPAApplicationsFilters(paConfig.Shared, null);

                    s_cpAppGroupsDict = ConvertApplicationsGroups(new List<PA_ApplicationGroupEntry>(paConfig.Shared.ApplicationGroupsEntries), s_appsMatchList, null, s_paAppFiltersList, s_cpServicesGroupsDict);

                    s_cpSchedulesDict = new Dictionary<string, List<CheckPoint_Time>>();
                    ConvertSchedules(paConfig.Shared).ForEach(x =>
                    {
                        string key = x.Name;
                        x = InspectCpScheduleName(x);
                        List<CheckPoint_Time> cpTimesList = null;
                        if (s_cpSchedulesDict.ContainsKey(key))
                            cpTimesList = s_cpSchedulesDict[key];
                        else
                            cpTimesList = new List<CheckPoint_Time>();
                        cpTimesList.Add(x);
                        s_cpSchedulesDict[key] = cpTimesList;
                    });
                }
                if (paConfig.Devices != null)
                {
                    if (paConfig.Devices.DevicesEntry != null && paConfig.Devices.DevicesEntry.Name.Equals(LOCAL_DEVICE_ENTRY_NAME)) //we parse PA config from PA
                    {
                        if (paConfig.Devices.DevicesEntry.Vsys != null &&
                            paConfig.Devices.DevicesEntry.Vsys.VsysEntries != null &&
                            paConfig.Devices.DevicesEntry.Vsys.VsysEntries.Count > 0)
                        {
                            if (paConfig.Devices.DevicesEntry.Vsys.VsysEntries.Count == 1)
                            {
                                AnalyzePaVsysEntry(targetFolderMain, targetFileNameMain, paConfig.Devices.DevicesEntry.Vsys.VsysEntries[0],
                                                    s_TagEntries,
                                                    s_cpAddressesDict,
                                                    s_cpNetGroupsDict,
                                                    s_cpServicesDict,
                                                    s_paServicesTypesDict,
                                                    s_cpServicesGroupsDict,
                                                    s_paAppFiltersList,
                                                    s_cpAppGroupsDict,
                                                    s_cpSchedulesDict);
                            }
                            else
                            {
                                foreach (PA_VsysEntry paVsysEntry in paConfig.Devices.DevicesEntry.Vsys.VsysEntries)
                                {
                                    string paVsysName = paVsysEntry.Name;
                                    _vsysNames.Add(paVsysName);
                                    string targetFolderVsys = targetFolderMain + "\\" + paVsysName;
                                    System.IO.Directory.CreateDirectory(targetFolderVsys);
                                    AnalyzePaVsysEntry(targetFolderVsys, paVsysName, paVsysEntry,
                                                        s_TagEntries,
                                                        s_cpAddressesDict,
                                                        s_cpNetGroupsDict,
                                                        s_cpServicesDict,
                                                        s_paServicesTypesDict,
                                                        s_cpServicesGroupsDict,
                                                        s_paAppFiltersList,
                                                        s_cpAppGroupsDict,
                                                        s_cpSchedulesDict);
                                }

                                _warningsConvertedPackage = -1;
                                _errorsConvertedPackage = -1;
                                _rulesInConvertedPackage = -1;
                                _rulesInNatLayer = -1;
                                CleanCheckPointObjectsLists();

                                // changing target folder path to folder contains config file
                                ChangeTargetFolder(targetFolderMain, targetFileNameMain);

                                CreateCatalogExportManagment();
                            }
                        }
                    }
                }
            }

            if (IsConsoleRunning)
            {
                Console.WriteLine("Optimizing Firewall rulebase ...");
                Progress.SetProgress(70);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(70, "Optimizing Firewall rulebase ...");


            if (IsConsoleRunning)
            {
                Progress.SetProgress(100);
                Progress.Dispose();
            }

            OptimizationPotential = NewPaloAnalizStatistic._totalFileRules > 0 ? ((NewPaloAnalizStatistic._totalFileRules - NewPaloAnalizStatistic._totalFileRulesOpt) * 100 / (float)NewPaloAnalizStatistic._totalFileRules) : 0;
            return 0;
        }

        public void AnalyzePaVsysEntry(string targetFolderNew, string targetFileNameNew, PA_VsysEntry paVsysEntry,
                                        List<PA_TagEntry> s_TagEntries,
                                        Dictionary<string, CheckPointObject> s_cpAddressesDict,
                                        Dictionary<string, CheckPoint_NetworkGroup> s_cpNetGroupsDict,
                                        Dictionary<string, CheckPointObject> s_cpServicesDict,
                                        Dictionary<string, string> s_paServicesTypesDict,
                                        Dictionary<string, CheckPoint_ServiceGroup> s_cpServicesGroupsDict,
                                        List<string> s_paAppFiltersList,
                                        Dictionary<string, CheckPoint_ApplicationGroup> s_cpAppGroupsDict,
                                        Dictionary<string, List<CheckPoint_Time>> s_cpSchedulesDict)
        {
            if (IsConsoleRunning)
            {
                Console.WriteLine("Analyzing configuration...");
                Progress.SetProgress(35);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(35, "Analyzing configuration...");

            if (IsConsoleRunning)
            {
                Console.WriteLine("Analyzing objects...");
                Progress.SetProgress(40);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(40, "Analyzing objects...");

            _cpObjects.Initialize(); // must be first!!!
            CleanCheckPointObjectsLists(); // must be first!!!

            //change folder path for writing reports
            //if it is multi-VSYS then each report will be placed to own folder
            //if it is single VSYS then report will be in the same folder as config file
            ChangeTargetFolder(targetFolderNew, targetFileNameNew);

            //convert PaloAlto Ojbects to CheckPoint Objects and save them to correspondings List

            Dictionary<string, CheckPoint_Zone> cpZonesDict = ConvertZones(paVsysEntry);

            Dictionary<string, CheckPointObject> cpAddressesDict = ConvertAddresses(paVsysEntry, s_cpAddressesDict);

            Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsDict = ConvertAddressesGroupsWithInspection(paVsysEntry, cpAddressesDict, s_cpNetGroupsDict, s_TagEntries);

            Dictionary<string, CheckPointObject> cpServicesDict = ConvertServices(paVsysEntry, s_cpServicesDict);

            Dictionary<string, string> paServicesTypesDict = GetServicesTypes(paVsysEntry, s_paServicesTypesDict);

            Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsDict = ConvertServicesGroupsWithInspection(paVsysEntry, cpServicesDict, s_cpServicesGroupsDict);

            List<string> appsMatchList = GetApplicationsMatchList();

            List<string> paAppFiltersList = GetPAApplicationsFilters(paVsysEntry, s_paAppFiltersList);

            Dictionary<string, CheckPoint_ApplicationGroup> cpAppGroupsDict =
                ConvertApplicationsGroups(new List<PA_ApplicationGroupEntry>(paVsysEntry.ApplicationGroupsEntries), appsMatchList, s_cpAppGroupsDict, paAppFiltersList, cpServicesGroupsDict);

            Dictionary<string, List<CheckPoint_Time>> cpSchedulesDict = null;
            if (s_cpSchedulesDict != null)
                cpSchedulesDict = new Dictionary<string, List<CheckPoint_Time>>(s_cpSchedulesDict);
            else
                cpSchedulesDict = new Dictionary<string, List<CheckPoint_Time>>();
            ConvertSchedules(paVsysEntry).ForEach(x =>
            {
                string key = x.Name;
                x = InspectCpScheduleName(x);
                List<CheckPoint_Time> cpTimesList = null;
                if (cpSchedulesDict.ContainsKey(key))
                    cpTimesList = cpSchedulesDict[key];
                else
                    cpTimesList = new List<CheckPoint_Time>();
                cpTimesList.Add(x);
                cpSchedulesDict[key] = cpTimesList;
            });

            Dictionary<string, CheckPoint_AccessRole> cpAccessRolesDict = new Dictionary<string, CheckPoint_AccessRole>();

            if (IsConsoleRunning)
            {
                Console.WriteLine("Analyze policy...");
                Progress.SetProgress(60);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(60, "Analyze policy...");

            ConvertSecurityPolicy(paVsysEntry, cpZonesDict,
                                  cpAddressesDict, cpNetGroupsDict,
                                  cpServicesDict, cpServicesGroupsDict,
                                  appsMatchList, cpAppGroupsDict, paAppFiltersList,
                                  cpSchedulesDict, cpAccessRolesDict);

            new List<CheckPoint_AccessRole>(cpAccessRolesDict.Values).ForEach(x => AddCheckPointObject(x));

            if (_isNatConverted)
            {
                ConvertNatPolicy(paVsysEntry, cpAddressesDict, cpNetGroupsDict, cpServicesDict, paServicesTypesDict, cpServicesGroupsDict, cpServicesGroupsDict);
            }

            //if non-optimized convert method is used then all objects are added

            NewPaloAnalizStatistic._Package = Add_Optimized_Package();

            ExportManagmentReport(true);

            new List<CheckPoint_Zone>(cpZonesDict.Values).ForEach(x => AddCheckPointObject(x));
            new List<CheckPointObject>(cpAddressesDict.Values).ForEach(x => AddCheckPointObject(x));
            new List<CheckPoint_NetworkGroup>(cpNetGroupsDict.Values).ForEach(x => AddCheckPointObject(x));
            new List<CheckPointObject>(cpServicesDict.Values).ForEach(x =>
            {
                if (x.GetType() != typeof(CheckPoint_PredifinedObject))
                    AddCheckPointObject(x);
            });
            new List<CheckPoint_ServiceGroup>(cpServicesGroupsDict.Values).ForEach(x => AddCheckPointObject(x));
            new List<CheckPoint_ApplicationGroup>(cpAppGroupsDict.Values).ForEach(x => AddCheckPointObject(x));
            new List<List<CheckPoint_Time>>(cpSchedulesDict.Values).ForEach(x => x.ForEach(y => AddCheckPointObject(y)));

            ExportManagmentReport(false);
            NewPaloAnalizStatistic.FlushObjects();

            // to clean; must be the last!!!
            _cpObjects.ClearRepository();
            CleanSavedData();
        }

        public void ExportManagmentReport(bool optimazed)
        {


            NewPaloAnalizStatistic._unusedNetworkObjectsCount += _cpNetworks.Count * (optimazed ? -1 : 1);
            NewPaloAnalizStatistic._unusedNetworkObjectsCount += _cpNetworkGroups.Count * (optimazed ? -1 : 1);
            NewPaloAnalizStatistic._unusedNetworkObjectsCount += _cpRanges.Count * (optimazed ? -1 : 1);
            NewPaloAnalizStatistic._unusedNetworkObjectsCount += _cpHosts.Count * (optimazed ? -1 : 1);

            NewPaloAnalizStatistic._unusedServicesObjectsCount += _cpTcpServices.Count * (optimazed ? -1 : 1);
            NewPaloAnalizStatistic._unusedServicesObjectsCount += _cpUdpServices.Count * (optimazed ? -1 : 1);
            NewPaloAnalizStatistic._unusedServicesObjectsCount += _cpSctpServices.Count * (optimazed ? -1 : 1);
            NewPaloAnalizStatistic._unusedServicesObjectsCount += _cpIcmpServices.Count * (optimazed ? -1 : 1);
            NewPaloAnalizStatistic._unusedServicesObjectsCount += _cpDceRpcServices.Count * (optimazed ? -1 : 1);
            NewPaloAnalizStatistic._unusedServicesObjectsCount += _cpOtherServices.Count * (optimazed ? -1 : 1);
            NewPaloAnalizStatistic._unusedServicesObjectsCount += _cpServiceGroups.Count * (optimazed ? -1 : 1);

            if (optimazed)
            {
                NewPaloAnalizStatistic.Flush();
            }
            else
            {
                int optimazed_count = 0;
                if (NewPaloAnalizStatistic._Package != null)
                {
                    int dis = 0;
                    int all = 0;
                    int so_count = 0;
                    int se_count = 0;
                    int de_count = 0;
                    int time_count = 0;
                    foreach (var layer in _cpPackages[0].SubPolicies)
                    {
                        foreach (var policy in layer.Rules)
                        {
                            bool any_fl = true;
                            if (policy.Time.Count > 0)
                            {
                                time_count++;
                            }
                            if (!policy.Enabled)
                            {
                                dis += 1;
                            }
                            if (policy.Comments == null || policy.Comments == "")
                            {
                                NewPaloAnalizStatistic._uncommentedServicesRulesCount++;
                            }
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
                        }
                    }
                    foreach (var policy in _cpPackages[0].ParentLayer.Rules)
                    {
                        bool any_fl = true;
                        if (policy.Time.Count > 0)
                        {
                            time_count++;
                        }
                        if (!policy.Enabled)
                        {
                            dis += 1;
                        }
                        if (policy.Comments == null || policy.Comments == "")
                        {
                            NewPaloAnalizStatistic._uncommentedServicesRulesCount++;
                        }
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
                    }
                    NewPaloAnalizStatistic._rulesServicesutilizingServicesAnyDestinationCount = de_count;
                    NewPaloAnalizStatistic._rulesServicesutilizingServicesAnyServiceCount = se_count;
                    NewPaloAnalizStatistic._rulesServicesutilizingServicesAnySourceCount = so_count;
                    NewPaloAnalizStatistic._rulesServicesutilizingServicesAnyCount = all;
                    NewPaloAnalizStatistic._disabledServicesRulesCount = dis;
                    NewPaloAnalizStatistic._timesServicesRulesCount = time_count;

                    foreach (var sub_policy in _cpPackages[1].SubPolicies)
                    {
                        optimazed_count += sub_policy.Rules.Count();
                    }
                    optimazed_count += _cpPackages[1].ParentLayer.Rules.Count();
                    NewPaloAnalizStatistic._totalServicesRulesOptCount = optimazed_count;

                }
                if (_cpPackages.Count > 0)
                {
                    NewPaloAnalizStatistic._totalServicesRulesCount = _cpPackages[0].TotalRules();
                    NewPaloAnalizStatistic._totalServicesRulesOptCount = _cpPackages[1].TotalRules();
                    this.OptimizationPotential = NewPaloAnalizStatistic._totalServicesRulesCount > 0 ? ((NewPaloAnalizStatistic._totalServicesRulesCount - NewPaloAnalizStatistic._totalServicesRulesOptCount) * 100 / (float)NewPaloAnalizStatistic._totalServicesRulesCount) : 0;
                    NewPaloAnalizStatistic.CalculateCorrectAll(_cpNetworks, _cpNetworkGroups, _cpHosts, _cpRanges, _cpTcpServices, _cpUdpServices, _cpSctpServices, _cpIcmpServices, _cpDceRpcServices, _cpOtherServices, _cpServiceGroups, _cpRpcServices);
                    ExportManagmentReport();
                    OptimizationPotential = -1;
                    TotalRules += NewPaloAnalizStatistic._totalServicesRulesCount;
                }

            }
        }

        public override void ExportManagmentReport()
        {
            NewPaloAnalizStatistic._totalFileRules += NewPaloAnalizStatistic._totalServicesRulesCount;
            NewPaloAnalizStatistic._totalFileRulesOpt += NewPaloAnalizStatistic._totalServicesRulesOptCount;
            var potentialCount = NewPaloAnalizStatistic._totalServicesRulesCount - NewPaloAnalizStatistic._totalServicesRulesOptCount;
            var potentialPersent = NewPaloAnalizStatistic._totalServicesRulesCount > 0 ? (potentialCount * 100 / (float)NewPaloAnalizStatistic._totalServicesRulesCount) : 0;
            NewPaloAnalizStatistic._fullrullPackageCount += NewPaloAnalizStatistic._fullrullPackcount;
            NewPaloAnalizStatistic._totalrullPackageCount += NewPaloAnalizStatistic._totalServicesRulesCount;
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
                file.WriteLine("<h2>PaloAlto managment report file</h2>");
                file.WriteLine("<h3>OBJECTS DATABASE</h3>");

                file.WriteLine("<table style='margin-bottom: 30px; background: rgb(250,250,250);'>");
                file.WriteLine($"   <tr><td style='font-size: 14px;'></td> <td style='font-size: 14px;'>STATUS</td> <td style='font-size: 14px;'>COUNT</td> <td style='font-size: 14px;'>PERCENT</td> <td style='font-size: 14px;'>REMEDIATION</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Total Network Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.TotalNetworkObjectsPercent, 100, 100)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._totalNetworkObjectsCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.TotalNetworkObjectsPercent}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Unused Network Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.UnusedNetworkObjectsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._unusedNetworkObjectsCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.UnusedNetworkObjectsPercent.ToString("F")}%</td> <td style='font-size: 14px;'>{(NewPaloAnalizStatistic._unusedNetworkObjectsCount > 0 ? "Consider deleting these objects." : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Duplicate Network Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.DuplicateNetworkObjectsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._duplicateNetworkObjectsCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.DuplicateNetworkObjectsPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Nested Network Groups</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.NestedNetworkGroupsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._nestedNetworkGroupsCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.NestedNetworkGroupsPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine("</table>");

                file.WriteLine("<h3>SERVICES DATABASE</h3>");
                file.WriteLine("<table style='margin-bottom: 30px; background: rgb(250,250,250);'>");
                file.WriteLine($"   <tr><td style='font-size: 14px;'></td> <td style='font-size: 14px;'>STATUS</td> <td style='font-size: 14px;'>COUNT</td> <td style='font-size: 14px;'>PERCENT</td> <td style='font-size: 14px;'>REMEDIATION</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Total Services Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.TotalServicesObjectsPercent, 100, 100)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._totalServicesObjectsCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.TotalServicesObjectsPercent}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Unused Services Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.UnusedServicesObjectsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._unusedServicesObjectsCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.UnusedServicesObjectsPercent.ToString("F")}%</td> <td style='font-size: 14px;'>{(NewPaloAnalizStatistic._unusedServicesObjectsCount > 0 ? "Consider deleting these objects." : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Duplicate Services Objects</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.DuplicateServicesObjectsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._duplicateServicesObjectsCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.DuplicateServicesObjectsPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Nested Services Groups</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.NestedServicesGroupsPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._nestedServicesGroupsCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.NestedServicesGroupsPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine("</table>");

                file.WriteLine("<h3>POLICY ANALYSIS</h3>");
                file.WriteLine("<table style='margin-bottom: 30px; background: rgb(250,250,250);'>");
                file.WriteLine($"   <tr><td style='font-size: 14px;'></td> <td style='font-size: 14px;'>STATUS</td> <td style='font-size: 14px;'>COUNT</td> <td style='font-size: 14px;'>PERCENT</td> <td style='font-size: 14px;'>REMEDIATION</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Total Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.TotalServicesRulesPercent, 100, 100)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._totalServicesRulesCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.TotalServicesRulesPercent}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Rules utilizing \"Any\"</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.RulesServicesutilizingServicesAnyPercent, 5, 15)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._rulesServicesutilizingServicesAnyCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.RulesServicesutilizingServicesAnyPercent.ToString("F")}%</td> <td style='font-size: 14px;'>- ANY in Source: {NewPaloAnalizStatistic._rulesServicesutilizingServicesAnySourceCount}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'>- ANY in Destination: {NewPaloAnalizStatistic._rulesServicesutilizingServicesAnyDestinationCount} </td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'></td> <td style='font-size: 14px;'>- ANY in Service: {NewPaloAnalizStatistic._rulesServicesutilizingServicesAnyServiceCount}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Disabled Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.DisabledServicesRulesPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._disabledServicesRulesCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.DisabledServicesRulesPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td> {(NewPaloAnalizStatistic._disabledServicesRulesCount > 0 ? "Check if rules are required." : "")}</tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Times Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.TimesServicesRulesPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._timesServicesRulesCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.TimesServicesRulesPercent.ToString("F")}%</td> <td style='font-size: 14px;'></td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Non Logging Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.NonServicesLoggingServicesRulesPercent, 5, 25)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._nonServicesLoggingServicesRulesCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.NonServicesLoggingServicesRulesPercent.ToString("F")}%</td> <td style='font-size: 14px;'> {(NewPaloAnalizStatistic._nonServicesLoggingServicesRulesCount > 0 ? "Enable logging for these rules for better tracking and change management." : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Cleanup Rule</td> <td style='font-size: 14px;'>{(NewPaloAnalizStatistic._cleanupServicesRuleCount > 0 ? HtmlGoodImageTagManagerReport : HtmlSeriosImageTagManagerReport)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._cleanupServicesRuleCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.CleanupServicesRulePercent.ToString("F")}%</td> <td style='font-size: 14px;'>{(NewPaloAnalizStatistic._cleanupServicesRuleCount > 0 ? "Found" : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Uncommented Rules</td> <td style='font-size: 14px;'>{ChoosePict(NewPaloAnalizStatistic.UncommentedServicesRulesPercent, 25, 100)}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic._uncommentedServicesRulesCount}</td> <td style='font-size: 14px;'>{NewPaloAnalizStatistic.UncommentedServicesRulesPercent.ToString("F")}%</td> <td style='font-size: 14px;'>{(NewPaloAnalizStatistic._uncommentedServicesRulesCount > 0 ? "Comment rules for better tracking and change management compliance." : "")}</td></tr>");
                file.WriteLine($"   <tr><td style='font-size: 14px; color: Black;'>Optimization Potential</td> <td style='font-size: 14px;'>{(potentialCount > 0 ? HtmlGoodImageTagManagerReport : HtmlAttentionImageTagManagerReport)}</td> <td style='font-size: 14px;'>{potentialCount}</td> <td style='font-size: 14px;'>{(potentialCount > 0 ? potentialPersent : 0).ToString("F")}%</td> <td style='font-size: 14px;'>{GetOptPhraze(potentialCount > 0 ? (int)potentialPersent : 0)}</td></tr>");
                file.WriteLine("</table>");
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
                foreach (string vsysName in _vsysNames)
                {
                    if (File.Exists(this._targetFolder + "\\" + vsysName + "\\" + vsysName + "_managment_report.html"))
                    {
                        file.WriteLine("<li>" + "<a href=\" " + vsysName + "\\" + vsysName + "_managment_report.html" + "\">" + "<h2>" + vsysName + "</h2>" + "</a>" + "</li>");
                    }
                    else
                    {
                        file.WriteLine("<li>" + "<h2>" + vsysName + "</h2>" + "</li>");
                    }
                }
                file.WriteLine("</ul>");
                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        public override Dictionary<string, int> Convert(bool convertNat)
        {

            string targetFileNameMain = _vendorFileName;
            string targetFolderMain = _targetFolder;
            _isOverMaxLengthPackageName = false;

            if (IsConsoleRunning)
                Progress = new ProgressBar();

            PA_Config paConfig = _paParser.Config;
            _isNatConverted = convertNat;

            LDAP_Account_Unit = LDAPAccoutUnit.Trim();

            if (paConfig != null)
            {
                List<PA_TagEntry> s_TagEntries = new List<PA_TagEntry>();
                Dictionary<string, CheckPointObject> s_cpAddressesDict = null;
                Dictionary<string, CheckPoint_NetworkGroup> s_cpNetGroupsDict = null;
                Dictionary<string, CheckPointObject> s_cpServicesDict = null;
                Dictionary<string, string> s_paServicesTypesDict = null;
                Dictionary<string, CheckPoint_ServiceGroup> s_cpServicesGroupsDict = null;
                List<string> s_paAppFiltersList = null;
                Dictionary<string, CheckPoint_ApplicationGroup> s_cpAppGroupsDict = null;
                Dictionary<string, List<CheckPoint_Time>> s_cpSchedulesDict = null;

                if (paConfig.Shared != null)
                {
                    if (paConfig.Shared.TagsEntries != null)
                        s_TagEntries.AddRange(paConfig.Shared.TagsEntries);
                    s_cpAddressesDict = ConvertAddresses(paConfig.Shared, null);

                    s_cpNetGroupsDict = ConvertAddressesGroupsWithInspection(paConfig.Shared, s_cpAddressesDict, null, null);

                    s_cpServicesDict = ConvertServices(paConfig.Shared, null);

                    s_paServicesTypesDict = GetServicesTypes(paConfig.Shared, null);

                    s_cpServicesGroupsDict = ConvertServicesGroupsWithInspection(paConfig.Shared, s_cpServicesDict, null);

                    List<string> s_appsMatchList = GetApplicationsMatchList();

                    s_paAppFiltersList = GetPAApplicationsFilters(paConfig.Shared, null);

                    s_cpAppGroupsDict = ConvertApplicationsGroups(new List<PA_ApplicationGroupEntry>(paConfig.Shared.ApplicationGroupsEntries), s_appsMatchList, null, s_paAppFiltersList, s_cpServicesGroupsDict);

                    s_cpSchedulesDict = new Dictionary<string, List<CheckPoint_Time>>();
                    ConvertSchedules(paConfig.Shared).ForEach(x =>
                    {
                        string key = x.Name;
                        x = InspectCpScheduleName(x);
                        List<CheckPoint_Time> cpTimesList = null;
                        if (s_cpSchedulesDict.ContainsKey(key))
                            cpTimesList = s_cpSchedulesDict[key];
                        else
                            cpTimesList = new List<CheckPoint_Time>();
                        cpTimesList.Add(x);
                        s_cpSchedulesDict[key] = cpTimesList;
                    });
                }
                if (paConfig.Devices != null)
                {
                    if (paConfig.Devices.DevicesEntry != null && paConfig.Devices.DevicesEntry.Name.Equals(LOCAL_DEVICE_ENTRY_NAME)) //we parse PA config from PA
                    {
                        if (paConfig.Devices.DevicesEntry.Vsys != null &&
                            paConfig.Devices.DevicesEntry.Vsys.VsysEntries != null &&
                            paConfig.Devices.DevicesEntry.Vsys.VsysEntries.Count > 0)
                        {
                            if (paConfig.Devices.DevicesEntry.Vsys.VsysEntries.Count == 1)
                            {
                                ConvertPaVsysEntry(targetFolderMain, targetFileNameMain, paConfig.Devices.DevicesEntry.Vsys.VsysEntries[0],
                                                    s_TagEntries,
                                                    s_cpAddressesDict,
                                                    s_cpNetGroupsDict,
                                                    s_cpServicesDict,
                                                    s_paServicesTypesDict,
                                                    s_cpServicesGroupsDict,
                                                    s_paAppFiltersList,
                                                    s_cpAppGroupsDict,
                                                    s_cpSchedulesDict);
                            }
                            else
                            {
                                foreach (PA_VsysEntry paVsysEntry in paConfig.Devices.DevicesEntry.Vsys.VsysEntries)
                                {
                                    string paVsysName = paVsysEntry.Name;
                                    _vsysNames.Add(paVsysName);
                                    string targetFolderVsys = targetFolderMain + "\\" + paVsysName;
                                    System.IO.Directory.CreateDirectory(targetFolderVsys);
                                    ConvertPaVsysEntry(targetFolderVsys, paVsysName, paVsysEntry,
                                                        s_TagEntries,
                                                        s_cpAddressesDict,
                                                        s_cpNetGroupsDict,
                                                        s_cpServicesDict,
                                                        s_paServicesTypesDict,
                                                        s_cpServicesGroupsDict,
                                                        s_paAppFiltersList,
                                                        s_cpAppGroupsDict,
                                                        s_cpSchedulesDict);
                                }

                                _warningsConvertedPackage = -1;
                                _errorsConvertedPackage = -1;
                                _rulesInConvertedPackage = -1;
                                _rulesInNatLayer = -1;
                                CleanCheckPointObjectsLists();

                                // changing target folder path to folder contains config file
                                ChangeTargetFolder(targetFolderMain, targetFileNameMain);

                                // create HTML files which contain links to each report
                                CreateCatalogObjects();
                                CreateCatalogNATs();
                                CreateCatalogPolicies();
                                CreateCatalogOptPolicies();
                                CreateCatalogErrors();
                                CreateCatalogWarnings();
                            }
                        }
                    }
                }
            }

            if (IsConsoleRunning)
            {
                Console.WriteLine("Optimizing Firewall rulebase ...");
                Progress.SetProgress(70);
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

            VendorHtmlFile = _vendorFilePath;

            ObjectsScriptFile = _targetFolder;
            PolicyScriptFile = _targetFolder;


            if (IsConsoleRunning)
            {
                Progress.SetProgress(100);
                Progress.Dispose();
            }

            if (_vsysNames.Count > 0)
                ShowOptBashLink = false;

            return new Dictionary<string, int>() { { "errors", ErrorsInConvertedPackage() }, { "warnings", WarningsInConvertedPackage() } };
        }

        public void ConvertPaVsysEntry(string targetFolderNew, string targetFileNameNew, PA_VsysEntry paVsysEntry,
                                        List<PA_TagEntry> s_TagEntries,
                                        Dictionary<string, CheckPointObject> s_cpAddressesDict,
                                        Dictionary<string, CheckPoint_NetworkGroup> s_cpNetGroupsDict,
                                        Dictionary<string, CheckPointObject> s_cpServicesDict,
                                        Dictionary<string, string> s_paServicesTypesDict,
                                        Dictionary<string, CheckPoint_ServiceGroup> s_cpServicesGroupsDict,
                                        List<string> s_paAppFiltersList,
                                        Dictionary<string, CheckPoint_ApplicationGroup> s_cpAppGroupsDict,
                                        Dictionary<string, List<CheckPoint_Time>> s_cpSchedulesDict)
        {
            if (IsConsoleRunning)
            {
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

            _cpObjects.Initialize(); // must be first!!!
            CleanCheckPointObjectsLists(); // must be first!!!

            //change folder path for writing reports
            //if it is multi-VSYS then each report will be placed to own folder
            //if it is single VSYS then report will be in the same folder as config file
            ChangeTargetFolder(targetFolderNew, targetFileNameNew);

            //convert PaloAlto Ojbects to CheckPoint Objects and save them to correspondings List

            Dictionary<string, CheckPoint_Zone> cpZonesDict = ConvertZones(paVsysEntry);

            Dictionary<string, CheckPointObject> cpAddressesDict = ConvertAddresses(paVsysEntry, s_cpAddressesDict);

            Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsDict = ConvertAddressesGroupsWithInspection(paVsysEntry, cpAddressesDict, s_cpNetGroupsDict, s_TagEntries);

            Dictionary<string, CheckPointObject> cpServicesDict = ConvertServices(paVsysEntry, s_cpServicesDict);

            Dictionary<string, string> paServicesTypesDict = GetServicesTypes(paVsysEntry, s_paServicesTypesDict);

            Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsDict = ConvertServicesGroupsWithInspection(paVsysEntry, cpServicesDict, s_cpServicesGroupsDict);

            List<string> appsMatchList = GetApplicationsMatchList();

            List<string> paAppFiltersList = GetPAApplicationsFilters(paVsysEntry, s_paAppFiltersList);

            Dictionary<string, CheckPoint_ApplicationGroup> cpAppGroupsDict =
                ConvertApplicationsGroups(new List<PA_ApplicationGroupEntry>(paVsysEntry.ApplicationGroupsEntries), appsMatchList, s_cpAppGroupsDict, paAppFiltersList, cpServicesGroupsDict);

            Dictionary<string, List<CheckPoint_Time>> cpSchedulesDict = null;
            if (s_cpSchedulesDict != null)
                cpSchedulesDict = new Dictionary<string, List<CheckPoint_Time>>(s_cpSchedulesDict);
            else
                cpSchedulesDict = new Dictionary<string, List<CheckPoint_Time>>();
            ConvertSchedules(paVsysEntry).ForEach(x =>
            {
                string key = x.Name;
                x = InspectCpScheduleName(x);
                List<CheckPoint_Time> cpTimesList = null;
                if (cpSchedulesDict.ContainsKey(key))
                    cpTimesList = cpSchedulesDict[key];
                else
                    cpTimesList = new List<CheckPoint_Time>();
                cpTimesList.Add(x);
                cpSchedulesDict[key] = cpTimesList;
            });

            Dictionary<string, CheckPoint_AccessRole> cpAccessRolesDict = new Dictionary<string, CheckPoint_AccessRole>();

            if (IsConsoleRunning)
            {
                Console.WriteLine("Convert policy...");
                Progress.SetProgress(60);
                Thread.Sleep(1000);
            }
            RaiseConversionProgress(60, "Convert policy...");

            ConvertSecurityPolicy(paVsysEntry, cpZonesDict,
                                  cpAddressesDict, cpNetGroupsDict,
                                  cpServicesDict, cpServicesGroupsDict,
                                  appsMatchList, cpAppGroupsDict, paAppFiltersList,
                                  cpSchedulesDict, cpAccessRolesDict);

            new List<CheckPoint_AccessRole>(cpAccessRolesDict.Values).ForEach(x => AddCheckPointObject(x));

            if (_isNatConverted)
            {
                ConvertNatPolicy(paVsysEntry, cpAddressesDict, cpNetGroupsDict, cpServicesDict, paServicesTypesDict, cpServicesGroupsDict, cpServicesGroupsDict);
            }

            //if non-optimized convert method is used then all objects are added

            if (!OptimizeConf)
            {
                new List<CheckPoint_Zone>(cpZonesDict.Values).ForEach(x => AddCheckPointObject(x));
                new List<CheckPointObject>(cpAddressesDict.Values).ForEach(x => AddCheckPointObject(x));
                new List<CheckPoint_NetworkGroup>(cpNetGroupsDict.Values).ForEach(x => AddCheckPointObject(x));
                new List<CheckPointObject>(cpServicesDict.Values).ForEach(x =>
                {
                    if (x.GetType() != typeof(CheckPoint_PredifinedObject))
                        AddCheckPointObject(x);
                });
                new List<CheckPoint_ServiceGroup>(cpServicesGroupsDict.Values).ForEach(x => AddCheckPointObject(x));
                new List<CheckPoint_ApplicationGroup>(cpAppGroupsDict.Values).ForEach(x => AddCheckPointObject(x));
                new List<List<CheckPoint_Time>>(cpSchedulesDict.Values).ForEach(x => x.ForEach(y => AddCheckPointObject(y)));
            }


            if (_cpPackages.Count > 0)
            {
                Add_Optimized_Package();
            }

            //Creating Result Files in Scripting Format and their reports in HTML format
            if (!_isOverMaxLengthPackageName)
                CreateObjectsScript();
            CreateObjectsHtml();

            if (!_isOverMaxLengthPackageName)
                CreatePackagesScript();
            ExportPolicyPackagesAsHtmlConfig();

            CreateErrorsHtml(targetFileNameNew);
            CreateWarningsHtml(targetFileNameNew);

            ExportNatLayerAsHtml();

            _warningsConvertedPackage = _warningsList.Count;
            _errorsConvertedPackage = _errorsList.Count;

            if (!_isOverMaxLengthPackageName)
            {
                CreateSmartConnector(true, false);
                CreateSmartConnector(true, true);
            }

            // to clean; must be the last!!!
            _cpObjects.ClearRepository();
            CleanSavedData();
        }

        public void CleanSavedData()
        {
            _errorsList.Clear();
            _warningsList.Clear();
            _timeCutterCounter = 0;
            _numPostfix = 0;
            _objectsNamesSet.Clear();
        }

        public string InspectObjectName(string objName, string objType)
        {
            string objNameNew = "";

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

            if (reservedWords.Contains(objName))
            {
                objNameNew += "_" + objName;
                _warningsList.Add(objName + " " + objType.Trim() + " was renamed to " + objNameNew);
                objName = objNameNew;
            }

            objNameNew = GetSafeName(objName);
            if (!objNameNew.Equals(objName))
            {
                _warningsList.Add(objName + " " + objType.Trim() + " was renamed to " + objNameNew);
                objName = objNameNew;
            }

            if (!_objectsNamesSet.Add(objName.ToLower()))
            {
                objNameNew = objName + "_" + _numPostfix++;
                _warningsList.Add(objName + " " + objType.Trim() + " was renamed to " + objNameNew);
                objName = objNameNew;
                _objectsNamesSet.Add(objName.ToLower());
            }
            return objName;
        }

        #endregion

        #region Convert Zones

        public Dictionary<string, CheckPoint_Zone> ConvertZones(PA_VsysEntry paVsysEntry)
        {
            Dictionary<string, CheckPoint_Zone> cpZonesDict = new Dictionary<string, CheckPoint_Zone>();

            if (paVsysEntry.ZoneEntries != null)
            {
                foreach (PA_ZoneEntry paZoneEntry in paVsysEntry.ZoneEntries)
                {
                    CheckPoint_Zone cpZone = new CheckPoint_Zone();
                    cpZone.Name = InspectObjectName(paZoneEntry.Name, CP_OBJECT_TYPE_NAME_ZONE);
                    cpZone.Name = cpZone.SafeName();
                    cpZone.Comments = paZoneEntry.Description;
                    cpZone.Tags = paZoneEntry.TagMembers;
                    cpZonesDict[paZoneEntry.Name] = cpZone;
                }
            }

            return cpZonesDict;
        }

        #endregion

        #region Convert Addresses and Addresses Groups

        public Dictionary<string, CheckPointObject> ConvertAddresses(PA_Objects paObjects, Dictionary<string, CheckPointObject> s_cpAddressesDict)
        {
            Dictionary<string, CheckPointObject> cpAddressesDict = null;
            if (s_cpAddressesDict != null)
                cpAddressesDict = new Dictionary<string, CheckPointObject>(s_cpAddressesDict);
            else
                cpAddressesDict = new Dictionary<string, CheckPointObject>();

            if (paObjects.AddressEntries != null)
            {
                foreach (PA_AddressEntry paAddressEntry in paObjects.AddressEntries)
                {
                    if (!string.IsNullOrWhiteSpace(paAddressEntry.IpNetmask))
                    {
                        int indexSlash = paAddressEntry.IpNetmask.IndexOf("/");

                        if (indexSlash == -1)
                        {
                            CheckPoint_Host cpHost = new CheckPoint_Host();
                            cpHost.Name = InspectObjectName(paAddressEntry.Name, CP_OBJECT_TYPE_NAME_ADDRESS_HOST);
                            cpHost.Comments = paAddressEntry.Description;
                            cpHost.Tags = paAddressEntry.TagMembers;
                            cpHost.IpAddress = paAddressEntry.IpNetmask;
                            cpAddressesDict[paAddressEntry.Name] = cpHost;
                        }
                        else if (NetworkUtils.IsValidIpv4(paAddressEntry.IpNetmask.Substring(0, indexSlash)) && paAddressEntry.IpNetmask.Substring(indexSlash + 1).Trim().Equals(NETWORK_NETMASK)
                                    || NetworkUtils.IsValidIpv6(paAddressEntry.IpNetmask.Substring(0, indexSlash)) && paAddressEntry.IpNetmask.Substring(indexSlash + 1).Trim().Equals(NETWORK_NETMASK_V6))
                        {
                            CheckPoint_Host cpHost = new CheckPoint_Host();
                            cpHost.Name = InspectObjectName(paAddressEntry.Name, CP_OBJECT_TYPE_NAME_ADDRESS_HOST);
                            cpHost.Comments = paAddressEntry.Description;
                            cpHost.Tags = paAddressEntry.TagMembers;
                            cpHost.IpAddress = paAddressEntry.IpNetmask.Substring(0, indexSlash);
                            cpAddressesDict[paAddressEntry.Name] = cpHost;
                        }
                        else
                        {
                            CheckPoint_Network cpNetwork = new CheckPoint_Network();
                            cpNetwork.Name = InspectObjectName(paAddressEntry.Name, CP_OBJECT_TYPE_NAME_ADDRESS_NETWORK);
                            cpNetwork.Comments = paAddressEntry.Description;
                            cpNetwork.Tags = paAddressEntry.TagMembers;
                            cpNetwork.Subnet = paAddressEntry.IpNetmask.Substring(0, indexSlash);
                            if (NetworkUtils.IsValidIpv6(cpNetwork.Subnet))
                            {
                                cpNetwork.MaskLength = paAddressEntry.IpNetmask.Substring(indexSlash + 1);
                            }
                            else
                            {
                                cpNetwork.Netmask = IPNetwork.Parse(paAddressEntry.IpNetmask).Netmask.ToString();
                            }
                            cpAddressesDict[paAddressEntry.Name] = cpNetwork;
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(paAddressEntry.IpRange))
                    {
                        int indexDash = paAddressEntry.IpRange.IndexOf("-");

                        CheckPoint_Range cpRange = new CheckPoint_Range();
                        cpRange.Name = InspectObjectName(paAddressEntry.Name, CP_OBJECT_TYPE_NAME_ADDRESS_RANGE);
                        cpRange.Comments = paAddressEntry.Description;
                        cpRange.Tags = paAddressEntry.TagMembers;
                        cpRange.RangeFrom = paAddressEntry.IpRange.Substring(0, indexDash);
                        cpRange.RangeTo = paAddressEntry.IpRange.Substring(indexDash + 1);
                        cpAddressesDict[paAddressEntry.Name] = cpRange;

                    }

                    if (!string.IsNullOrWhiteSpace(paAddressEntry.Fqdn))
                    {
                        int index = (new List<CheckPointObject>(cpAddressesDict.Values)).FindIndex(x => x.GetType() == typeof(CheckPoint_Domain) && x.Name.Equals("." + paAddressEntry.Fqdn));
                        CheckPoint_Domain cpDomain = null;
                        if (index == -1)
                        {
                            cpDomain = new CheckPoint_Domain();
                            cpDomain.Name = "." + paAddressEntry.Fqdn;
                            cpDomain.Comments = paAddressEntry.Description;
                            cpDomain.Tags = paAddressEntry.TagMembers;
                            cpDomain.Fqdn = paAddressEntry.Fqdn;
                        }
                        else
                        {
                            cpDomain = (CheckPoint_Domain)(new List<CheckPointObject>(cpAddressesDict.Values))[index];
                        }
                        cpAddressesDict[paAddressEntry.Name] = cpDomain;
                    }
                }
            }

            return cpAddressesDict;
        }

        public Dictionary<string, CheckPoint_NetworkGroup> ConvertAddressesGroups(PA_Objects paObjects, List<PA_TagEntry> s_TagEntries,
                                                                                  List<CheckPointObject> cpAddressesList,
                                                                                  Dictionary<string, CheckPoint_NetworkGroup> s_cpNetGroupsDict)
        {
            Dictionary<string, CheckPoint_NetworkGroup> cpAddressesGroupsDict = null;
            if (s_cpNetGroupsDict != null)
                cpAddressesGroupsDict = new Dictionary<string, CheckPoint_NetworkGroup>(s_cpNetGroupsDict);
            else
                cpAddressesGroupsDict = new Dictionary<string, CheckPoint_NetworkGroup>();


            List<CheckPoint_NetworkGroup> cpNetGrpList = new List<CheckPoint_NetworkGroup>();
            if (s_cpNetGroupsDict != null)
                cpNetGrpList.AddRange((new List<CheckPoint_NetworkGroup>(s_cpNetGroupsDict.Values)));

            if (paObjects.AddressGroupEntries != null)
            {
                foreach (PA_AddressGroupEntry paAddressGroupEntry in paObjects.AddressGroupEntries)
                {
                    CheckPoint_NetworkGroup cpNetGroup = new CheckPoint_NetworkGroup();
                    cpNetGroup.Name = paAddressGroupEntry.Name;
                    cpNetGroup.Comments = paAddressGroupEntry.Description;
                    cpNetGroup.Tags = paAddressGroupEntry.TagMembers;
                    cpNetGrpList.Add(cpNetGroup);
                }
            }


            Dictionary<string, List<string>> tagsToMembersDict = GetDictTagsToNames(paObjects, s_TagEntries, cpAddressesList, cpNetGrpList);

            if (paObjects.AddressGroupEntries != null)
            {
                foreach (PA_AddressGroupEntry paAddressGroupEntry in paObjects.AddressGroupEntries)
                {
                    CheckPoint_NetworkGroup cpNetGroup = new CheckPoint_NetworkGroup();
                    cpNetGroup.Name = InspectObjectName(GetSafeName(paAddressGroupEntry.Name), CP_OBJECT_TYPE_NAME_ADDRESS_GROUP);
                    cpNetGroup.Comments = paAddressGroupEntry.Description;
                    cpNetGroup.Tags = paAddressGroupEntry.TagMembers;

                    if (paAddressGroupEntry.StaticMembers != null && paAddressGroupEntry.StaticMembers.Count > 0)
                    {
                        cpNetGroup.Members = paAddressGroupEntry.StaticMembers;
                    }
                    else if (paAddressGroupEntry.Dynamic != null && !string.IsNullOrWhiteSpace(paAddressGroupEntry.Dynamic.Filter))
                    {
                        string adjustedFilter = paAddressGroupEntry.Dynamic.Filter.Trim('\'').Trim('"').Trim();

                        if (tagsToMembersDict.ContainsKey(adjustedFilter))
                        {
                            cpNetGroup.Members = tagsToMembersDict[adjustedFilter];
                        }
                        else
                        {
                            _errorsList.Add(cpNetGroup.Name + " dynamic network group is not converted because the filter is too complex");
                            cpNetGroup = null;
                        }
                    }

                    if (cpNetGroup != null)
                    {
                        cpAddressesGroupsDict[paAddressGroupEntry.Name] = cpNetGroup;
                    }
                }
            }

            return cpAddressesGroupsDict;
        }

        public Dictionary<string, List<string>> GetDictTagsToNames(PA_Objects paObjects, List<PA_TagEntry> s_TagEntries,
                                                                    List<CheckPointObject> cpAddressesList, List<CheckPoint_NetworkGroup> cpNetGrpList)
        {
            Dictionary<string, List<string>> tagsToNamesDict = new Dictionary<string, List<string>>();

            List<PA_TagEntry> tagEntriesList = new List<PA_TagEntry>();
            if (s_TagEntries != null)
                tagEntriesList.AddRange(s_TagEntries);

            tagEntriesList.AddRange(paObjects.TagsEntries);

            foreach (PA_TagEntry paTagEntry in tagEntriesList)
            {
                if (tagsToNamesDict.ContainsKey(paTagEntry.Name))
                    continue;

                List<string> namesList = new List<string>();

                if (cpAddressesList != null)
                {
                    foreach (CheckPointObject cpAddressEntry in cpAddressesList)
                    {
                        if (cpAddressEntry.Tags.Contains(paTagEntry.Name))
                        {
                            namesList.Add(cpAddressEntry.Name);
                        }
                    }
                }

                if (cpNetGrpList != null)
                {
                    foreach (CheckPoint_NetworkGroup cpAddressGroupEntry in cpNetGrpList)
                    {
                        if (cpAddressGroupEntry.Tags.Contains(paTagEntry.Name))
                        {
                            namesList.Add(cpAddressGroupEntry.Name);
                        }
                    }
                }

                tagsToNamesDict.Add(paTagEntry.Name, namesList);
            }

            return tagsToNamesDict;
        }

        public Dictionary<string, CheckPoint_NetworkGroup> ConvertAddressesGroupsWithInspection(PA_Objects paVsysEntry,
                                                                                                Dictionary<string, CheckPointObject> cpAddressesDict,
                                                                                                Dictionary<string, CheckPoint_NetworkGroup> s_cpNetGroupsDict,
                                                                                                List<PA_TagEntry> s_TagEntries)
        {
            Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsList =
                ConvertAddressesGroups(paVsysEntry, s_TagEntries, (new List<CheckPointObject>(cpAddressesDict.Values)), s_cpNetGroupsDict);

            Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsResult = InspectAddressGroups(cpAddressesDict, cpNetGroupsList, null);

            return cpNetGroupsResult;
        }

        public Dictionary<string, CheckPoint_NetworkGroup> InspectAddressGroups(Dictionary<string, CheckPointObject> cpAddressesNamesDict,
                                                                                Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsCheck,
                                                                                Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsTemp)
        {
            Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsResult = null;
            if (cpNetGroupsTemp != null)
            {
                cpNetGroupsResult = new Dictionary<string, CheckPoint_NetworkGroup>(cpNetGroupsTemp);
            }
            else
            {
                cpNetGroupsResult = new Dictionary<string, CheckPoint_NetworkGroup>();
            }

            while (cpNetGroupsCheck.Count > 0)
            {
                string paNetGroupName = new List<string>(cpNetGroupsCheck.Keys)[0];
                CheckPoint_NetworkGroup cpNetGroupCheck = cpNetGroupsCheck[paNetGroupName];
                cpNetGroupsCheck.Remove(paNetGroupName);

                CheckPoint_NetworkGroup cpNetGroupResult = new CheckPoint_NetworkGroup();
                cpNetGroupResult.Name = cpNetGroupCheck.Name;
                cpNetGroupResult.Comments = cpNetGroupCheck.Comments;
                cpNetGroupResult.Tags = cpNetGroupCheck.Tags;

                foreach (string member in cpNetGroupCheck.Members)
                {
                    if (cpAddressesNamesDict.ContainsKey(member)) //group member is in Addresses
                    {
                        cpNetGroupResult.Members.Add(cpAddressesNamesDict[member].Name);
                    }
                    else if (cpNetGroupsResult.ContainsKey(member)) //group member is converted and added to Addresses Groups
                    {
                        cpNetGroupResult.Members.Add(cpNetGroupsResult[member].Name);
                    }
                    else if (cpNetGroupsCheck.ContainsKey(member)) //group member is not converted yet
                    {
                        cpNetGroupsResult = InspectAddressGroups(cpAddressesNamesDict, cpNetGroupsCheck, cpNetGroupsResult);
                        if (cpNetGroupsResult.ContainsKey(member))
                        {
                            cpNetGroupResult.Members.Add(cpNetGroupsResult[member].Name);
                        }
                        else
                        {
                            _warningsList.Add(cpNetGroupCheck.Name + " address group contains non-existing member: " + member);
                        }
                    }
                    else
                    {
                        _warningsList.Add(cpNetGroupCheck.Name + " address group contains non-existing member: " + member);
                    }
                }
                cpNetGroupsResult.Add(paNetGroupName, cpNetGroupResult);
            }

            return cpNetGroupsResult;
        }

        #endregion

        #region Convert Schedules

        public List<CheckPoint_Time> ConvertSchedules(PA_Objects paObjects)
        {
            List<CheckPoint_Time> cpTimesList = new List<CheckPoint_Time>();

            if (paObjects.ScheduleEntries != null)
            {
                foreach (PA_ScheduleEntry paScheduleEntry in paObjects.ScheduleEntries)
                {
                    if (paScheduleEntry.Type.Recurring != null)
                    {
                        if (paScheduleEntry.Type.Recurring.MembersDaily != null)
                        {
                            for (int i = 0; i < paScheduleEntry.Type.Recurring.MembersDaily.Count; i += 3)
                            {
                                List<string> timesList =
                                    paScheduleEntry.Type.Recurring.MembersDaily.GetRange(i, Math.Min(3, paScheduleEntry.Type.Recurring.MembersDaily.Count - i));

                                CheckPoint_Time cpTime = new CheckPoint_Time();
                                cpTime.Name = paScheduleEntry.Name;
                                cpTime.Comments = paScheduleEntry.Description;
                                cpTime.Tags = paScheduleEntry.TagMembers;
                                cpTime.RecurrencePattern = CheckPoint_Time.RecurrencePatternEnum.Daily;
                                cpTime.StartNow = true;
                                cpTime.EndNever = true;

                                cpTime = SetHourseRanges(cpTime, timesList);

                                cpTimesList.Add(cpTime);
                            }
                        }
                        if (paScheduleEntry.Type.Recurring.Weekly != null)
                        {
                            if (paScheduleEntry.Type.Recurring.Weekly.MembersMonday != null)
                            {
                                for (int i = 0; i < paScheduleEntry.Type.Recurring.Weekly.MembersMonday.Count; i += 3)
                                {
                                    List<string> timesList =
                                        paScheduleEntry.Type.Recurring.Weekly.MembersMonday.GetRange(i, Math.Min(3, paScheduleEntry.Type.Recurring.Weekly.MembersMonday.Count - i));

                                    CheckPoint_Time cpTime = new CheckPoint_Time();
                                    cpTime.Name = paScheduleEntry.Name;
                                    cpTime.Comments = paScheduleEntry.Description;
                                    cpTime.Tags = paScheduleEntry.TagMembers;
                                    cpTime.RecurrencePattern = CheckPoint_Time.RecurrencePatternEnum.Weekly;
                                    cpTime.RecurrenceWeekdays.Add(CheckPoint_Time.Weekdays.Mon);
                                    cpTime.StartNow = true;
                                    cpTime.EndNever = true;

                                    cpTime = SetHourseRanges(cpTime, timesList);

                                    cpTimesList.Add(cpTime);
                                }
                            }
                            if (paScheduleEntry.Type.Recurring.Weekly.MembersTuesday != null)
                            {
                                for (int i = 0; i < paScheduleEntry.Type.Recurring.Weekly.MembersTuesday.Count; i += 3)
                                {
                                    List<string> timesList =
                                        paScheduleEntry.Type.Recurring.Weekly.MembersTuesday.GetRange(i, Math.Min(3, paScheduleEntry.Type.Recurring.Weekly.MembersTuesday.Count - i));

                                    CheckPoint_Time cpTime = new CheckPoint_Time();
                                    cpTime.Name = paScheduleEntry.Name;
                                    cpTime.Comments = paScheduleEntry.Description;
                                    cpTime.Tags = paScheduleEntry.TagMembers;
                                    cpTime.RecurrencePattern = CheckPoint_Time.RecurrencePatternEnum.Weekly;
                                    cpTime.RecurrenceWeekdays.Add(CheckPoint_Time.Weekdays.Tue);
                                    cpTime.StartNow = true;
                                    cpTime.EndNever = true;

                                    cpTime = SetHourseRanges(cpTime, timesList);

                                    cpTimesList.Add(cpTime);
                                }
                            }
                            if (paScheduleEntry.Type.Recurring.Weekly.MembersWednesday != null)
                            {
                                for (int i = 0; i < paScheduleEntry.Type.Recurring.Weekly.MembersWednesday.Count; i += 3)
                                {
                                    List<string> timesList =
                                        paScheduleEntry.Type.Recurring.Weekly.MembersWednesday.GetRange(i, Math.Min(3, paScheduleEntry.Type.Recurring.Weekly.MembersWednesday.Count - i));

                                    CheckPoint_Time cpTime = new CheckPoint_Time();
                                    cpTime.Name = paScheduleEntry.Name;
                                    cpTime.Comments = paScheduleEntry.Description;
                                    cpTime.Tags = paScheduleEntry.TagMembers;
                                    cpTime.RecurrencePattern = CheckPoint_Time.RecurrencePatternEnum.Weekly;
                                    cpTime.RecurrenceWeekdays.Add(CheckPoint_Time.Weekdays.Wed);
                                    cpTime.StartNow = true;
                                    cpTime.EndNever = true;

                                    cpTime = SetHourseRanges(cpTime, timesList);

                                    cpTimesList.Add(cpTime);
                                }
                            }
                            if (paScheduleEntry.Type.Recurring.Weekly.MembersThursday != null)
                            {
                                for (int i = 0; i < paScheduleEntry.Type.Recurring.Weekly.MembersThursday.Count; i += 3)
                                {
                                    List<string> timesList =
                                        paScheduleEntry.Type.Recurring.Weekly.MembersThursday.GetRange(i, Math.Min(3, paScheduleEntry.Type.Recurring.Weekly.MembersThursday.Count - i));

                                    CheckPoint_Time cpTime = new CheckPoint_Time();
                                    cpTime.Name = paScheduleEntry.Name;
                                    cpTime.Comments = paScheduleEntry.Description;
                                    cpTime.Tags = paScheduleEntry.TagMembers;
                                    cpTime.RecurrencePattern = CheckPoint_Time.RecurrencePatternEnum.Weekly;
                                    cpTime.RecurrenceWeekdays.Add(CheckPoint_Time.Weekdays.Thu);
                                    cpTime.StartNow = true;
                                    cpTime.EndNever = true;

                                    cpTime = SetHourseRanges(cpTime, timesList);

                                    cpTimesList.Add(cpTime);
                                }
                            }
                            if (paScheduleEntry.Type.Recurring.Weekly.MembersFriday != null)
                            {
                                for (int i = 0; i < paScheduleEntry.Type.Recurring.Weekly.MembersFriday.Count; i += 3)
                                {
                                    List<string> timesList =
                                        paScheduleEntry.Type.Recurring.Weekly.MembersFriday.GetRange(i, Math.Min(3, paScheduleEntry.Type.Recurring.Weekly.MembersFriday.Count - i));

                                    CheckPoint_Time cpTime = new CheckPoint_Time();
                                    cpTime.Name = paScheduleEntry.Name;
                                    cpTime.Comments = paScheduleEntry.Description;
                                    cpTime.Tags = paScheduleEntry.TagMembers;
                                    cpTime.RecurrencePattern = CheckPoint_Time.RecurrencePatternEnum.Weekly;
                                    cpTime.RecurrenceWeekdays.Add(CheckPoint_Time.Weekdays.Fri);
                                    cpTime.StartNow = true;
                                    cpTime.EndNever = true;

                                    cpTime = SetHourseRanges(cpTime, timesList);

                                    cpTimesList.Add(cpTime);
                                }
                            }
                            if (paScheduleEntry.Type.Recurring.Weekly.MembersSaturday != null)
                            {
                                for (int i = 0; i < paScheduleEntry.Type.Recurring.Weekly.MembersSaturday.Count; i += 3)
                                {
                                    List<string> timesList =
                                        paScheduleEntry.Type.Recurring.Weekly.MembersSaturday.GetRange(i, Math.Min(3, paScheduleEntry.Type.Recurring.Weekly.MembersSaturday.Count - i));

                                    CheckPoint_Time cpTime = new CheckPoint_Time();
                                    cpTime.Name = paScheduleEntry.Name;
                                    cpTime.Comments = paScheduleEntry.Description;
                                    cpTime.Tags = paScheduleEntry.TagMembers;
                                    cpTime.RecurrencePattern = CheckPoint_Time.RecurrencePatternEnum.Weekly;
                                    cpTime.RecurrenceWeekdays.Add(CheckPoint_Time.Weekdays.Sat);
                                    cpTime.StartNow = true;
                                    cpTime.EndNever = true;

                                    cpTime = SetHourseRanges(cpTime, timesList);

                                    cpTimesList.Add(cpTime);
                                }
                            }
                            if (paScheduleEntry.Type.Recurring.Weekly.MembersSunday != null)
                            {
                                for (int i = 0; i < paScheduleEntry.Type.Recurring.Weekly.MembersSunday.Count; i += 3)
                                {
                                    List<string> timesList =
                                        paScheduleEntry.Type.Recurring.Weekly.MembersSunday.GetRange(i, Math.Min(3, paScheduleEntry.Type.Recurring.Weekly.MembersSunday.Count - i));

                                    CheckPoint_Time cpTime = new CheckPoint_Time();
                                    cpTime.Name = paScheduleEntry.Name;
                                    cpTime.Comments = paScheduleEntry.Description;
                                    cpTime.Tags = paScheduleEntry.TagMembers;
                                    cpTime.RecurrencePattern = CheckPoint_Time.RecurrencePatternEnum.Weekly;
                                    cpTime.RecurrenceWeekdays.Add(CheckPoint_Time.Weekdays.Sun);
                                    cpTime.StartNow = true;
                                    cpTime.EndNever = true;

                                    cpTime = SetHourseRanges(cpTime, timesList);

                                    cpTimesList.Add(cpTime);
                                }
                            }
                        }
                    }
                    else if (paScheduleEntry.Type.NonRecurring != null)
                    {
                        foreach (string member in paScheduleEntry.Type.NonRecurring.Memebers)
                        {
                            int indexDash = member.IndexOf("-");

                            if (indexDash == -1)
                            {
                                continue;
                            }

                            CheckPoint_Time cpTime = new CheckPoint_Time();
                            cpTime.Name = paScheduleEntry.Name;
                            cpTime.Comments = paScheduleEntry.Description;
                            cpTime.Tags = paScheduleEntry.TagMembers;

                            cpTime.StartNow = false;
                            cpTime.EndNever = false;

                            DateTime dateStart = DateTime.ParseExact(member.Substring(0, indexDash), "yyyy/MM/dd@HH:mm", System.Globalization.CultureInfo.InvariantCulture);
                            cpTime.StartDate = dateStart.ToString("dd-MMM-yyyy", CultureInfo.InvariantCulture);
                            cpTime.StartTime = dateStart.ToString("HH:mm");

                            DateTime dateEnd = DateTime.ParseExact(member.Substring(indexDash + 1), "yyyy/MM/dd@HH:mm", System.Globalization.CultureInfo.InvariantCulture);
                            cpTime.EndDate = dateEnd.ToString("dd-MMM-yyyy", CultureInfo.InvariantCulture);
                            cpTime.EndTime = dateEnd.ToString("HH:mm");

                            cpTimesList.Add(cpTime);
                        }
                    }
                }
            }
            return cpTimesList;
        }

        private CheckPoint_Time SetHourseRanges(CheckPoint_Time cpTime, List<string> timesList)
        {
            for (int j = 0; j < timesList.Count; j++)
            {
                int indexDash = timesList[j].IndexOf("-");
                if (indexDash == -1)
                {
                    continue;
                }
                switch (j)
                {
                    case 0:
                        cpTime.HoursRangesEnabled_1 = true;
                        cpTime.HoursRangesFrom_1 = timesList[j].Substring(0, indexDash);
                        cpTime.HoursRangesTo_1 = timesList[j].Substring(indexDash + 1);
                        break;
                    case 1:
                        cpTime.HoursRangesEnabled_2 = true;
                        cpTime.HoursRangesFrom_2 = timesList[j].Substring(0, indexDash);
                        cpTime.HoursRangesTo_2 = timesList[j].Substring(indexDash + 1);
                        break;
                    case 2:
                        cpTime.HoursRangesEnabled_3 = true;
                        cpTime.HoursRangesFrom_3 = timesList[j].Substring(0, indexDash);
                        cpTime.HoursRangesTo_3 = timesList[j].Substring(indexDash + 1);
                        break;
                }
            }

            return cpTime;
        }

        public CheckPoint_Time InspectCpScheduleName(CheckPoint_Time cpTime)
        {
            string cpTimeName = cpTime.Name;
            if (cpTimeName.Length > 11)
            {
                cpTimeName = cpTimeName.Substring(0, 5) + "_t" + _timeCutterCounter++;
            }

            if (!_timesNamesSet.Add(cpTimeName))
            {
                cpTimeName = cpTimeName.Substring(0, 5) + "_t" + _timeCutterCounter++;
            }

            if (!cpTimeName.Equals(cpTime.Name))
            {
                _warningsList.Add(cpTime.Name + " time object was renamed to " + cpTimeName);
                cpTime.Name = cpTimeName;
            }
            return cpTime;
        }

        #endregion

        #region Convert Services and Services Groups

        public Dictionary<string, string> GetServicesTypes(PA_Objects paObjects, Dictionary<string, string> s_paServicesTypesDict)
        {
            Dictionary<string, string> paServicesTypesDict = null;
            if (s_paServicesTypesDict != null)
                paServicesTypesDict = new Dictionary<string, string>(s_paServicesTypesDict);
            else
                paServicesTypesDict = new Dictionary<string, string>();

            if (paObjects.ServiceEntries != null)
            {
                foreach (PA_ServiceEntry paServiceEntry in paObjects.ServiceEntries)
                {
                    if (paServiceEntry.Protocol != null)
                    {
                        if (paServiceEntry.Protocol.ServiceTcp != null && paServiceEntry.Protocol.ServiceTcp.Port != null)
                        {
                            paServicesTypesDict[paServiceEntry.Name] = SERVICE_TYPE_TCP;
                        }

                        if (paServiceEntry.Protocol.ServiceUdp != null && paServiceEntry.Protocol.ServiceUdp.Port != null)
                        {
                            paServicesTypesDict[paServiceEntry.Name] = SERVICE_TYPE_UDP;
                        }
                    }
                }
            }

            return paServicesTypesDict;
        }

        public Dictionary<string, CheckPointObject> ConvertServices(PA_Objects paObjects, Dictionary<string, CheckPointObject> s_cpServicesDict)
        {
            Dictionary<string, CheckPointObject> cpServicesDict = null;
            if (s_cpServicesDict != null)
                cpServicesDict = new Dictionary<string, CheckPointObject>(s_cpServicesDict);
            else
                cpServicesDict = new Dictionary<string, CheckPointObject>();

            GetPredefinedServices().ForEach(x => cpServicesDict[x.Name] = InspectService(x));

            if (paObjects.ServiceEntries != null)
            {
                foreach (PA_ServiceEntry paServiceEntry in paObjects.ServiceEntries)
                {
                    if (paServiceEntry.Protocol != null)
                    {
                        if (paServiceEntry.Protocol.ServiceTcp != null && paServiceEntry.Protocol.ServiceTcp.Port != null)
                        {
                            string srvName = paServiceEntry.Name;
                            if (!char.IsLetter(paServiceEntry.Name[0]))
                            {
                                srvName = SERVICE_TYPE_TCP + "_" + paServiceEntry.Name;
                                _warningsList.Add(paServiceEntry.Name + " service (TCP) was renamed to " + srvName);
                            }

                            string[] ports = paServiceEntry.Protocol.ServiceTcp.Port.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);
                            string[] sourcePorts = new string[] { "" };
                            if (paServiceEntry.Protocol.ServiceTcp.SourcePort != null)
                            {
                                sourcePorts = paServiceEntry.Protocol.ServiceTcp.SourcePort.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);
                            }

                            if (ports.Length > 1 || sourcePorts.Length > 1)
                            {
                                //create group
                                CheckPoint_ServiceGroup cpServicesGrp = new CheckPoint_ServiceGroup();
                                cpServicesGrp.Name = InspectObjectName(srvName, CP_OBJECT_TYPE_NAME_SERVICE_GROUP);
                                cpServicesGrp.Comments = paServiceEntry.Description;
                                cpServicesGrp.Tags = paServiceEntry.TagMembers;
                                _warningsList.Add(srvName + " tcp service is replaced by service group: " + cpServicesGrp.Name);
                                foreach (string port in ports)
                                {
                                    foreach (string sourcePort in sourcePorts)
                                    {
                                        string srvNameNew = srvName;
                                        srvNameNew += port.Trim().Equals("") ? "" : "_" + port;
                                        srvNameNew += sourcePort.Trim().Equals("") ? "" : "_" + sourcePort;
                                        CheckPoint_TcpService cpTcpService = new CheckPoint_TcpService();
                                        cpTcpService.Name = InspectObjectName(srvNameNew, CP_OBJECT_TYPE_NAME_SERVICE_TCP);
                                        cpTcpService.Comments = paServiceEntry.Description;
                                        cpTcpService.Tags = paServiceEntry.TagMembers;
                                        cpTcpService.Port = AdjustPorts(port);
                                        cpTcpService.SourcePort = AdjustPorts(sourcePort);

                                        CheckPointObject cpServiceChecked = InspectService(cpTcpService);
                                        cpServicesGrp.Members.Add(cpServiceChecked.Name);
                                        cpServicesDict[cpServiceChecked.Name] = cpServiceChecked;
                                    }
                                }
                                cpServicesDict[paServiceEntry.Name] = cpServicesGrp;
                            }
                            else
                            {
                                CheckPoint_TcpService cpTcpService = new CheckPoint_TcpService();
                                cpTcpService.Name = InspectObjectName(srvName, CP_OBJECT_TYPE_NAME_SERVICE_TCP);
                                cpTcpService.Comments = paServiceEntry.Description;
                                cpTcpService.Tags = paServiceEntry.TagMembers;
                                cpTcpService.Port = AdjustPorts(paServiceEntry.Protocol.ServiceTcp.Port);
                                cpTcpService.SourcePort = AdjustPorts(paServiceEntry.Protocol.ServiceTcp.SourcePort);

                                CheckPointObject cpServiceChecked = InspectService(cpTcpService);
                                cpServicesDict[paServiceEntry.Name] = cpServiceChecked;
                            }
                        }

                        if (paServiceEntry.Protocol.ServiceUdp != null && paServiceEntry.Protocol.ServiceUdp.Port != null)
                        {
                            string srvName = paServiceEntry.Name;
                            if (!char.IsLetter(paServiceEntry.Name[0]))
                            {
                                srvName = SERVICE_TYPE_UDP + "_" + paServiceEntry.Name;
                                _warningsList.Add(paServiceEntry.Name + " service (UDP) was renamed to " + srvName);
                            }
                            string[] ports = paServiceEntry.Protocol.ServiceUdp.Port.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);
                            string[] sourcePorts = new string[] { "" };
                            if (paServiceEntry.Protocol.ServiceUdp.SourcePort != null)
                            {
                                sourcePorts = paServiceEntry.Protocol.ServiceUdp.SourcePort.Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);
                            }

                            if (ports.Length > 1 || sourcePorts.Length > 1)
                            {
                                //create group
                                CheckPoint_ServiceGroup cpServicesGrp = new CheckPoint_ServiceGroup();
                                cpServicesGrp.Name = InspectObjectName(srvName, CP_OBJECT_TYPE_NAME_SERVICE_GROUP);
                                cpServicesGrp.Comments = paServiceEntry.Description;
                                cpServicesGrp.Tags = paServiceEntry.TagMembers;
                                _warningsList.Add(srvName + " udp service is replaced by service group: " + cpServicesGrp.Name);
                                foreach (string port in ports)
                                {
                                    foreach (string sourcePort in sourcePorts)
                                    {
                                        string srvNameNew = srvName;
                                        srvNameNew += port.Trim().Equals("") ? "" : "_" + port;
                                        srvNameNew += sourcePort.Trim().Equals("") ? "" : "_" + sourcePort;
                                        CheckPoint_UdpService cpUdpService = new CheckPoint_UdpService();
                                        cpUdpService.Name = InspectObjectName(srvNameNew, CP_OBJECt_TYPE_NAME_SERVICE_UDP);
                                        cpUdpService.Comments = paServiceEntry.Description;
                                        cpUdpService.Tags = paServiceEntry.TagMembers;
                                        cpUdpService.Port = AdjustPorts(port);
                                        cpUdpService.SourcePort = AdjustPorts(sourcePort);

                                        CheckPointObject cpServiceChecked = InspectService(cpUdpService);
                                        cpServicesGrp.Members.Add(cpServiceChecked.Name);
                                        cpServicesDict[cpServiceChecked.Name] = cpServiceChecked;
                                    }
                                }
                                cpServicesDict[paServiceEntry.Name] = cpServicesGrp;
                            }
                            else
                            {
                                CheckPoint_UdpService cpUdpService = new CheckPoint_UdpService();
                                cpUdpService.Name = InspectObjectName(srvName, CP_OBJECt_TYPE_NAME_SERVICE_UDP);
                                cpUdpService.Comments = paServiceEntry.Description;
                                cpUdpService.Tags = paServiceEntry.TagMembers;
                                cpUdpService.Port = AdjustPorts(paServiceEntry.Protocol.ServiceUdp.Port);
                                cpUdpService.SourcePort = AdjustPorts(paServiceEntry.Protocol.ServiceUdp.SourcePort);

                                CheckPointObject cpServiceChecked = InspectService(cpUdpService);
                                cpServicesDict[paServiceEntry.Name] = cpServiceChecked;
                            }
                        }
                    }
                }
            }
            return cpServicesDict;
        }

        public List<CheckPointObject> GetPredefinedServices()
        {
            List<CheckPointObject> predefinedServices = new List<CheckPointObject>();

            CheckPoint_ServiceGroup cpServiceGroupHttp = new CheckPoint_ServiceGroup();
            cpServiceGroupHttp.Name = "service-http";
            cpServiceGroupHttp.Members.Add("http");
            cpServiceGroupHttp.Members.Add("HTTP_proxy");

            predefinedServices.Add(cpServiceGroupHttp);

            CheckPoint_TcpService cpServiceHttps = new CheckPoint_TcpService();
            cpServiceHttps.Name = "service-https";
            cpServiceHttps.Port = "443";

            predefinedServices.Add(cpServiceHttps);

            return predefinedServices;
        }

        private string AdjustPorts(string input)
        {
            if (!string.IsNullOrWhiteSpace(input) && input.StartsWith("0"))
            {
                input = "1" + input.Substring(1);
            }
            return input;
        }

        public CheckPointObject InspectService(CheckPointObject cpService)
        {
            CheckPointObject cpServiceRet = null;

            if (cpService.GetType() == typeof(CheckPoint_TcpService))
            {
                CheckPoint_TcpService cpTcpService = (CheckPoint_TcpService)cpService;
                bool isFound;
                string cpServiceName = _cpObjects.GetKnownServiceName(SERVICE_TYPE_TCP + "_" + cpTcpService.Port, out isFound);

                if (isFound)
                {
                    cpServiceRet = _cpObjects.GetObject(cpServiceName);
                    cpPredefServicesTypes[cpServiceRet.Name] = SERVICE_TYPE_TCP;
                }
                else
                {
                    cpServiceRet = cpTcpService;
                }
            }
            else if (cpService.GetType() == typeof(CheckPoint_UdpService))
            {
                CheckPoint_UdpService cpUdpService = (CheckPoint_UdpService)cpService;
                bool isFound;
                string cpServiceName = _cpObjects.GetKnownServiceName(SERVICE_TYPE_UDP + "_" + cpUdpService.Port, out isFound);

                if (isFound)
                {
                    cpServiceRet = _cpObjects.GetObject(cpServiceName);
                    cpPredefServicesTypes[cpServiceRet.Name] = SERVICE_TYPE_UDP;
                }
                else
                {
                    cpServiceRet = cpUdpService;
                }
            }
            else if (cpService.GetType() == typeof(CheckPoint_ServiceGroup))
            {
                cpServiceRet = cpService;
            }
            else
            {
                _errorsList.Add(cpService.Name + " service is not TCP or UDP or service group.");
            }

            return cpServiceRet;
        }

        public Dictionary<string, CheckPoint_ServiceGroup> ConvertServicesGroups(PA_Objects paObjects, Dictionary<string, CheckPoint_ServiceGroup> s_cpServicesGroupsDict)
        {
            Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsDict = null;
            if (s_cpServicesGroupsDict != null)
                cpServicesGroupsDict = new Dictionary<string, CheckPoint_ServiceGroup>(s_cpServicesGroupsDict);
            else
                cpServicesGroupsDict = new Dictionary<string, CheckPoint_ServiceGroup>();

            if (paObjects.ServiceGroupEntries != null)
            {
                foreach (PA_ServiceGroupEntry paServiceGroupEntry in paObjects.ServiceGroupEntries)
                {
                    CheckPoint_ServiceGroup cpServiceGroup = new CheckPoint_ServiceGroup();
                    cpServiceGroup.Name = InspectObjectName(paServiceGroupEntry.Name, CP_OBJECT_TYPE_NAME_SERVICE_GROUP);
                    cpServiceGroup.Comments = paServiceGroupEntry.Description;
                    cpServiceGroup.Tags = paServiceGroupEntry.TagMembers;
                    cpServiceGroup.Members = paServiceGroupEntry.Members;
                    cpServicesGroupsDict[paServiceGroupEntry.Name] = cpServiceGroup;
                }
            }

            return cpServicesGroupsDict;
        }

        public Dictionary<string, CheckPoint_ServiceGroup> ConvertServicesGroupsWithInspection(PA_Objects paObjects, Dictionary<string, CheckPointObject> cpServicesDict,
                                                                                                Dictionary<string, CheckPoint_ServiceGroup> s_cpServicesGroupsDict)
        {
            Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsCheck = ConvertServicesGroups(paObjects, s_cpServicesGroupsDict);

            Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsResult = new Dictionary<string, CheckPoint_ServiceGroup>();

            InspectServicesGroups(cpServicesDict, cpServicesGroupsCheck, cpServicesGroupsResult);

            return cpServicesGroupsResult;
        }

        public void InspectServicesGroups(Dictionary<string, CheckPointObject> cpServicesDict,
                                          Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsCheck,
                                          Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsResult)
        {
            while (cpServicesGroupsCheck.Count > 0)
            {
                string paSrvGroupName = new List<string>(cpServicesGroupsCheck.Keys)[0];
                CheckPoint_ServiceGroup cpSrvGroupCheck = cpServicesGroupsCheck[paSrvGroupName];

                cpServicesGroupsCheck.Remove(paSrvGroupName);

                InspectServicesGroup(paSrvGroupName, cpSrvGroupCheck, cpServicesDict, cpServicesGroupsCheck, cpServicesGroupsResult);
            }
        }

        public bool InspectServicesGroup(string paSrvGroupName,
                                         CheckPoint_ServiceGroup cpServicesGroup,
                                         Dictionary<string, CheckPointObject> cpServicesDict,
                                         Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsCheck,
                                         Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsResult)
        {
            bool isOk = true;

            CheckPoint_ServiceGroup cpServicesGroupNew = new CheckPoint_ServiceGroup();
            cpServicesGroupNew.Name = cpServicesGroup.Name;
            cpServicesGroupNew.Comments = cpServicesGroup.Comments;
            cpServicesGroupNew.Tags = cpServicesGroup.Tags;

            foreach (string member in cpServicesGroup.Members)
            {
                //group member is in Services List
                if (cpServicesDict.ContainsKey(member))
                {
                    cpServicesGroupNew.Members.Add(cpServicesDict[member].Name);
                    continue;
                }

                //group member is Services Group and converted already
                if (cpServicesGroupsResult.ContainsKey(member))
                {
                    cpServicesGroupNew.Members.Add(cpServicesGroupsResult[member].Name);
                    continue;
                }

                //group member is Services Group and not converted yet
                if (cpServicesGroupsCheck.ContainsKey(member))
                {
                    CheckPoint_ServiceGroup cpSrvGroupNew = cpServicesGroupsCheck[member];
                    cpServicesGroupsCheck.Remove(member);
                    if (InspectServicesGroup(member, cpSrvGroupNew, cpServicesDict, cpServicesGroupsCheck, cpServicesGroupsResult))
                    {
                        cpServicesGroupNew.Members.Add(cpSrvGroupNew.Name);
                        continue;
                    }
                }

                isOk = false;
                _errorsList.Add(cpServicesGroup.Name + " services group can not been converted becuase it contains non-existing member: " + member);
            }

            if (isOk)
            {
                cpServicesGroupsResult[paSrvGroupName] = cpServicesGroupNew;
            }

            return isOk;
        }

        #endregion

        #region Convert Applications, Applications Groups and Applications Filters

        public List<string> GetApplicationsMatchList()
        {
            return new List<string>(File.ReadAllLines(PA_APPLICATIONS_FILE_NAME));
        }

        public Dictionary<string, CheckPoint_ApplicationGroup> ConvertApplicationsGroups(List<PA_ApplicationGroupEntry> paAppsGroupsListCheck,
                                                                                         List<string> appsMatchList,
                                                                                         Dictionary<string, CheckPoint_ApplicationGroup> s_cpAppGroupDict,
                                                                                         List<string> paAppFiltersList,
                                                                                         Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsDict)
        {
            Dictionary<string, CheckPoint_ApplicationGroup> cpAppGroupDict = null;
            if (s_cpAppGroupDict != null)
                cpAppGroupDict = new Dictionary<string, CheckPoint_ApplicationGroup>(s_cpAppGroupDict);
            else
                cpAppGroupDict = new Dictionary<string, CheckPoint_ApplicationGroup>();

            if (paAppsGroupsListCheck != null)
            {
                while (paAppsGroupsListCheck.Count > 0)
                {
                    PA_ApplicationGroupEntry paAppsGroupCheck = paAppsGroupsListCheck[0];
                    paAppsGroupsListCheck.RemoveAt(0);

                    CheckPoint_ApplicationGroup cpAppGroup = new CheckPoint_ApplicationGroup();
                    cpAppGroup.Name = InspectObjectName(GetSafeName(paAppsGroupCheck.Name), CP_OBJECT_TYPE_NAME_APPLICATION_GROUP);

                    CheckPoint_ServiceGroup cpServiceGroup = new CheckPoint_ServiceGroup();
                    cpServiceGroup.Name = InspectObjectName(GetSafeName(paAppsGroupCheck.Name + "-svc"), CP_OBJECT_TYPE_NAME_APPLICATION_GROUP);

                    foreach (string appMember in paAppsGroupCheck.ApplicationGroupMembers)
                    {
                        string matchedLine = appsMatchList.Find(x => x.StartsWith(appMember + ";"));
                        if (!string.IsNullOrEmpty(matchedLine))
                        {
                            string[] matchedArray = matchedLine.Split(';');
                            if (!string.IsNullOrWhiteSpace(matchedArray[1]))
                            {
                                string[] matchedValues = matchedArray[1].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                                foreach (string matchedValue in matchedValues)
                                {
                                    if (!matchedValue.Trim().Equals(""))
                                    {
                                        cpAppGroup.Members.Add(matchedValue.Trim());
                                    }
                                }
                            }
                            else if (!string.IsNullOrWhiteSpace(matchedArray[2]))
                            {
                                string[] matchedValues = matchedArray[2].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                                foreach (string matchedValue in matchedValues)
                                {
                                    if (!matchedValue.Trim().Equals(""))
                                    {
                                        cpServiceGroup.Members.Add(matchedValue.Trim());
                                    }
                                }
                                cpServicesGroupsDict[paAppsGroupCheck.Name + "-svc"] = cpServiceGroup;
                            }
                            else
                            {
                                _warningsList.Add(paAppsGroupCheck.Name + " application group contains non-mapped application: " + appMember);
                            }
                        }
                        else if (cpAppGroupDict.ContainsKey(appMember))
                        {
                            cpAppGroup.Members.Add(cpAppGroupDict[appMember].Name);
                        }
                        else if (paAppFiltersList.Contains(appMember))
                        {
                            _warningsList.Add(paAppsGroupCheck.Name + " application group contains application filter: " + appMember);
                        }
                        else if (paAppsGroupsListCheck.FindIndex(x => x.Name.Equals(appMember)) != -1)
                        {
                            cpAppGroupDict = ConvertApplicationsGroups(paAppsGroupsListCheck, appsMatchList, cpAppGroupDict, paAppFiltersList, cpServicesGroupsDict);
                            if (cpAppGroupDict.ContainsKey(appMember))
                            {
                                cpAppGroup.Members.Add(cpAppGroupDict[appMember].Name);
                            }
                            else
                            {
                                _warningsList.Add(paAppsGroupCheck.Name + " application group contains unknown application: " + appMember);
                            }
                        }
                        else
                        {
                            _warningsList.Add(paAppsGroupCheck.Name + " application group contains unknown application: " + appMember);
                        }
                    }

                    cpAppGroupDict[paAppsGroupCheck.Name] = cpAppGroup;
                }
            }

            return cpAppGroupDict;
        }

        public List<string> GetPAApplicationsFilters(PA_Objects paObjects, List<string> s_cpAppFiltersDict)
        {
            List<string> paAppFiltersList = null;
            if (s_cpAppFiltersDict != null)
                paAppFiltersList = new List<string>(s_cpAppFiltersDict);
            else
                paAppFiltersList = new List<string>();

            if (paObjects.ApplicationFiltersEntries != null)
            {
                foreach (PA_ApplicationFilterEntry paAppFilterEntry in paObjects.ApplicationFiltersEntries)
                {
                    paAppFiltersList.Add(paAppFilterEntry.Name);
                }
            }

            return paAppFiltersList;
        }

        #endregion

        #region Convert Security Policy

        public void ConvertSecurityPolicy(PA_VsysEntry paVsysEntry,
                                          Dictionary<string, CheckPoint_Zone> cpZonesDict,
                                          Dictionary<string, CheckPointObject> cpAddressesDict,
                                          Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsDict,
                                          Dictionary<string, CheckPointObject> cpServicesDict,
                                          Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsDict,
                                          List<string> appsMatchList,
                                          Dictionary<string, CheckPoint_ApplicationGroup> cpAppGroupsDict,
                                          List<string> paAppFiltersList,
                                          Dictionary<string, List<CheckPoint_Time>> cpSchedulesDict,
                                          Dictionary<string, CheckPoint_AccessRole> cpAccessRolesDict)
        {
            Dictionary<string, CheckPoint_Layer> cpLayersDict = new Dictionary<string, CheckPoint_Layer>();
            Dictionary<string, bool> cpGroupRuleAppFiltering = new Dictionary<string, bool>();

            List<PA_SecurityRuleEntry> paRules = new List<PA_SecurityRuleEntry>();
            bool isPolicyPlain = false;

            if (paVsysEntry.Rulebase != null && paVsysEntry.Rulebase.Security != null && paVsysEntry.Rulebase.Security.RulesList != null)
            {
                foreach (PA_SecurityRuleEntry paSecurityRuleEntry in paVsysEntry.Rulebase.Security.RulesList)
                {
                    isPolicyPlain =
                        !isPolicyPlain && (paSecurityRuleEntry.FromList.Contains(PA_ANY_VALUE) || paSecurityRuleEntry.ToList.Contains(PA_ANY_VALUE)) ? true : isPolicyPlain;
                    paRules.Add(paSecurityRuleEntry);
                }
            }

            var cpPackage = new CheckPoint_Package();
            cpPackage.Name = _policyPackageName;
            string pckg_name = _policyPackageName.Replace("_policy", "");
            if (pckg_name.Length > _maxAllowedpackageNameLength)
            {
                _isOverMaxLengthPackageName = true;
                _errorsList.Add("Package " + pckg_name + " has name length more then " + _maxAllowedpackageNameLength + "chars");
            }
            cpPackage.ParentLayer.Name = cpPackage.NameOfAccessLayer;

            foreach (PA_SecurityRuleEntry paSecurityRuleEntry in paRules)
            {
                List<string> messagesE = new List<string>();

                List<CheckPointObject> cpRuleSourceList = new List<CheckPointObject>();
                #region Processing Source of Rule
                if (!paSecurityRuleEntry.SourceList.Contains(PA_ANY_VALUE))
                {
                    foreach (string srcMember in paSecurityRuleEntry.SourceList)
                    {
                        if (cpAddressesDict.ContainsKey(srcMember))
                        {
                            cpRuleSourceList.Add(cpAddressesDict[srcMember]);
                        }
                        else if (cpNetGroupsDict.ContainsKey(srcMember))
                        {
                            cpRuleSourceList.Add(cpNetGroupsDict[srcMember]);
                        }
                        else if (Regex.IsMatch(srcMember, RE_NET_ADDRESS))
                        {
                            if (!srcMember.Contains("/") || srcMember.Contains(NETWORK_NETMASK_WS))
                            {
                                string ipAddress;

                                if (srcMember.Contains("/"))
                                    ipAddress = srcMember.Substring(0, srcMember.IndexOf("/"));
                                else
                                    ipAddress = srcMember.Substring(0);

                                CheckPoint_Host cpHostNew = new CheckPoint_Host();
                                cpHostNew.Name = "Host_" + ipAddress;
                                cpHostNew.IpAddress = ipAddress;

                                cpAddressesDict[srcMember] = cpHostNew;

                                cpRuleSourceList.Add(cpHostNew);
                            }
                            else
                            {
                                IPNetwork ipNetwork;
                                if (IPNetwork.TryParse(srcMember, out ipNetwork))
                                {
                                    string ipAddress = srcMember.Substring(0, srcMember.IndexOf("/"));

                                    CheckPoint_Network cpNetworkNew = new CheckPoint_Network();
                                    cpNetworkNew.Name = "Net_" + ipAddress;
                                    cpNetworkNew.Subnet = ipAddress;
                                    cpNetworkNew.Netmask = ipNetwork.Netmask.ToString();

                                    cpAddressesDict[srcMember] = cpNetworkNew;

                                    cpRuleSourceList.Add(cpNetworkNew);
                                }
                            }
                        }
                        else
                        {
                            messagesE.Add(paSecurityRuleEntry.Name +
                                            " security rule is not converted because source object is not defined or converted: " +
                                            srcMember);
                        }
                    }
                }
                else
                {
                    if (isPolicyPlain && !paSecurityRuleEntry.FromList.Contains(PA_ANY_VALUE)
                        && !(ConvertUserConf && paSecurityRuleEntry.SourceUserList != null && !paSecurityRuleEntry.SourceUserList.Contains(PA_ANY_VALUE)))
                    {
                        paSecurityRuleEntry.FromList.ForEach(fromObj =>
                        {
                            if (cpZonesDict.ContainsKey(fromObj))
                            {
                                CheckPoint_Zone cpZone = cpZonesDict[fromObj];
                                cpRuleSourceList.Add(cpZone);
                                AddCheckPointObject(cpZone);
                            }
                        });
                    }
                }
                #endregion

                List<CheckPointObject> cpRuleDestinationList = new List<CheckPointObject>();
                #region Processing Destination of Rule
                if (!paSecurityRuleEntry.DestinationList.Contains(PA_ANY_VALUE))
                {
                    foreach (string dstMember in paSecurityRuleEntry.DestinationList)
                    {
                        if (cpAddressesDict.ContainsKey(dstMember))
                        {
                            cpRuleDestinationList.Add(cpAddressesDict[dstMember]);
                        }
                        else if (cpNetGroupsDict.ContainsKey(dstMember))
                        {
                            cpRuleDestinationList.Add(cpNetGroupsDict[dstMember]);
                        }
                        else if (Regex.IsMatch(dstMember, RE_NET_ADDRESS))
                        {
                            if (!dstMember.Contains("/") || dstMember.Contains(NETWORK_NETMASK_WS))
                            {
                                string ipAddress;

                                if (dstMember.Contains("/"))
                                    ipAddress = dstMember.Substring(0, dstMember.IndexOf("/"));
                                else
                                    ipAddress = dstMember.Substring(0);

                                CheckPoint_Host cpHostNew = new CheckPoint_Host();
                                cpHostNew.Name = "Host_" + ipAddress;
                                cpHostNew.IpAddress = ipAddress;

                                cpAddressesDict[dstMember] = cpHostNew;

                                cpRuleDestinationList.Add(cpHostNew);
                            }
                            else
                            {
                                IPNetwork ipNetwork;
                                if (IPNetwork.TryParse(dstMember, out ipNetwork))
                                {
                                    string ipAddress = dstMember.Substring(0, dstMember.IndexOf("/"));

                                    CheckPoint_Network cpNetworkNew = new CheckPoint_Network();
                                    cpNetworkNew.Name = "Net_" + ipAddress;
                                    cpNetworkNew.Subnet = ipAddress;
                                    cpNetworkNew.Netmask = ipNetwork.Netmask.ToString();

                                    cpAddressesDict[dstMember] = cpNetworkNew;

                                    cpRuleDestinationList.Add(cpNetworkNew);
                                }
                            }
                        }
                        else
                        {
                            messagesE.Add(paSecurityRuleEntry.Name +
                                            " security rule is not converted because destination object is not defined or converted: " +
                                            dstMember);
                        }
                    }
                }
                else
                {
                    if (isPolicyPlain && !paSecurityRuleEntry.ToList.Contains(PA_ANY_VALUE))
                    {
                        paSecurityRuleEntry.ToList.ForEach(toObj =>
                        {
                            if (cpZonesDict.ContainsKey(toObj))
                            {
                                CheckPoint_Zone cpZone = cpZonesDict[toObj];
                                cpRuleDestinationList.Add(cpZone);
                                AddCheckPointObject(cpZone);
                            }
                        });
                    }
                }
                #endregion

                List<CheckPointObject> cpRuleServiceList = new List<CheckPointObject>();
                List<CheckPointObject> cpRuleApplilcationList = new List<CheckPointObject>();
                bool applicationsFiltering = false;
                #region Processing Services, Groups of Services and Applications of Rule
                if ((paSecurityRuleEntry.ApplicationList.Contains(PA_ANY_VALUE))) // services only -> processing services
                {
                    if (!(paSecurityRuleEntry.ServiceList.Contains(PA_APPLICATION_DEFAULT) || paSecurityRuleEntry.ServiceList.Contains(PA_ANY_VALUE)))
                    {
                        foreach (string paServiceName in paSecurityRuleEntry.ServiceList)
                        {
                            CheckPointObject cpServiceObj = null;
                            if (cpServicesDict.ContainsKey(paServiceName))
                            {
                                cpServiceObj = cpServicesDict[paServiceName];
                            }
                            else if (cpServicesGroupsDict.ContainsKey(paServiceName))
                            {
                                cpServiceObj = cpServicesGroupsDict[paServiceName];
                            }

                            if (cpServiceObj != null)
                            {
                                cpRuleServiceList.Add(cpServiceObj);
                            }
                            else
                            {
                                messagesE.Add(paSecurityRuleEntry.Name +
                                                " security rule is not converted because service object is not defined or converted: " +
                                                paServiceName);
                            }
                        }
                    }
                }
                else //application and services or applications only -> processing applications
                {
                    applicationsFiltering = true;
                    foreach (string paAppName in paSecurityRuleEntry.ApplicationList)
                    {
                        if (cpServicesGroupsDict.ContainsKey(paAppName + "-svc"))//to add mapped PA services from CP application group entry
                        {
                            cpRuleServiceList.Add(cpServicesGroupsDict[paAppName + "-svc"]);
                        }
                        if (cpAppGroupsDict.ContainsKey(paAppName))
                        {
                            cpRuleApplilcationList.Add(cpAppGroupsDict[paAppName]);
                        }
                        else if (paAppFiltersList.Contains(paAppName))
                        {
                            _warningsList.Add(paSecurityRuleEntry.Name + " security rule contains application filter: " + paAppName);
                        }
                        else
                        {
                            string matchedLine = appsMatchList.Find(x => x.StartsWith(paAppName + ";"));
                            if (!string.IsNullOrEmpty(matchedLine))
                            {
                                string[] matchedArray = matchedLine.Split(';');
                                if (!string.IsNullOrWhiteSpace(matchedArray[1]))
                                {
                                    string[] matchedValues = matchedArray[1].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                                    foreach (string matchedValue in matchedValues)
                                    {
                                        if (!matchedValue.Trim().Equals(""))
                                        {
                                            cpRuleApplilcationList.Add(new CheckPoint_PredifinedObject { Name = matchedValue.Trim() });
                                        }
                                    }
                                }
                                else if (!string.IsNullOrWhiteSpace(matchedArray[2]))
                                {
                                    string[] matchedValues = matchedArray[2].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                                    foreach (string matchedValue in matchedValues)
                                    {
                                        if (!matchedValue.Trim().Equals(""))
                                        {
                                            cpRuleApplilcationList.Add(new CheckPoint_PredifinedObject { Name = matchedValue.Trim() });
                                        }
                                    }
                                }
                                else
                                    _warningsList.Add(paSecurityRuleEntry.Name + " security rule contains non-mapped application: " + paAppName);
                            }
                            else
                            {
                                _warningsList.Add(paSecurityRuleEntry.Name + " security rule contains unknown application: " + paAppName);
                            }
                        }
                    }

                    if (!(paSecurityRuleEntry.ServiceList.Contains(PA_APPLICATION_DEFAULT) || paSecurityRuleEntry.ServiceList.Contains(PA_ANY_VALUE)))
                    {
                        foreach (string paServiceName in paSecurityRuleEntry.ServiceList)
                        {
                            _warningsList.Add(paSecurityRuleEntry.Name + " access rule contains service which was not converted: " + paServiceName);
                        }
                    }
                }
                if (!paSecurityRuleEntry.CategoryList.Contains(PA_ANY_VALUE))
                {
                    foreach (string paCategoryName in paSecurityRuleEntry.CategoryList)
                    {
                        _warningsList.Add(paSecurityRuleEntry.Name + " access rule contains URL-category which was not converted: " + paCategoryName);
                    }
                }
                #endregion

                List<CheckPoint_AccessRole> cpAccessRolesList = new List<CheckPoint_AccessRole>();
                #region Processing Users Roles
                if (ConvertUserConf && paSecurityRuleEntry.SourceUserList != null && !paSecurityRuleEntry.SourceUserList.Contains(PA_ANY_VALUE))
                {
                    CheckPoint_AccessRole cpAccessRole = new CheckPoint_AccessRole();
                    cpAccessRole.Name = InspectObjectName("AR_" + paSecurityRuleEntry.Name, CP_OBJECT_TYPE_NAME_ACCESS_ROLE);

                    foreach (string sourceUser in paSecurityRuleEntry.SourceUserList)
                    {
                        if (sourceUser.Contains(","))
                        {
                            List<string> values = new List<string>();
                            sourceUser.Split(new string[] { "," }, StringSplitOptions.None).ToList().ForEach(x => values.Add(x.Trim().Substring(x.IndexOf("=") + 1)));
                            AccessRoleUser arUser = new AccessRoleUser();
                            arUser.Name = values[0];
                            arUser.BaseDn = sourceUser;

                            cpAccessRole.Users.Add(arUser);
                        }
                        else if (sourceUser.Contains("\\"))
                        {
                            AccessRoleUser arUser = new AccessRoleUser();
                            arUser.Name = sourceUser.Substring(sourceUser.IndexOf("\\") + 1);

                            cpAccessRole.Users.Add(arUser);
                        }
                        else
                        {
                            AccessRoleUser arUser = new AccessRoleUser();
                            arUser.Name = sourceUser;

                            cpAccessRole.Users.Add(arUser);
                        }
                    }

                    if (paSecurityRuleEntry.SourceList != null && !paSecurityRuleEntry.SourceList.Contains(PA_ANY_VALUE))
                    {
                        cpRuleSourceList.ForEach(x => cpAccessRole.Networks.Add(x.Name));
                        cpRuleSourceList.Clear();
                    }

                    cpAccessRolesDict.Add(cpAccessRole.Name, cpAccessRole);
                    cpAccessRolesList.Add(cpAccessRole);
                }
                #endregion

                CheckPoint_Rule.ActionType cpRuleActionType = (paSecurityRuleEntry.Action.Equals("allow")) ?
                                                                CheckPoint_Rule.ActionType.Accept : CheckPoint_Rule.ActionType.Drop;

                List<CheckPointObject> cpRuleTimeList = new List<CheckPointObject>();
                #region Processing Schedule of Rule
                if (paSecurityRuleEntry.Schedule != null && cpSchedulesDict.ContainsKey(paSecurityRuleEntry.Schedule))
                {
                    cpRuleTimeList.AddRange(cpSchedulesDict[paSecurityRuleEntry.Schedule]);
                }
                #endregion

                CheckPoint_Rule.TrackTypes cpRuleTrack = ("no".Equals(paSecurityRuleEntry.LogStart) && "no".Equals(paSecurityRuleEntry.LogEnd)) ?
                                                            CheckPoint_Rule.TrackTypes.None : CheckPoint_Rule.TrackTypes.Log;

                bool cpRuleEnabled = !("yes".Equals(paSecurityRuleEntry.Disabled));

                bool cpRuleNegateSource = "yes".Equals(paSecurityRuleEntry.NegateSource);
                bool cpRuleNegateDestination = "yes".Equals(paSecurityRuleEntry.NegateDestination);

                if (messagesE.Count == 0)
                {
                    if (isPolicyPlain)
                    {
                        CheckPoint_RuleWithApplication cpRule = CreateCpRule(paSecurityRuleEntry,
                                                                             cpRuleSourceList,
                                                                             cpRuleDestinationList,
                                                                             cpRuleServiceList,
                                                                             cpRuleApplilcationList,
                                                                             cpRuleActionType,
                                                                             cpRuleTimeList,
                                                                             cpRuleTrack,
                                                                             cpRuleEnabled,
                                                                             cpRuleNegateSource,
                                                                             cpRuleNegateDestination,
                                                                             cpAddressesDict,
                                                                             cpNetGroupsDict,
                                                                             cpServicesDict,
                                                                             cpServicesGroupsDict,
                                                                             cpAccessRolesList,
                                                                             cpAppGroupsDict);
                        cpRule.Layer = cpPackage.ParentLayer.Name;

                        cpPackage.ParentLayer.Rules.Add(cpRule);
                        _rulesInConvertedPackage += 1;

                        if (applicationsFiltering)
                        {
                            cpPackage.ParentLayer.ApplicationsAndUrlFiltering = true;
                        }
                        string ruleCmd = cpRule.ToCLIScript();
                    }
                    else
                    {
                        List<string> zonesNamesFromList = paSecurityRuleEntry.FromList;

                        List<string> zonesNamesToList = paSecurityRuleEntry.ToList;

                        foreach (string zoneNameFrom in zonesNamesFromList)
                        {
                            foreach (string zoneNameTo in zonesNamesToList)
                            {
                                if (PA_INTRAZONE_NAME.Equals(paSecurityRuleEntry.RuleType) && zoneNameFrom.Equals(zoneNameTo))
                                {
                                    continue;
                                }
                                if (PA_INTRAZONE_NAME.Equals(paSecurityRuleEntry.RuleType) && !zoneNameFrom.Equals(zoneNameTo))
                                {
                                    continue;
                                }

                                CheckPoint_RuleWithApplication cpRule = CreateCpRule(paSecurityRuleEntry,
                                                                                     cpRuleSourceList,
                                                                                     cpRuleDestinationList,
                                                                                     cpRuleServiceList,
                                                                                     cpRuleApplilcationList,
                                                                                     cpRuleActionType,
                                                                                     cpRuleTimeList,
                                                                                     cpRuleTrack,
                                                                                     cpRuleEnabled,
                                                                                     cpRuleNegateSource,
                                                                                     cpRuleNegateDestination,
                                                                                     cpAddressesDict,
                                                                                     cpNetGroupsDict,
                                                                                     cpServicesDict,
                                                                                     cpServicesGroupsDict,
                                                                                     cpAccessRolesList,
                                                                                     cpAppGroupsDict);

                                string keyLayerName = zoneNameFrom + "_TK_" + zoneNameTo;
                                string cpGroupRuleName = zoneNameFrom + "__" + zoneNameTo;

                                CheckPoint_Layer cpLayer = null;
                                if (!cpLayersDict.TryGetValue(keyLayerName, out cpLayer))
                                {
                                    CheckPoint_Zone cpZoneSrc = cpZonesDict[zoneNameFrom];
                                    CheckPoint_Zone cpZoneDst = cpZonesDict[zoneNameTo];

                                    AddCheckPointObject(cpZoneSrc);
                                    AddCheckPointObject(cpZoneDst);

                                    cpLayer = new CheckPoint_Layer();
                                    cpLayer.Name = keyLayerName;
                                    cpLayer.ApplicationsAndUrlFiltering = false;

                                    cpPackage.SubPolicies.Add(cpLayer);
                                    validatePackage(cpPackage);

                                    CheckPoint_Rule cpGroupRule = new CheckPoint_Rule();
                                    cpGroupRule.Name = cpGroupRuleName;
                                    cpGroupRule.Source.Add(cpZoneSrc);
                                    cpGroupRule.Destination.Add(cpZoneDst);
                                    cpGroupRule.Layer = cpPackage.NameOfAccessLayer;
                                    cpGroupRule.Action = CheckPoint_Rule.ActionType.SubPolicy;
                                    cpGroupRule.SubPolicyName = cpLayer.Name;

                                    cpPackage.ParentLayer.Rules.Add(cpGroupRule);
                                    _rulesInConvertedPackage += 1;

                                    cpGroupRuleAppFiltering[cpGroupRuleName] = false;
                                }

                                cpRule.Layer = cpLayer.Name;

                                cpLayer.Rules.Add(cpRule);
                                _rulesInConvertedPackage += 1;
                                cpLayersDict[keyLayerName] = cpLayer;

                                //---
                                if (applicationsFiltering)
                                {
                                    cpLayer.ApplicationsAndUrlFiltering = true;
                                    cpGroupRuleAppFiltering[cpGroupRuleName] = true;
                                }
                            }
                        }
                    }
                }
                else
                {
                    _errorsList.AddRange(messagesE);
                }
            }

            cpPackage.ParentLayer.Rules.ForEach(x =>
            {
                if (cpGroupRuleAppFiltering.ContainsKey(x.Name) && cpGroupRuleAppFiltering[x.Name])
                    x.ConversionComments = "Applications and URL filtering is enabled for layer.";
            });

            foreach (CheckPoint_Layer cpLayer in cpLayersDict.Values)
            {
                CheckPoint_Rule cpRuleCU = new CheckPoint_Rule();
                cpRuleCU.Name = "Sub-Policy Cleanup";
                cpRuleCU.Layer = cpLayer.Name;
                cpLayer.Rules.Add(cpRuleCU);
            };

            // Do NOT create a cleanup rule if it already exists
            bool createCleanupRule = true;
            if (cpPackage.ParentLayer.Rules.Count > 0)
            {
                var lastRule = cpPackage.ParentLayer.Rules[cpPackage.ParentLayer.Rules.Count - 1];
                createCleanupRule = !lastRule.IsCleanupRule();
            }

            if (createCleanupRule)
            {
                var cpRuleFake = new CheckPoint_Rule();
                cpRuleFake.Name = "Cleanup rule"; //the last rule which is created by default by CheckPoint script importer. It is for report only.
                cpPackage.ParentLayer.Rules.Add(cpRuleFake);
            }

            AddCheckPointObject(cpPackage);
        }

        private CheckPoint_RuleWithApplication CreateCpRule(PA_SecurityRuleEntry paSecurityRuleEntry,
                                                            List<CheckPointObject> cpRuleSourceList,
                                                            List<CheckPointObject> cpRuleDestinationList,
                                                            List<CheckPointObject> cpRuleServiceList,
                                                            List<CheckPointObject> cpRuleApplilcationList,
                                                            CheckPoint_Rule.ActionType cpRuleActionType,
                                                            List<CheckPointObject> cpRuleTimeList,
                                                            CheckPoint_Rule.TrackTypes cpRuleTrack,
                                                            bool cpRuleEnabled,
                                                            bool cpRuleNegateSource,
                                                            bool cpRuleNegateDestination,
                                                            Dictionary<string, CheckPointObject> cpAddressesDict,
                                                            Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsDict,
                                                            Dictionary<string, CheckPointObject> cpServicesDict,
                                                            Dictionary<string, CheckPoint_ServiceGroup> cpSrvGroupsDict,
                                                            List<CheckPoint_AccessRole> cpAccessRolesList,
                                                            Dictionary<string, CheckPoint_ApplicationGroup> cpAppGroupsDict)
        {
            CheckPoint_RuleWithApplication cpRule = new CheckPoint_RuleWithApplication();
            cpRule.Name = paSecurityRuleEntry.Name;
            cpRule.Comments = string.IsNullOrWhiteSpace(paSecurityRuleEntry.Description) ? "" : (" " + paSecurityRuleEntry.Description);
            cpRule.Tags = paSecurityRuleEntry.TagMembers;
            cpRule.Source.AddRange(cpRuleSourceList);
            cpRule.Destination.AddRange(cpRuleDestinationList);
            cpRule.Service.AddRange(cpRuleServiceList);
            cpRule.Application.AddRange(cpRuleApplilcationList);
            cpRule.Action = cpRuleActionType;
            cpRule.Time.AddRange(cpRuleTimeList);
            cpRule.Track = cpRuleTrack;
            cpRule.Enabled = cpRuleEnabled;
            cpRule.SourceNegated = cpRuleNegateSource;
            cpRule.DestinationNegated = cpRuleNegateDestination;
            cpRule.ConversionComments = "Matched rule: " + paSecurityRuleEntry.Name;

            cpRule.Source.ForEach(x =>
            {
                if (x.GetType() == typeof(CheckPoint_NetworkGroup))
                {
                    AddCpNetworkGroup((CheckPoint_NetworkGroup)x, cpAddressesDict, cpNetGroupsDict);
                }
                else if (x.GetType() != typeof(CheckPoint_PredifinedObject))
                {
                    AddCheckPointObject(x);
                }
            });
            cpRule.Destination.ForEach(x =>
            {
                if (x.GetType() == typeof(CheckPoint_NetworkGroup))
                {
                    AddCpNetworkGroup((CheckPoint_NetworkGroup)x, cpAddressesDict, cpNetGroupsDict);
                }
                else if (x.GetType() != typeof(CheckPoint_PredifinedObject))
                {
                    AddCheckPointObject(x);
                }
            });
            cpRule.Service.ForEach(x =>
            {
                if (x.GetType() == typeof(CheckPoint_ServiceGroup))
                {
                    AddCpServiceGroup((CheckPoint_ServiceGroup)x, cpServicesDict, cpSrvGroupsDict);
                }
                else if (x.GetType() != typeof(CheckPoint_PredifinedObject))
                {
                    AddCheckPointObject(x);
                }
            });
            cpRule.Time.ForEach(x => AddCheckPointObject(x));

            if (ConvertUserConf && cpAccessRolesList.Count > 0)
            {
                if (cpRule.Source.Contains(_cpObjects.GetObject(CheckPointObject.Any)))
                    cpRule.Source.Clear();
                cpRule.Source.AddRange(cpAccessRolesList);
            }
            cpRule.Application.ForEach(x =>
            {
                if (x.GetType() == typeof(CheckPoint_ApplicationGroup))
                {
                    AddCpApplicationGroup((CheckPoint_ApplicationGroup)x, cpAppGroupsDict);
                }
                else if (x.GetType() != typeof(CheckPoint_PredifinedObject))
                {
                    AddCheckPointObject(x);
                }
            });

            return cpRule;
        }

        #endregion

        #region Convert Nat Policy

        public void ConvertNatPolicy(PA_VsysEntry paVsysEntry,
                                     Dictionary<string, CheckPointObject> cpAddressesDict,
                                     Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsDict,
                                     Dictionary<string, CheckPointObject> cpServicesDict,
                                     Dictionary<string, string> paServicesTypesDict,
                                     Dictionary<string, CheckPoint_ServiceGroup> cpServicesGroupsDict,
                                     Dictionary<string, CheckPoint_ServiceGroup> cpServicesFromAppsGroupDict)
        {
            int counterNatRules = -1;

            if (paVsysEntry.Rulebase != null && paVsysEntry.Rulebase.Nat != null && paVsysEntry.Rulebase.Nat.RulesList != null)
            {
                foreach (PA_NatRuleEntry paNatRuleEntry in paVsysEntry.Rulebase.Nat.RulesList)
                {
                    List<CheckPointObject> cpSourceTranslationList = new List<CheckPointObject>();
                    bool isSourceTranslationExists = true;
                    bool isNatRuleStatic = false;
                    bool isNatRuleBiDirectional = false;
                    bool isDestinationTranslationNone = false;

                    if ("nptv6".Equals(paNatRuleEntry.NatType?.ToLower()))
                    {
                        _warningsList.Add(String.Format("Unsupported nat-type '{1}' for NAT rule '{0}'.", paNatRuleEntry.Name, paNatRuleEntry.NatType));
                        continue;
                    }

                    #region converting source translation to list; checking if NAT Rule Method should be Static
                    if (paNatRuleEntry.SourceTranslation != null)
                    {
                        if (paNatRuleEntry.SourceTranslation.StaticIp != null)
                        {
                            if (!string.IsNullOrWhiteSpace(paNatRuleEntry.SourceTranslation.StaticIp.TranslatedAddress))
                            {
                                if (cpAddressesDict.ContainsKey(paNatRuleEntry.SourceTranslation.StaticIp.TranslatedAddress))
                                {
                                    cpSourceTranslationList.Add(cpAddressesDict[paNatRuleEntry.SourceTranslation.StaticIp.TranslatedAddress]);
                                    isNatRuleStatic = true;
                                    if (!string.IsNullOrWhiteSpace(paNatRuleEntry.SourceTranslation.StaticIp.IsBiDirectional)
                                        && paNatRuleEntry.SourceTranslation.StaticIp.IsBiDirectional.ToLower().Equals("yes"))
                                    {
                                        isNatRuleBiDirectional = true;
                                    }
                                }
                            }
                        }
                        else if (paNatRuleEntry.SourceTranslation.DynamicIp != null)
                        {
                            if (paNatRuleEntry.SourceTranslation.DynamicIp.TranslatedAddresses != null)
                            {
                                foreach (string translatedAddress in paNatRuleEntry.SourceTranslation.DynamicIp.TranslatedAddresses)
                                {
                                    if (cpAddressesDict.ContainsKey(translatedAddress))
                                    {
                                        cpSourceTranslationList.Add(cpAddressesDict[translatedAddress]);
                                    }
                                    else if (cpNetGroupsDict.ContainsKey(translatedAddress))
                                    {
                                        cpSourceTranslationList.Add(cpNetGroupsDict[translatedAddress]);
                                    }
                                }
                            }
                        }
                        else if (paNatRuleEntry.SourceTranslation.DynamicIpAndPort != null)
                        {
                            if (paNatRuleEntry.SourceTranslation.DynamicIpAndPort.TranslatedAddresses != null &&
                                paNatRuleEntry.SourceTranslation.DynamicIpAndPort.TranslatedAddresses.Count > 0)
                            {
                                foreach (string translatedAddress in paNatRuleEntry.SourceTranslation.DynamicIpAndPort.TranslatedAddresses)
                                {
                                    if (cpAddressesDict.ContainsKey(translatedAddress))
                                    {
                                        cpSourceTranslationList.Add(cpAddressesDict[translatedAddress]);
                                    }
                                    else if (cpNetGroupsDict.ContainsKey(translatedAddress))
                                    {
                                        cpSourceTranslationList.Add(cpNetGroupsDict[translatedAddress]);
                                    }
                                    else if (Regex.IsMatch(translatedAddress, RE_NET_ADDRESS)) //create address or network object for translated address if they were not created before
                                    {
                                        if (!translatedAddress.Contains("/") || translatedAddress.Contains(NETWORK_NETMASK_WS))
                                        {
                                            string ipAddress;

                                            if (translatedAddress.Contains("/"))
                                                ipAddress = translatedAddress.Substring(0, translatedAddress.IndexOf("/"));
                                            else
                                                ipAddress = translatedAddress.Substring(0);

                                            CheckPoint_Host cpHostNew = new CheckPoint_Host();
                                            cpHostNew.Name = "Host_" + ipAddress;
                                            cpHostNew.IpAddress = ipAddress;

                                            cpAddressesDict[translatedAddress] = cpHostNew;
                                            cpSourceTranslationList.Add(cpHostNew);
                                            _warningsList.Add(cpHostNew.Name + " host object is created for NAT rule.");
                                        }
                                        else
                                        {
                                            IPNetwork ipNetwork;
                                            if (IPNetwork.TryParse(translatedAddress, out ipNetwork))
                                            {
                                                string ipAddress = translatedAddress.Substring(0, translatedAddress.IndexOf("/"));

                                                CheckPoint_Network cpNetworkNew = new CheckPoint_Network();
                                                cpNetworkNew.Name = "Net_" + ipAddress;
                                                cpNetworkNew.Subnet = ipAddress;
                                                cpNetworkNew.Netmask = ipNetwork.Netmask.ToString();
                                                cpAddressesDict[translatedAddress] = cpNetworkNew;
                                                cpSourceTranslationList.Add(cpNetworkNew);
                                                _warningsList.Add(cpNetworkNew.Name + " network object is created for NAT rule.");
                                            }
                                        }
                                    }
                                }
                            }
                            else if (paNatRuleEntry.SourceTranslation.DynamicIpAndPort.InterfaceAddress != null)
                            {
                                string intfAddrIP = paNatRuleEntry.SourceTranslation.DynamicIpAndPort.InterfaceAddress.Ip;
                                if (!string.IsNullOrWhiteSpace(intfAddrIP))
                                {
                                    if (cpAddressesDict.ContainsKey(intfAddrIP))
                                    {
                                        cpSourceTranslationList.Add(cpAddressesDict[intfAddrIP]);
                                    }
                                    else
                                    {
                                        if (intfAddrIP.Contains("/"))
                                        {
                                            intfAddrIP = intfAddrIP.Substring(0, intfAddrIP.IndexOf("/"));
                                        }

                                        IPAddress ipAddress;
                                        if (IPAddress.TryParse(intfAddrIP, out ipAddress))
                                        {
                                            CheckPoint_Host cpHost = new CheckPoint_Host();
                                            cpHost.Name = "NatIntf_" + intfAddrIP;
                                            cpHost.IpAddress = intfAddrIP;
                                            cpSourceTranslationList.Add(cpHost);

                                            _warningsList.Add(cpHost.Name + " host object is created for NAT rule.");
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (cpSourceTranslationList.Count == 0)
                    {
                        isSourceTranslationExists = false;
                        // createing Dummy Object because we need to have at least 1 element in cpSourceTranslationList for creating NAT rule
                        cpSourceTranslationList.Add(new CheckPoint_PredifinedObject { Name = "DUMMY_OBJECT" });
                    }
                    #endregion

                    if (paNatRuleEntry.DestinationTranslation == null)
                    {
                        isDestinationTranslationNone = true;
                    }

                    foreach (string source in paNatRuleEntry.SourceList)
                    {
                        foreach (string destination in paNatRuleEntry.DestinationList)
                        {
                            foreach (CheckPointObject cpSourceTranslation in cpSourceTranslationList)
                            {
                                CheckPoint_NAT_Rule cpNatRule = new CheckPoint_NAT_Rule();

                                List<string> messagesW = new List<string>();
                                List<string> messagesE = new List<string>();

                                CheckPointObject extraNatServiceSourced = null;
                                CheckPointObject extraNatServiceTranslated = null;

                                cpNatRule.Name = GetSafeName(paNatRuleEntry.Name + ((++counterNatRules > 0) ? "_" + counterNatRules : ""));
                                cpNatRule.Comments = "Matched rule name: " + paNatRuleEntry.Name + ". ";

                                cpNatRule.Comments += paNatRuleEntry.Description;
                                cpNatRule.Tags = paNatRuleEntry.TagMembers;
                                cpNatRule.Enabled = !("yes".Equals(paNatRuleEntry.Disabled));
                                cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Hide;

                                #region adding original source
                                if (!PA_ANY_VALUE.Equals(source))
                                {
                                    if (cpAddressesDict.ContainsKey(source))
                                    {
                                        cpNatRule.Source = cpAddressesDict[source];
                                    }
                                    else if (cpNetGroupsDict.ContainsKey(source))
                                    {
                                        cpNatRule.Source = cpNetGroupsDict[source];
                                    }
                                    else if (Regex.IsMatch(source, RE_NET_ADDRESS))
                                    {
                                        if (!source.Contains("/") || source.Contains(NETWORK_NETMASK_WS))
                                        {
                                            string ipAddress;

                                            if (source.Contains("/"))
                                                ipAddress = source.Substring(0, source.IndexOf("/"));
                                            else
                                                ipAddress = source.Substring(0);

                                            CheckPoint_Host cpHostNew = new CheckPoint_Host();
                                            cpHostNew.Name = "Host_" + ipAddress;
                                            cpHostNew.IpAddress = ipAddress;

                                            cpAddressesDict[source] = cpHostNew;

                                            cpNatRule.Source = cpHostNew;
                                        }
                                        else
                                        {
                                            IPNetwork ipNetwork;
                                            if (IPNetwork.TryParse(source, out ipNetwork))
                                            {
                                                string ipAddress = source.Substring(0, source.IndexOf("/"));

                                                CheckPoint_Network cpNetworkNew = new CheckPoint_Network();
                                                cpNetworkNew.Name = "Net_" + ipAddress;
                                                cpNetworkNew.Subnet = ipAddress;
                                                cpNetworkNew.Netmask = ipNetwork.Netmask.ToString();

                                                cpAddressesDict[source] = cpNetworkNew;

                                                cpNatRule.Source = cpNetworkNew;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        messagesE.Add(paNatRuleEntry.Name +
                                                        " NAT rule is not converted because source object is not defined or converted: " +
                                                        source);
                                    }
                                }
                                #endregion

                                #region adding original destination
                                if (!PA_ANY_VALUE.Equals(destination))
                                {
                                    if (cpAddressesDict.ContainsKey(destination))
                                    {
                                        cpNatRule.Destination = cpAddressesDict[destination];
                                    }
                                    else if (cpNetGroupsDict.ContainsKey(destination))
                                    {
                                        cpNatRule.Destination = cpNetGroupsDict[destination];
                                    }
                                    else if (Regex.IsMatch(destination, RE_NET_ADDRESS))
                                    {
                                        if (!destination.Contains("/") || destination.Contains(NETWORK_NETMASK_WS))
                                        {
                                            string ipAddress;

                                            if (destination.Contains("/"))
                                                ipAddress = destination.Substring(0, destination.IndexOf("/"));
                                            else
                                                ipAddress = destination.Substring(0);

                                            CheckPoint_Host cpHostNew = new CheckPoint_Host();
                                            cpHostNew.Name = "Host_" + ipAddress;
                                            cpHostNew.IpAddress = ipAddress;

                                            cpAddressesDict[destination] = cpHostNew;

                                            cpNatRule.Destination = cpHostNew;
                                        }
                                        else
                                        {
                                            IPNetwork ipNetwork;
                                            if (IPNetwork.TryParse(destination, out ipNetwork))
                                            {
                                                string ipAddress = destination.Substring(0, destination.IndexOf("/"));

                                                CheckPoint_Network cpNetworkNew = new CheckPoint_Network();
                                                cpNetworkNew.Name = "Net_" + ipAddress;
                                                cpNetworkNew.Subnet = ipAddress;
                                                cpNetworkNew.Netmask = ipNetwork.Netmask.ToString();

                                                cpAddressesDict[destination] = cpNetworkNew;

                                                cpNatRule.Destination = cpNetworkNew;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        messagesE.Add(paNatRuleEntry.Name +
                                                        " NAT rule is not converted because destination object is not defined or converted: " +
                                                        destination);
                                    }
                                }
                                #endregion

                                #region adding original service
                                if (!PA_ANY_VALUE.Equals(paNatRuleEntry.Service))
                                {
                                    if (cpServicesDict.ContainsKey(paNatRuleEntry.Service))
                                    {
                                        cpNatRule.Service = cpServicesDict[paNatRuleEntry.Service];
                                    }
                                    else if (cpServicesGroupsDict.ContainsKey(paNatRuleEntry.Service))
                                    {
                                        cpNatRule.Service = cpServicesGroupsDict[paNatRuleEntry.Service];
                                    }
                                    else
                                    {
                                        messagesE.Add(paNatRuleEntry.Name +
                                                        " NAT rule is not converted because service or group of services object is not defined or converted: " +
                                                        paNatRuleEntry.Service);
                                    }
                                }
                                #endregion

                                #region adding source translation and changing NAT rule Method to static if it is required by Source Translation
                                if (isSourceTranslationExists)
                                {
                                    cpNatRule.TranslatedSource = cpSourceTranslation;
                                    if (isNatRuleStatic)
                                    {
                                        cpNatRule.Method = CheckPoint_NAT_Rule.NatMethod.Static;
                                    }
                                }
                                #endregion

                                PostProcessNatRule46(cpNatRule);
                                PostProcessNatRule64(cpNatRule);

                                #region adding destination translation

                                if (paNatRuleEntry.DestinationTranslation != null)
                                {
                                    if (!string.IsNullOrWhiteSpace(paNatRuleEntry.DestinationTranslation.TranslatedAddress))
                                    {
                                        if (cpAddressesDict.ContainsKey(paNatRuleEntry.DestinationTranslation.TranslatedAddress))
                                        {
                                            cpNatRule.TranslatedDestination = cpAddressesDict[paNatRuleEntry.DestinationTranslation.TranslatedAddress];
                                        }
                                        else if (Regex.IsMatch(paNatRuleEntry.DestinationTranslation.TranslatedAddress, RE_NET_ADDRESS))
                                        {
                                            if (!paNatRuleEntry.DestinationTranslation.TranslatedAddress.Contains("/") || paNatRuleEntry.DestinationTranslation.TranslatedAddress.Contains(NETWORK_NETMASK_WS))
                                            {
                                                string ipAddress;

                                                if (paNatRuleEntry.DestinationTranslation.TranslatedAddress.Contains("/"))
                                                    ipAddress = paNatRuleEntry.DestinationTranslation.TranslatedAddress.Substring(0, paNatRuleEntry.DestinationTranslation.TranslatedAddress.IndexOf("/"));
                                                else
                                                    ipAddress = paNatRuleEntry.DestinationTranslation.TranslatedAddress.Substring(0);

                                                CheckPoint_Host cpHostNew = new CheckPoint_Host();
                                                cpHostNew.Name = "Host_" + ipAddress;
                                                cpHostNew.IpAddress = ipAddress;

                                                cpAddressesDict[paNatRuleEntry.DestinationTranslation.TranslatedAddress] = cpHostNew;

                                                cpNatRule.TranslatedDestination = cpHostNew;
                                            }
                                            else
                                            {
                                                IPNetwork ipNetwork;
                                                if (IPNetwork.TryParse(paNatRuleEntry.DestinationTranslation.TranslatedAddress, out ipNetwork))
                                                {
                                                    string ipAddress = paNatRuleEntry.DestinationTranslation.TranslatedAddress.Substring(0, paNatRuleEntry.DestinationTranslation.TranslatedAddress.IndexOf("/"));

                                                    CheckPoint_Network cpNetworkNew = new CheckPoint_Network();
                                                    cpNetworkNew.Name = "Net_" + ipAddress;
                                                    cpNetworkNew.Subnet = ipAddress;
                                                    cpNetworkNew.Netmask = ipNetwork.Netmask.ToString();

                                                    cpAddressesDict[paNatRuleEntry.DestinationTranslation.TranslatedAddress] = cpNetworkNew;

                                                    cpNatRule.TranslatedDestination = cpNetworkNew;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            messagesE.Add(paNatRuleEntry.Name +
                                                            " NAT rule is not converted because destination translation object is not defined or converted: " +
                                                            paNatRuleEntry.DestinationTranslation.TranslatedAddress);
                                        }

                                        if (!string.IsNullOrWhiteSpace(paNatRuleEntry.DestinationTranslation.TranslatedPort))
                                        {
                                            if (!string.IsNullOrWhiteSpace(paNatRuleEntry.Service))
                                            {
                                                if (cpServicesDict.ContainsKey(paNatRuleEntry.Service))
                                                {
                                                    CheckPointObject cpService = cpServicesDict[paNatRuleEntry.Service];
                                                    if (cpService.GetType() == typeof(CheckPoint_TcpService) || cpService.GetType() == typeof(CheckPoint_ServiceGroup))
                                                    {
                                                        cpNatRule.TranslatedService = CreateNatServiceTcpFromStatDest(paNatRuleEntry);
                                                    }
                                                    else if (cpService.GetType() == typeof(CheckPoint_UdpService))
                                                    {
                                                        cpNatRule.TranslatedService = CreateNatServiceUdpFromStatDest(paNatRuleEntry);
                                                    }
                                                    else if (cpService.GetType() == typeof(CheckPoint_PredifinedObject) && paServicesTypesDict.ContainsKey(paNatRuleEntry.Service))
                                                    {
                                                        string servicesType = paServicesTypesDict[paNatRuleEntry.Service];
                                                        if (servicesType.Trim().ToUpper().Equals(SERVICE_TYPE_TCP))
                                                        {
                                                            cpNatRule.TranslatedService = CreateNatServiceTcpFromStatDest(paNatRuleEntry);
                                                        }
                                                        else if (servicesType.Trim().ToUpper().Equals(SERVICE_TYPE_UDP))
                                                        {
                                                            cpNatRule.TranslatedService = CreateNatServiceUdpFromStatDest(paNatRuleEntry);
                                                        }
                                                    }
                                                }
                                                else if (cpServicesGroupsDict.ContainsKey(paNatRuleEntry.Service))
                                                {
                                                    bool isTcpSrv = false;
                                                    bool isUdpSrv = false;

                                                    GetServicesTypesFromServicesGroup((CheckPoint_ServiceGroup)cpServicesGroupsDict[paNatRuleEntry.Service],
                                                                            (new List<CheckPoint_ServiceGroup>(cpServicesGroupsDict.Values)),
                                                                            (new List<CheckPointObject>(cpServicesDict.Values)),
                                                                            out isTcpSrv, out isUdpSrv);

                                                    if (isTcpSrv && !isUdpSrv)
                                                    {
                                                        cpNatRule.TranslatedService = CreateNatServiceTcpFromStatDest(paNatRuleEntry);
                                                    }
                                                    else if (!isTcpSrv && isUdpSrv)
                                                    {
                                                        cpNatRule.TranslatedService = CreateNatServiceUdpFromStatDest(paNatRuleEntry);
                                                    }
                                                    else
                                                    {
                                                        cpNatRule.TranslatedService = CreateNatServiceTcpFromStatDest(paNatRuleEntry);
                                                        extraNatServiceTranslated = CreateNatServiceUdpFromStatDest(paNatRuleEntry);

                                                        List<CheckPointObject> cpSrvGrpMembersTcp = new List<CheckPointObject>();
                                                        List<CheckPointObject> cpSrvGrpMembersUdp = new List<CheckPointObject>();
                                                        GetServicesGroupsFromServiceGroup(
                                                            (CheckPoint_ServiceGroup)cpServicesGroupsDict[paNatRuleEntry.Service],
                                                            (new List<CheckPoint_ServiceGroup>(cpServicesGroupsDict.Values)),
                                                            (new List<CheckPointObject>(cpServicesDict.Values)),
                                                            cpSrvGrpMembersTcp,
                                                            cpSrvGrpMembersUdp);

                                                        CheckPoint_ServiceGroup cpSrvGrpTcpNat = new CheckPoint_ServiceGroup();
                                                        cpSrvGrpTcpNat.Name = InspectObjectName("Nat_SrcTcpGrp_" + paNatRuleEntry.Name, "services group");
                                                        cpSrvGrpMembersTcp.ForEach(x => cpSrvGrpTcpNat.Members.Add(x.Name));

                                                        CheckPoint_ServiceGroup cpSrvGrpUdpNat = new CheckPoint_ServiceGroup();
                                                        cpSrvGrpUdpNat.Name = InspectObjectName("Nat_SrcUdpGrp_" + paNatRuleEntry.Name, "services group");
                                                        cpSrvGrpMembersUdp.ForEach(x => cpSrvGrpUdpNat.Members.Add(x.Name));

                                                        cpNatRule.Service = cpSrvGrpTcpNat;
                                                        extraNatServiceSourced = cpSrvGrpUdpNat;
                                                    }
                                                }
                                                else // paNatRuleEntry.Service = "any"
                                                {
                                                    cpNatRule.TranslatedService = CreateNatServiceTcpFromStatDest(paNatRuleEntry);
                                                    extraNatServiceTranslated = CreateNatServiceUdpFromStatDest(paNatRuleEntry);

                                                    CheckPoint_TcpService extraSrcSrvTcp = new CheckPoint_TcpService();
                                                    extraSrcSrvTcp.Name = InspectObjectName("Nat_SrcTcp_" + paNatRuleEntry.Name, "tcp service");
                                                    extraSrcSrvTcp.Port = "1-65535";

                                                    CheckPoint_UdpService extraSrcSrvUdp = new CheckPoint_UdpService();
                                                    extraSrcSrvUdp.Name = InspectObjectName("Nat_SrcUdp_" + paNatRuleEntry.Name, "udp service");
                                                    extraSrcSrvUdp.Port = "1-65535";

                                                    cpNatRule.Service = extraSrcSrvTcp;
                                                    extraNatServiceSourced = extraSrcSrvUdp;
                                                }
                                            }
                                        }
                                    }
                                }

                                #endregion

                                #region adding dynamic destination translation

                                if (paNatRuleEntry.DynamicDestinationTranslation != null && !string.IsNullOrWhiteSpace(paNatRuleEntry.DynamicDestinationTranslation.TranslatedAddress)
                                    && !(isNatRuleBiDirectional && isDestinationTranslationNone))
                                {
                                    if (cpAddressesDict.ContainsKey(paNatRuleEntry.DynamicDestinationTranslation.TranslatedAddress))
                                    {
                                        cpNatRule.TranslatedDestination = cpAddressesDict[paNatRuleEntry.DynamicDestinationTranslation.TranslatedAddress];
                                    }
                                    else if (cpNetGroupsDict.ContainsKey(paNatRuleEntry.DynamicDestinationTranslation.TranslatedAddress))
                                    {
                                        cpNatRule.TranslatedDestination = cpNetGroupsDict[paNatRuleEntry.DynamicDestinationTranslation.TranslatedAddress];
                                    }

                                    if (!string.IsNullOrWhiteSpace(paNatRuleEntry.DynamicDestinationTranslation.TranslatedPort))
                                    {
                                        if (!string.IsNullOrWhiteSpace(paNatRuleEntry.Service))
                                        {
                                            if (cpServicesDict.ContainsKey(paNatRuleEntry.Service))
                                            {
                                                CheckPointObject cpService = cpServicesDict[paNatRuleEntry.Service];
                                                if (cpService.GetType() == typeof(CheckPoint_TcpService))
                                                {
                                                    cpNatRule.TranslatedService = CreateNatServiceTcpFromDynDest(paNatRuleEntry);
                                                }
                                                else if (cpService.GetType() == typeof(CheckPoint_UdpService))
                                                {
                                                    cpNatRule.TranslatedService = CreateNatServiceUdpFromDynDest(paNatRuleEntry);
                                                }
                                                else if (cpService.GetType() == typeof(CheckPoint_PredifinedObject) && paServicesTypesDict.ContainsKey(paNatRuleEntry.Service))
                                                {
                                                    string servicesType = paServicesTypesDict[paNatRuleEntry.Service];
                                                    if (servicesType.Trim().ToUpper().Equals("TCP"))
                                                    {
                                                        cpNatRule.TranslatedService = CreateNatServiceTcpFromDynDest(paNatRuleEntry);
                                                    }
                                                    else if (servicesType.Trim().ToUpper().Equals("UDP"))
                                                    {
                                                        cpNatRule.TranslatedService = CreateNatServiceUdpFromDynDest(paNatRuleEntry);
                                                    }
                                                }
                                            }
                                            else if (cpServicesGroupsDict.ContainsKey(paNatRuleEntry.Service))
                                            {
                                                bool isTcpSrv = false;
                                                bool isUdpSrv = false;

                                                GetServicesTypesFromServicesGroup((CheckPoint_ServiceGroup)cpServicesGroupsDict[paNatRuleEntry.Service],
                                                                        (new List<CheckPoint_ServiceGroup>(cpServicesGroupsDict.Values)),
                                                                        (new List<CheckPointObject>(cpServicesDict.Values)),
                                                                        out isTcpSrv, out isUdpSrv);

                                                if (isTcpSrv && !isUdpSrv)
                                                {
                                                    cpNatRule.TranslatedService = CreateNatServiceTcpFromDynDest(paNatRuleEntry);
                                                }
                                                else if (!isTcpSrv && isUdpSrv)
                                                {
                                                    cpNatRule.TranslatedService = CreateNatServiceUdpFromDynDest(paNatRuleEntry);
                                                }
                                                else
                                                {
                                                    cpNatRule.TranslatedService = CreateNatServiceTcpFromDynDest(paNatRuleEntry);
                                                    extraNatServiceTranslated = CreateNatServiceUdpFromDynDest(paNatRuleEntry);

                                                    List<CheckPointObject> cpSrvGrpMembersTcp = new List<CheckPointObject>();
                                                    List<CheckPointObject> cpSrvGrpMembersUdp = new List<CheckPointObject>();
                                                    GetServicesGroupsFromServiceGroup(
                                                        (CheckPoint_ServiceGroup)cpServicesGroupsDict[paNatRuleEntry.Service],
                                                        (new List<CheckPoint_ServiceGroup>(cpServicesGroupsDict.Values)),
                                                        (new List<CheckPointObject>(cpServicesDict.Values)),
                                                        cpSrvGrpMembersTcp,
                                                        cpSrvGrpMembersUdp);

                                                    CheckPoint_ServiceGroup cpSrvGrpTcpNat = new CheckPoint_ServiceGroup();
                                                    cpSrvGrpTcpNat.Name = InspectObjectName("Nat_SrcTcpGrp_" + paNatRuleEntry.Name, "services group");
                                                    cpSrvGrpMembersTcp.ForEach(x => cpSrvGrpTcpNat.Members.Add(x.Name));

                                                    CheckPoint_ServiceGroup cpSrvGrpUdpNat = new CheckPoint_ServiceGroup();
                                                    cpSrvGrpUdpNat.Name = InspectObjectName("Nat_SrcUdpGrp_" + paNatRuleEntry.Name, "services group");
                                                    cpSrvGrpMembersUdp.ForEach(x => cpSrvGrpUdpNat.Members.Add(x.Name));

                                                    cpNatRule.Service = cpSrvGrpTcpNat;
                                                    extraNatServiceSourced = cpSrvGrpUdpNat;
                                                }
                                            }
                                            else // paNatRuleEntry.Service = "any"
                                            {
                                                cpNatRule.TranslatedService = CreateNatServiceTcpFromDynDest(paNatRuleEntry);
                                                extraNatServiceTranslated = CreateNatServiceUdpFromDynDest(paNatRuleEntry);

                                                CheckPoint_TcpService extraSrcSrvTcp = new CheckPoint_TcpService();
                                                extraSrcSrvTcp.Name = InspectObjectName("Nat_SrcTcp_" + paNatRuleEntry.Name, "tcp service");
                                                extraSrcSrvTcp.Port = "1-65535";

                                                CheckPoint_UdpService extraSrcSrvUdp = new CheckPoint_UdpService();
                                                extraSrcSrvUdp.Name = InspectObjectName("Nat_SrcUdp_" + paNatRuleEntry.Name, "udp service");
                                                extraSrcSrvUdp.Port = "1-65535";

                                                cpNatRule.Service = extraSrcSrvTcp;
                                                extraNatServiceSourced = extraSrcSrvUdp;
                                            }
                                        }
                                    }
                                }

                                #endregion

                                if (messagesE.Count == 0)
                                {
                                    if (!(cpNatRule.Source is CheckPoint_Domain) &&
                                        !(cpNatRule.Destination is CheckPoint_Domain) &&
                                        !(cpNatRule.TranslatedSource is CheckPoint_Domain) &&
                                        !(cpNatRule.TranslatedDestination is CheckPoint_Domain))
                                    {
                                        if (isNatRuleBiDirectional && isDestinationTranslationNone)
                                        {
                                            //TRANS DEST == NONE
                                            // orig source <- orig destin
                                            // orig destin <- trans source
                                            // trans source <- trans destin
                                            // trans destin <- orig source

                                            CheckPoint_NAT_Rule cpNatRuleBi = new CheckPoint_NAT_Rule();
                                            cpNatRuleBi.Comments = cpNatRule.Comments;
                                            cpNatRuleBi.ConversionIncidentType = cpNatRule.ConversionIncidentType;
                                            cpNatRuleBi.ConvertedCommandId = cpNatRule.ConvertedCommandId;
                                            cpNatRuleBi.Enabled = cpNatRule.Enabled;
                                            cpNatRuleBi.Method = cpNatRule.Method;
                                            cpNatRuleBi.Name = cpNatRule.Name + "_BD";
                                            cpNatRuleBi.Package = cpNatRule.Package;
                                            cpNatRuleBi.Service = cpNatRule.Service;
                                            cpNatRuleBi.Tag = cpNatRule.Tag;
                                            cpNatRuleBi.Tags = cpNatRule.Tags;
                                            cpNatRuleBi.TranslatedService = cpNatRule.TranslatedService;
                                            cpNatRuleBi.VendorCustomData = cpNatRule.VendorCustomData;

                                            cpNatRuleBi.Source = cpNatRule.Destination;
                                            cpNatRuleBi.Destination = cpNatRule.TranslatedSource;
                                            cpNatRuleBi.TranslatedSource = cpNatRule.TranslatedDestination;
                                            cpNatRuleBi.TranslatedDestination = cpNatRule.Source;

                                            _cpNatRules.Add(cpNatRuleBi);
                                        }

                                        if (isNatRule46AndHasNonOriginTranslatedService(cpNatRule))
                                        {
                                            _warningsList.Add(String.Format("NAT Rule {0} has nat46 method and non-origin translated-service.", cpNatRule.Name));
                                            continue; // skip this Nat rule
                                        }
                                        if (isNatRule46AndTranslatedSourceIsHost(cpNatRule))
                                        {
                                            _warningsList.Add(string.Format("NAT Rule {0} has nat46 method and host as translated-source.", cpNatRule.Name));
                                            continue;
                                        }
                                        if (isNatRule46AndOriginalDestinationIsNotHost(cpNatRule))
                                        {
                                            _warningsList.Add(string.Format("NAT Rule {0} has nat46 method and original-destination is not a host.", cpNatRule.Name));
                                            continue;
                                        }

                                        _cpNatRules.Add(cpNatRule);
                                        AddCheckPointObject(cpNatRule.Source);
                                        AddCheckPointObject(cpNatRule.Destination);
                                        AddCheckPointObject(cpNatRule.Service);
                                        AddCheckPointObject(cpNatRule.TranslatedSource);
                                        AddCheckPointObject(cpNatRule.TranslatedDestination);
                                        AddCheckPointObject(cpNatRule.TranslatedService);
                                        _rulesInNatLayer += 1;

                                        if (extraNatServiceSourced != null && extraNatServiceTranslated != null)
                                        {
                                            AddCheckPointObject(extraNatServiceSourced);
                                            AddCheckPointObject(extraNatServiceTranslated);

                                            CheckPoint_NAT_Rule cpNatRuleExtra = cpNatRule.Clone();
                                            cpNatRuleExtra.Service = extraNatServiceSourced;
                                            cpNatRuleExtra.TranslatedService = extraNatServiceTranslated;
                                            _cpNatRules.Add(cpNatRuleExtra);
                                            _rulesInNatLayer += 1;
                                        }
                                    }
                                    else
                                    {
                                        _errorsList.Add(cpNatRule.Name + " NAT rule contains FQDN object so it can not been converted.");
                                    }
                                }
                                else
                                {
                                    counterNatRules -= 1;
                                    _errorsList.AddRange(messagesE);
                                }
                                _warningsList.AddRange(messagesW);
                            }
                        }
                    }
                }
            }
        }

        public CheckPointObject CreateNatServiceTcpFromStatDest(PA_NatRuleEntry paNatRuleEntry)
        {
            CheckPoint_TcpService natServiceTcp = new CheckPoint_TcpService();
            natServiceTcp.Name = InspectObjectName("Nat_TrTcp_" + paNatRuleEntry.Name, CP_OBJECT_TYPE_NAME_SERVICE_TCP);
            natServiceTcp.Port = paNatRuleEntry.DestinationTranslation.TranslatedPort;

            return InspectService(natServiceTcp);
        }

        public CheckPointObject CreateNatServiceUdpFromStatDest(PA_NatRuleEntry paNatRuleEntry)
        {
            CheckPoint_UdpService natServiceUdp = new CheckPoint_UdpService();
            natServiceUdp.Name = InspectObjectName("Nat_TrUdp_" + paNatRuleEntry.Name, CP_OBJECt_TYPE_NAME_SERVICE_UDP);
            natServiceUdp.Port = paNatRuleEntry.DestinationTranslation.TranslatedPort;

            return InspectService(natServiceUdp);
        }

        public CheckPointObject CreateNatServiceTcpFromDynDest(PA_NatRuleEntry paNatRuleEntry)
        {
            CheckPoint_TcpService natServiceTcp = new CheckPoint_TcpService();
            natServiceTcp.Name = InspectObjectName("Nat_TrTcp_" + paNatRuleEntry.Name, CP_OBJECT_TYPE_NAME_SERVICE_TCP);
            natServiceTcp.Port = paNatRuleEntry.DynamicDestinationTranslation.TranslatedPort;

            return InspectService(natServiceTcp);
        }

        public CheckPointObject CreateNatServiceUdpFromDynDest(PA_NatRuleEntry paNatRuleEntry)
        {
            CheckPoint_UdpService natServiceUdp = new CheckPoint_UdpService();
            natServiceUdp.Name = InspectObjectName("Nat_TrUdp_" + paNatRuleEntry.Name, CP_OBJECt_TYPE_NAME_SERVICE_UDP);
            natServiceUdp.Port = paNatRuleEntry.DynamicDestinationTranslation.TranslatedPort;

            return InspectService(natServiceUdp);
        }

        public void GetServicesTypesFromServicesGroup(
                                        CheckPoint_ServiceGroup cpSrvGroup,
                                        List<CheckPoint_ServiceGroup> cpServicesGroups,
                                        List<CheckPointObject> cpServices,
                                        out bool isTcpSrv, out bool isUdpSrv)
        {
            isTcpSrv = false;
            isUdpSrv = false;

            foreach (string cpSrvMember in cpSrvGroup.Members)
            {
                CheckPointObject cpSrv = cpServices.Find(x => x.Name.Equals(cpSrvMember));
                if (cpSrv != null)
                {
                    if (cpSrv.GetType() == typeof(CheckPoint_TcpService))
                        isTcpSrv = true;
                    else if (cpSrv.GetType() == typeof(CheckPoint_UdpService))
                        isUdpSrv = true;

                    continue;
                }

                CheckPoint_ServiceGroup cpSrvGrp = cpServicesGroups.Find(x => x.Name.Equals(cpSrvMember));
                if (cpSrvGrp != null)
                {
                    GetServicesTypesFromServicesGroup(cpSrvGrp, cpServicesGroups, cpServices, out isTcpSrv, out isUdpSrv);
                }
            }
        }

        public void GetServicesGroupsFromServiceGroup(
                                            CheckPoint_ServiceGroup cpSrvGroup,
                                            List<CheckPoint_ServiceGroup> cpServicesGroups,
                                            List<CheckPointObject> cpServices,
                                            List<CheckPointObject> cpSrvGrpMembersTcp,
                                            List<CheckPointObject> cpSrvGrpMembersUdp)
        {
            foreach (string cpSrvMember in cpSrvGroup.Members)
            {
                CheckPointObject cpSrv = cpServices.Find(x => x.Name.Equals(cpSrvMember));
                if (cpSrv != null)
                {
                    if (cpSrv.GetType() == typeof(CheckPoint_TcpService))
                    {
                        cpSrvGrpMembersTcp.Add(cpSrv);
                    }
                    else if (cpSrv.GetType() == typeof(CheckPoint_UdpService))
                    {
                        cpSrvGrpMembersUdp.Add(cpSrv);
                    }
                    else if (cpSrv.GetType() == typeof(CheckPoint_PredifinedObject) && cpPredefServicesTypes.ContainsKey(cpSrv.Name))
                    {
                        string srvType = cpPredefServicesTypes[cpSrv.Name].ToLower();
                        if (srvType.Equals(SERVICE_TYPE_TCP.ToLower()))
                        {
                            cpSrvGrpMembersTcp.Add(cpSrv);
                        }
                        else if (srvType.Equals(SERVICE_TYPE_UDP.ToLower()))
                        {
                            cpSrvGrpMembersUdp.Add(cpSrv);
                        }
                    }
                    continue;
                }

                CheckPoint_ServiceGroup cpSrvGrp = cpServicesGroups.Find(x => x.Name.Equals(cpSrvMember));
                if (cpSrvGrp != null)
                {
                    GetServicesGroupsFromServiceGroup(cpSrvGrp, cpServicesGroups, cpServices, cpSrvGrpMembersTcp, cpSrvGrpMembersUdp);
                }
            }
        }

        #endregion

        #region Utility methods

        public void AddCpApplicationGroup(CheckPoint_ApplicationGroup cpAppGrp,
                                          Dictionary<string, CheckPoint_ApplicationGroup> cpAppGroupsDict)
        {
            foreach (string member in cpAppGrp.Members)
            {
                if (cpAppGroupsDict.ContainsKey(member))
                {
                    AddCpApplicationGroup(cpAppGroupsDict[member], cpAppGroupsDict);
                }
            }
            AddCheckPointObject(cpAppGrp);
        }

        public void AddCpNetworkGroup(CheckPoint_NetworkGroup cpNetGroup,
                                      Dictionary<string, CheckPointObject> cpAddressesDict,
                                      Dictionary<string, CheckPoint_NetworkGroup> cpNetGroupsDict)
        {
            foreach (string member in cpNetGroup.Members)
            {
                if (cpAddressesDict.ContainsKey(member))
                {
                    AddCheckPointObject(cpAddressesDict[member]);
                }
                else if (cpNetGroupsDict.ContainsKey(member))
                {
                    AddCpNetworkGroup(cpNetGroupsDict[member], cpAddressesDict, cpNetGroupsDict);
                    AddCheckPointObject(cpNetGroupsDict[member]);
                }
            }
            AddCheckPointObject(cpNetGroup);
        }

        public void AddCpServiceGroup(CheckPoint_ServiceGroup cpSrvGroup,
                                      Dictionary<string, CheckPointObject> cpServicesDict,
                                      Dictionary<string, CheckPoint_ServiceGroup> cpSrvGroupsDict)
        {
            foreach (string member in cpSrvGroup.Members)
            {
                if (cpServicesDict.ContainsKey(member))
                {
                    AddCheckPointObject(cpServicesDict[member]);
                }
                else if (cpSrvGroupsDict.ContainsKey(member))
                {
                    //if cpSrvGroupsDict contains a member
                    //whose members have a copy of the original member,
                    //then we get an infinite recursion
                    //to fix the bug we are skipping the call of the same member
                    var infiniteRecursion = false;
                    foreach (string subMember in cpSrvGroupsDict[member].Members)
                    {
                        if (subMember == member)
                        {
                            infiniteRecursion = true;
                        }
                    }
                    if (!infiniteRecursion)
                        AddCpServiceGroup(cpSrvGroupsDict[member], cpServicesDict, cpSrvGroupsDict);
                    AddCheckPointObject(cpSrvGroupsDict[member]);
                }
            }
            AddCheckPointObject(cpSrvGroup);
        }

        public static string GetSafeName(string name)
        {
            if (name != null && !name.Trim().Equals(""))
            {
                name = Validators.ChangeNameAccordingToRules(name);
                return Regex.Replace(name, RE_NAME_UNSAFE, "_");
            }
            else
            {
                return name;
            }
        }

        protected override string GetVendorName()
        {
            return Vendor.PaloAlto.ToString();
        }
        #endregion
    }

    public class NewAnalizStatistic
    {
        public CheckPoint_Package _Package;
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
        public int _unrulesServicesutilizingServicesAnyCount = 0;
        public int _unrulesServicesutilizingServicesAnySourceCount = 0;
        public int _unrulesServicesutilizingServicesAnyDestinationCount = 0;
        public int _unrulesServicesutilizingServicesAnyServiceCount = 0;
        public int _disabledServicesRulesCount = 0;
        public int _undisabledServicesRulesCount = 0;
        public int _unnamedServicesRulesCount = 0;
        public int _timesServicesRulesCount = 0;
        public int _untimesServicesRulesCount = 0;
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
        public float RulesServicesutilizingServicesAnyPercent { get { return _totalServicesRulesCount > 0 ? ((float)_unrulesServicesutilizingServicesAnyCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float DisabledServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_undisabledServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float UnnamedServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_unnamedServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float TimesServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_untimesServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
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

        public void FlushObjects()
        {
            _unusedNetworkObjectsCount = 0;
            _duplicateNetworkObjectsCount = 0;
            _nestedNetworkGroupsCount = 0;
            _nestedNetworkGroupsCountAll = 0;

            _totalServicesObjectsCount = 0;
            _unusedServicesObjectsCount = 0;
            _duplicateServicesObjectsCount = 0;
            _nestedServicesGroupsCount = 0;
            _nestedServicesGroupsCountAll = 0;
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
                                                   List<CheckPoint_ServiceGroup> _cpServiceGroups,
                                                   List<CheckPoint_RpcService> _cpRpcServices)
        {
            _unusedNetworkObjectsCount = _unusedNetworkObjectsCount >= 0 ? _unusedNetworkObjectsCount : 0;
            _unusedServicesObjectsCount = _unusedServicesObjectsCount >= 0 ? _unusedServicesObjectsCount : 0;
            _undisabledServicesRulesCount = _disabledServicesRulesCount;
            _unrulesServicesutilizingServicesAnyCount = _rulesServicesutilizingServicesAnyCount;
            _unrulesServicesutilizingServicesAnySourceCount = _rulesServicesutilizingServicesAnySourceCount;
            _unrulesServicesutilizingServicesAnyDestinationCount = _rulesServicesutilizingServicesAnyDestinationCount;
            _unrulesServicesutilizingServicesAnyServiceCount = _rulesServicesutilizingServicesAnyServiceCount;
            _untimesServicesRulesCount = _timesServicesRulesCount;
            _totalNetworkObjectsCount = _cpNetworks.Count + _cpHosts.Count + _cpNetworkGroups.Count + _cpRanges.Count;

            //DUPLICATE CALCULATION
            foreach (var item in _cpNetworks)
            {
                if (_cpNetworks.Where(nt => nt.Netmask == item.Netmask & nt.Subnet == nt.Subnet).Count() > 1) { _duplicateNetworkObjectsCount++; }
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
            _totalServicesObjectsCount = _cpTcpServices.Count + _cpUdpServices.Count + _cpSctpServices.Count + _cpIcmpServices.Count + _cpDceRpcServices.Count + _cpOtherServices.Count + _cpServiceGroups.Count + _cpRpcServices.Count;
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
}
