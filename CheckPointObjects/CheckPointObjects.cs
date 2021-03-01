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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using CommonUtils;

namespace CheckPointObjects
{
    /// <summary>
    /// Represents a basic Check Point object.
    /// Exposes properties for the name and comments for the object, and validates their values.
    /// Each derived object must implement the methods for CLI scripts generation.
    /// </summary>
    public abstract class CheckPointObject
    {
        /// <summary>
        /// Regex: replace any char that is NOT any of the following to "_" char
        /// </summary>
        protected const string NameValidityRegex = @"[^A-Za-z0-9_.-]";

        /// <summary>
        /// Regex: replace any char that is NOT any of the following to "_" char
        /// </summary>
        protected const string CommentsValidityRegex = @"[^A-Za-z0-9 @#*$(){}\[\]_.\-=:,/]";

        public const string Any = "any";
        public const string All = "All";
        public const string All_Internet = "All_Internet";
        public const string icmpProtocol = "icmp-proto";

        public string Name { get; set; }

        public string SafeName()
        {
            return GetSafeName(Name);
        }

        private string _comments = "";
        public string Comments
        {
            get { return Regex.Replace(_comments, CommentsValidityRegex, "_"); }
            set { _comments = value; }
        }

        // The Tag property is used as a general data placeholder.
        public string Tag { get; set; }

        /// <summary>
        /// A collection of object tag names.
        /// </summary>
        public List<string> Tags = new List<string>();

        // the type of CheckPoint object, is used for JSON representation
        public string TypeName
        {
            get { return this.GetType().Name; }
        }

        public int ConvertedCommandId { get; set; }
        public ConversionIncidentType ConversionIncidentType { get; set; }

        public virtual IPRanges GetIPRanges()
        {
            return new IPRanges();
        }

        public abstract string ToCLIScript();

        public abstract string ToCLIScriptInstruction();

        protected static string GetSafeName(string name)
        {
            return Regex.Replace(name, NameValidityRegex, "_");
        }

        //escaping quote sign in script
        public List<string> EscapeQuote(List<string> members)
        {
            List<string> resultList = new List<string>();
            foreach (string member in members)
            {
                if (member.IndexOf("\'") != -1)
                    resultList.Add(member.Replace("\'", "\'\\\'\'"));
                else
                    resultList.Add(member);
            }
            return resultList;
        }

        protected static string WriteParam(string paramName, bool paramValue, bool defaultValue)
        {
            if (paramValue == defaultValue)
            {
                return "";
            }

            return paramName + " \"" + paramValue.ToString().ToLower() + "\" ";
        }

        protected static string WriteParam(string paramName, string paramValue, string defaultValue)
        {
            if (paramValue == defaultValue || paramValue == null)
            {
                return "";
            }

            return paramName + " \"" + paramValue + "\" ";
        }

        protected static string WriteListParam(string paramName, List<string> paramValues, bool useSafeNames)
        {
            return WriteListParam(paramName, paramValues, useSafeNames, 0, paramValues.Count);
        }

        protected static string WriteListParam(string paramName, List<string> paramValues, bool useSafeNames, int firstIndex, int maxSize)
        {
            return WriteListParam(paramName, paramValues, useSafeNames, firstIndex, maxSize, "");
        }

        protected static string WriteListParam(string paramName, List<string> paramValues, bool useSafeNames, int firstIndex, int maxSize, string suffix)
        {
            if (paramValues.Count == 0 || firstIndex >= paramValues.Count || maxSize <= 0)
            {
                return "";
            }

            if (paramValues.Count == 1)
            {
                return WriteParam(paramName, paramValues[0], "");
            }

            var sb = new StringBuilder("");
            int maxIndex = ((firstIndex + maxSize) < paramValues.Count) ? (firstIndex + maxSize) : paramValues.Count;
            for (int i = firstIndex; i < maxIndex; i++)
            {
                string value = useSafeNames ? GetSafeName(paramValues[i]) : paramValues[i];
                sb.AppendFormat("{0}{1}.{2} \"{3}\" ", paramName, suffix, i, value);
            }

            return sb.ToString();
        }

        protected static string WriteListParamWithIndexes(string paramName, List<string> paramValues, bool useSafeNames, int i = 0)
        {
            return WriteListParam(paramName, paramValues, useSafeNames, i, paramValues.Count);
        }
    }

    public class CheckPoint_PredifinedObject : CheckPointObject
    {
        public override string ToCLIScript()
        {
            return "";
        }

        public override string ToCLIScriptInstruction()
        {
            return "";
        }
    }

    public class CheckPoint_Zone : CheckPointObject
    {
        public override string ToCLIScript()
        {
            return "add security-zone " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create zone [" + Name + "]";
        }
    }

    public class CheckPoint_Domain : CheckPointObject
    {
        public string Fqdn { get; set; }
        public bool IsSubDomain { get; set; }

        public override string ToCLIScript()
        {
            return "add dns-domain " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("is-sub-domain", IsSubDomain, !IsSubDomain) //"is-sub-domain" is a required field by documentation 
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create domain [" + Name + "]";
        }
    }

    public class CheckPoint_Host : CheckPointObject
    {
        public string IpAddress { get; set; }

        public override IPRanges GetIPRanges()
        {
            return new IPRanges(new IPRange(IPAddress.Parse(IpAddress)));
        }

        public override string ToCLIScript()
        {
            return "add host " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("ip-address", IpAddress, "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create host [" + Name + "] with ip-address [" + IpAddress + "]";
        }
    }

    public class CheckPoint_Network : CheckPointObject
    {
        public string Subnet { get; set; }
        public string Netmask { get; set; }
        public string MaskLenght { get; set; }

        public override IPRanges GetIPRanges()
        {
            if (!string.IsNullOrEmpty(Netmask))
            {
                return new IPRanges(new IPRange(IPNetwork.Parse(Subnet, Netmask)));
            }
            else
            {
                return new IPRanges(new IPRange(IPNetwork.Parse(String.Format("{0}/{1}", Subnet, MaskLenght))));
            }
        }

        public override string ToCLIScript()
        {
            return "add network " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("subnet", Subnet, "")
                + WriteParam("subnet-mask", Netmask, "")
                + WriteParam("mask-length", MaskLenght, "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create network [" + Name + "]: subnet [" + Subnet + "] mask [" + Netmask + "] mask-lenght [" + MaskLenght + "]";
        }
    }

    public class CheckPoint_Range : CheckPointObject
    {
        public string RangeFrom { get; set; }
        public string RangeTo { get; set; }

        public override IPRanges GetIPRanges()
        {
            return new IPRanges(new IPRange(IPAddress.Parse(RangeFrom), IPAddress.Parse(RangeTo)));
        }

        public override string ToCLIScript()
        {
            return "add address-range " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("ipv4-address-first", RangeFrom, "")
                + WriteParam("ipv4-address-last", RangeTo, "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create address range [" + Name + "]: from [" + RangeFrom + "] to [" + RangeTo + "]";
        }
    }

    public class CheckPoint_NetworkGroup : CheckPointObject
    {
        public List<string> Members = new List<string>();

        public bool IsPanoramaDeviceGroup = false;

        /// <summary>
        /// This property is used to overcome the problematic order of objects creation for 
        /// GroupWithExclusion and NetworkGroup types cross-referencing each other.
        /// </summary>
        public bool CreateAfterGroupsWithExclusion { get; set; }
        public int MembersPublishIndex { get; set; } = 0;
        public int MembersMaxPublishSize { get; set; } = Int32.MaxValue;

        public override string ToCLIScript()
        {
            return (MembersPublishIndex == 0 ? "add " : "set ") + "group " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteListParam("members", Members, true, MembersPublishIndex, MembersMaxPublishSize, MembersPublishIndex == 0 ? "" : ".add")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            int index = ((MembersPublishIndex + MembersMaxPublishSize) > Members.Count) ? Members.Count : MembersPublishIndex + MembersMaxPublishSize;
            return (MembersPublishIndex == 0 ? "create " : "update ") + "network group [" + Name + "]: " + index + "/" + Members.Count + " members";
        }

    }

    public class CheckPoint_GroupWithExclusion : CheckPointObject
    {
        public string Include { get; set; }
        public string Except { get; set; }

        public override string ToCLIScript()
        {
            return "add group-with-exclusion " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("include", Include, "")
                + WriteParam("except", Except, "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create group with exclusion [" + Name + "]: Include: " + Include + ", Except: " + Except;
        }
    }

    public class CheckPoint_SimpleGateway : CheckPointObject
    {
        public string IpAddress { get; set; }

        public override string ToCLIScript()
        {
            return "add simple-gateway " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("ip-address", IpAddress, "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create simple gateway [" + Name + "] with ip-address [" + IpAddress + "]";
        }
    }

    public class CheckPoint_UdpService : CheckPointObject
    {
        public string Port { get; set; }
        public string SourcePort { get; set; }
        public string SessionTimeout { get; set; }

        public override string ToCLIScript()
        {
            return "add service-udp " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("port", Port, "")
                + WriteParam("source-port", SourcePort, "")
                + WriteParam("session-timeout", SessionTimeout, "0")
                + ((SessionTimeout != null && !SessionTimeout.Equals("0")) ? WriteParam("use-default-session-timeout", "false", "") : "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create udp service [" + Name + "]: port [" + Port + "]";
        }
    }

    public class CheckPoint_TcpService : CheckPointObject
    {
        public string Port { get; set; }
        public string SourcePort { get; set; }
        public string SessionTimeout { get; set; }

        public override string ToCLIScript()
        {
            return "add service-tcp " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("port", Port, "")
                + WriteParam("source-port", SourcePort, "")
                + WriteParam("session-timeout", SessionTimeout, "0")
                + ((SessionTimeout != null && !SessionTimeout.Equals("0")) ? WriteParam("use-default-session-timeout", "false", "") : "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create tcp service [" + Name + "]: port [" + Port + "]";
        }
    }

    public class CheckPoint_SctpService : CheckPointObject
    {
        public string Port { get; set; }
        public string SourcePort { get; set; }
        public string SessionTimeout { get; set; }

        public override string ToCLIScript()
        {
            return "add service-sctp " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("port", Port, "")
                + WriteParam("source-port", SourcePort, "")
                + WriteParam("session-timeout", SessionTimeout, "0")
                + ((SessionTimeout != null && !SessionTimeout.Equals("0")) ? WriteParam("use-default-session-timeout", "false", "") : "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create sctp service [" + Name + "]: port [" + Port + "]";
        }
    }

    public class CheckPoint_IcmpService : CheckPointObject
    {
        public string Type { get; set; }
        public string Code { get; set; }

        public override string ToCLIScript()
        {
            return "add service-icmp " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("icmp-type", Type, "0")
                + WriteParam("icmp-code", Code, "0")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create icmp service [" + Name + "]: type [" + Type + "] code [" + Code + "]";
        }
    }

    public class CheckPoint_RpcService : CheckPointObject
    {
        public string ProgramNumber { get; set; }

        public override string ToCLIScript()
        {
            return "add service-rpc " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("program-number", ProgramNumber, "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create rpc service [" + Name + "]: program-number [" + ProgramNumber + "]";
        }
    }

    public class CheckPoint_DceRpcService : CheckPointObject
    {
        public string InterfaceUuid { get; set; }

        public override string ToCLIScript()
        {
            return "add service-dce-rpc " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("interface-uuid", InterfaceUuid, "")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create dce-rpc service [" + Name + "]: interface-uuid [" + InterfaceUuid + "]";
        }
    }

    public class CheckPoint_OtherService : CheckPointObject
    {
        public string IpProtocol { get; set; }

        public override string ToCLIScript()
        {
            return "add service-other " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("ip-protocol", IpProtocol, "")
                + WriteParam("match-for-any", true, false)
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create other service [" + Name + "]: IP protocol [" + IpProtocol + "]";
        }
    }

    public class CheckPoint_ServiceGroup : CheckPointObject
    {
        public List<string> Members = new List<string>();
        public int MembersPublishIndex { get; set; } = 0;
        public int MembersMaxPublishSize { get; set; } = Int32.MaxValue;

        public override string ToCLIScript()
        {
            return (MembersPublishIndex == 0 ? "add " : "set ") + "service-group " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteListParam("members", Members, true, MembersPublishIndex, MembersMaxPublishSize, MembersPublishIndex == 0 ? "" : ".add")
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            //index for comments
            int index = ((MembersPublishIndex + MembersMaxPublishSize) > Members.Count) ? Members.Count : MembersPublishIndex + MembersMaxPublishSize;
            return (MembersPublishIndex == 0 ? "create " : "update ") + "service group [" + Name + "]: " + index + "/" + Members.Count + " members";
        }
        
    }

    public class CheckPoint_ApplicationGroup : CheckPointObject
    {
        public List<string> Members = new List<string>();

        public override string ToCLIScript()
        {
            List<string> members = EscapeQuote(Members);//escaping quote sign in script

            return "add application-site-group " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteListParam("members", members, false)
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create application group [" + Name + "]: " + Members.Count + " members";
        }
    }

    public class CheckPoint_Time : CheckPointObject
    {
        public enum Weekdays { Sun, Mon, Tue, Wed, Thu, Fri, Sat };
        public enum RecurrencePatternEnum { None, Daily, Weekly, Monthly };

        public bool StartNow { get; set; }
        public string StartDate { get; set; }
        public string StartTime { get; set; }
        public double StartPosix { get; set; }

        public bool EndNever { get; set; }
        public string EndDate { get; set; }
        public string EndTime { get; set; }
        public double EndPosix { get; set; }

        public bool HoursRangesEnabled_1 { get; set; }
        public string HoursRangesFrom_1 { get; set; }
        public string HoursRangesTo_1 { get; set; }

        public bool HoursRangesEnabled_2 { get; set; }
        public string HoursRangesFrom_2 { get; set; }
        public string HoursRangesTo_2 { get; set; }

        public bool HoursRangesEnabled_3 { get; set; }
        public string HoursRangesFrom_3 { get; set; }
        public string HoursRangesTo_3 { get; set; }

        public RecurrencePatternEnum RecurrencePattern { get; set; }

        public List<Weekdays> RecurrenceWeekdays = new List<Weekdays>();

        public override string ToCLIScript()
        {
            return "add time " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")

                + WriteParam("start-now", StartNow.ToString().ToLower(), "")
                + WriteParam("start.date", StartDate, "")
                + WriteParam("start.time", StartTime, "")
                + WriteParam("start.posix", (StartPosix > 0 ? "" + StartPosix : ""), "")

                + WriteParam("end-never", EndNever.ToString().ToLower(), "")
                + WriteParam("end.date", EndDate, "")
                + WriteParam("end.time", EndTime, "")
                + WriteParam("end.posix", (EndPosix > 0 ? "" + EndPosix : ""), "")

                + WriteParam("hours-ranges.1.enabled", (HoursRangesEnabled_1 ? HoursRangesEnabled_1.ToString().ToLower() : ""), "")
                + WriteParam("hours-ranges.1.from", HoursRangesFrom_1, "")
                + WriteParam("hours-ranges.1.to", HoursRangesTo_1, "")

                + WriteParam("hours-ranges.2.enabled", (HoursRangesEnabled_2 ? HoursRangesEnabled_2.ToString().ToLower() : ""), "")
                + WriteParam("hours-ranges.2.from", HoursRangesFrom_2, "")
                + WriteParam("hours-ranges.2.to", HoursRangesTo_2, "")

                + WriteParam("hours-ranges.3.enabled", (HoursRangesEnabled_3 ? HoursRangesEnabled_3.ToString().ToLower() : ""), "")
                + WriteParam("hours-ranges.3.from", HoursRangesFrom_3, "")
                + WriteParam("hours-ranges.3.to", HoursRangesTo_3, "")

                + WriteParam("recurrence.pattern", ((RecurrenceWeekdays.Count > 0 || RecurrencePattern == RecurrencePatternEnum.Weekly) ? "Weekly" : ""), "")
                + WriteParam("recurrence.pattern", ((RecurrencePattern == RecurrencePatternEnum.Daily) ? "Daily" : ""), "")
                + WriteParam("recurrence.pattern", ((RecurrencePattern == RecurrencePatternEnum.Monthly) ? "Monthly" : ""), "")
                + WriteListParamWithIndexes("recurrence.weekdays", (from o in RecurrenceWeekdays select o.ToString()).ToList(), true)

                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create time [" + Name + "]";
        }

        public CheckPoint_Time Clone()
        {
            var newTime = new CheckPoint_Time();

            newTime.Name = Name;
            newTime.Comments = Comments;
            newTime.StartNow = StartNow;
            newTime.StartDate = StartDate;
            newTime.StartTime = StartTime;
            newTime.StartPosix = StartPosix;
            newTime.EndNever = EndNever;
            newTime.EndDate = EndDate;
            newTime.EndTime = EndTime;
            newTime.EndPosix = EndPosix;

            newTime.HoursRangesEnabled_1 = HoursRangesEnabled_1;
            newTime.HoursRangesFrom_1 = HoursRangesFrom_1;
            newTime.HoursRangesTo_1 = HoursRangesTo_1;

            newTime.HoursRangesEnabled_2 = HoursRangesEnabled_2;
            newTime.HoursRangesFrom_2 = HoursRangesFrom_2;
            newTime.HoursRangesTo_2 = HoursRangesTo_2;

            newTime.HoursRangesEnabled_3 = HoursRangesEnabled_3;
            newTime.HoursRangesFrom_3 = HoursRangesFrom_3;
            newTime.HoursRangesTo_3 = HoursRangesTo_3;

            newTime.RecurrencePattern = RecurrencePattern;
            newTime.RecurrenceWeekdays = RecurrenceWeekdays;

            return newTime;
        }
    }

    public class CheckPoint_TimeGroup : CheckPointObject
    {
        public List<string> Members = new List<string>();

        public override string ToCLIScript()
        {
            return "add time-group " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteListParam("members", Members, true)
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create time group [" + Name + "]: " + Members.Count + " members";
        }
    }

    public class AccessRoleUser
    {
        public string Name { get; set; }
        public string BaseDn { get; set; }
    }

    public class CheckPoint_AccessRole : CheckPointObject
    {
        public List<string> Networks = new List<string>();
        public List<AccessRoleUser> Users = new List<AccessRoleUser>();

        public override string ToCLIScript()
        {
            if (Networks.Count == 0)
            {
                Networks.Add("any");
            }
            return "add access-role "
                + WriteParam("name", SafeName(), "")
                + WriteListParam("networks", Networks, true)
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create access role [" + Name + "]: " + Users.Count + " users";
        }
    }

    public class CheckPoint_Rule : CheckPointObject
    {
        public enum ActionType { Accept, Drop, Reject, SubPolicy };
        public enum TrackTypes { None, Log };

        public const string SubPolicyCleanupRuleName = "Sub-Policy Cleanup rule";

        public bool Enabled { get; set; }
        public string Layer { get; set; }
        public string SubPolicyName { get; set; }
        public ActionType Action { get; set; }
        public TrackTypes Track { get; set; }
        public bool SourceNegated { get; set; }
        public bool DestinationNegated { get; set; }

        public List<string> Target = new List<string>();//"install-on" parameter of CP rule
        public bool TargetNegated { get; set; }

        private string _conversionComments;
        public string ConversionComments
        {
            get { return Regex.Replace(_conversionComments, CommentsValidityRegex, "_"); }
            set { _conversionComments = value; }
        }

        public List<CheckPointObject> Source = new List<CheckPointObject>();
        public List<CheckPointObject> Destination = new List<CheckPointObject>();
        public List<CheckPointObject> Service = new List<CheckPointObject>();
        public List<CheckPointObject> Time = new List<CheckPointObject>();

        public CheckPoint_Rule()
        {
            Enabled = true;
            Layer = "";
            SubPolicyName = "";
            Action = ActionType.Drop;
            Track = TrackTypes.Log;
            SourceNegated = false;
            DestinationNegated = false;
            ConversionComments = "";
        }

        public override string ToCLIScript()
        {
            string actionName = "";

            switch (Action)
            {
                case ActionType.Accept:
                    actionName = "accept";
                    break;
                case ActionType.Drop:
                    actionName = "drop";
                    break;
                case ActionType.Reject:
                    actionName = "reject";
                    break;
                case ActionType.SubPolicy:
                    actionName = "apply layer";
                    break;
            }

            return "add access-rule " + WriteParam("layer", Layer, "") + WriteParam("comments", Comments, "")
                + WriteListParam("source", (from o in Source select o.Name).ToList(), true)
                + WriteListParam("destination", (from o in Destination select o.Name).ToList(), true)
                + WriteServicesParams()
                + WriteParamWithIndexesForApplications()
                + WriteListParam("time", (from o in Time select o.Name).ToList(), true)
                + WriteParam("action", actionName, "")
                + WriteParam("track-settings.type", Track.ToString(), "")
                + WriteParam("enabled", Enabled, true)
                + WriteParam("source-negate", SourceNegated, false)
                + WriteParam("destination-negate", DestinationNegated, false)
                + WriteParam("position", "top", "")
                + WriteParam("inline-layer", SubPolicyName, "")
                + WriteParam("name", Name, "")
                + WriteListParam("install-on", (from o in Target select o).ToList(), true)
                + WriteParam("custom-fields.field-1", ConversionComments.Substring(0, Math.Min(ConversionComments.Length, 150)), "");
        }

        public override string ToCLIScriptInstruction()
        {
            return "";
        }

        public CheckPoint_Rule Clone()
        {
            var newRule = new CheckPoint_Rule();
            newRule.Name = Name;
            newRule.Comments = Comments;
            newRule.Enabled = Enabled;
            newRule.Layer = Layer;
            newRule.SubPolicyName = SubPolicyName;
            newRule.Action = Action;
            newRule.Track = Track;
            newRule.SourceNegated = SourceNegated;
            newRule.DestinationNegated = DestinationNegated;
            newRule.ConvertedCommandId = ConvertedCommandId;
            newRule.ConversionIncidentType = ConversionIncidentType;

            foreach (CheckPointObject obj in Source)
            {
                newRule.Source.Add(obj);
            }
            foreach (CheckPointObject obj in Destination)
            {
                newRule.Destination.Add(obj);
            }
            foreach (CheckPointObject obj in Service)
            {
                newRule.Service.Add(obj);
            }
            foreach (CheckPointObject obj in Time)
            {
                newRule.Time.Add(obj);
            }
            foreach (string obj in Target)
            {
                newRule.Target.Add(obj);
            }
            CloneApplicationsToRule(newRule);

            return newRule;
        }

        public bool CompareTo(CheckPoint_Rule other)
        {
            if (Enabled != other.Enabled ||
                Action != other.Action ||
                Track != other.Track ||
                SourceNegated != other.SourceNegated ||
                DestinationNegated != other.DestinationNegated)
            {
                return false;
            }

            if ((Time.Count != other.Time.Count) ||
                (Time.Count > 0 && other.Time.Count > 0 && Time[0].Name != other.Time[0].Name))
            {
                return false;
            }

            bool sourceMatch = CompareLists(Source, other.Source);
            bool destMatch = CompareLists(Destination, other.Destination);
            bool serviceMatch = CompareLists(Service, other.Service);
            bool applicationMatch = CompareApplications(other);

            return sourceMatch && destMatch && serviceMatch && applicationMatch;
        }

        public bool IsCleanupRule()
        {
            if (!string.IsNullOrEmpty(Name) && Name == SubPolicyCleanupRuleName)
            {
                return true;   // sub-policy's automatic cleanup rule
            }
            return checkRuleType(ActionType.Drop);// user defined cleanup rule           
        }

        /// <summary>
        /// Verifies if the rule allows all traffic (which means rule has source: Any, destination: Any, service: Any and action: Accept)
        /// </summary>
        /// <returns></returns>
        public bool IsAllowAnyRule()
        {
            return checkRuleType(ActionType.Accept);// user defined Allow Any rule
        }

        private bool checkRuleType(ActionType actionType)
        {
            if ((Source.Count == 1 && Source[0].Name == Any || Source.Count == 0) &&
                (Destination.Count == 1 && Destination[0].Name == Any || Destination.Count == 0) &&
                (Service.Count == 1 && Service[0].Name == Any || Service.Count == 0) &&
                IsApplicationsClean() &&
                (Action == actionType))
            {
                return true;
            }
            return false;
        }

        protected static bool CompareLists(IEnumerable<CheckPointObject> items1, IEnumerable<CheckPointObject> items2)
        {
            var list1 = (from o in items1 select o.Name).ToList();
            var list2 = (from o in items2 select o.Name).ToList();

            var firstNotSecond = list1.Except(list2).ToList();
            var secondNotFirst = list2.Except(list1).ToList();

            return (!firstNotSecond.Any() && !secondNotFirst.Any());
        }

        //WriteParamWithIndexesForApplications will be overridden in the derived class if the class needs specific implementation for applications
        //return null because this object doesn't handle with applications.
        protected virtual string WriteParamWithIndexesForApplications()
        {
            return null;
        }

        protected virtual string WriteServicesParams()
        {
            return WriteListParam("service", (from o in Service select o.Name).ToList(), true);
        }

        //CloneApplicationsToRule will be overridden in the derived class if the class needs specific clone implementation for applications
        //in this class the function empty because it doesn't handle with applications in services.
        protected virtual void CloneApplicationsToRule(CheckPoint_Rule newRule)
        {
            return;
        }

        //CompareApplications will be overridden in the derived class if the class needs specific compare implementation for applications
        //this function returns true so the CompareTo function won't be affected.
        protected virtual bool CompareApplications(CheckPoint_Rule other)
        {
            return true;
        }

        //IsApplicationsClean will be overridden in the derived class if the class needs specific check for cleanup rule
        ////this function returns true so the IsCleanupRule function won't be affected.
        protected virtual bool IsApplicationsClean()
        {
            return true;
        }
    }

    //In Check Point rules - both applications and services are part of "service" filed in the rule.
    //This class used for rules that contains applications in the services list.
    public class CheckPoint_RuleWithApplication : CheckPoint_Rule
    {
        //this is the vendor's responsibility to separate the applications from the services.
        public List<CheckPointObject> Application = new List<CheckPointObject>();

        //Since applications can include spaces and services can't, we first get services with safe names
        //and then applications without safe names with the right index so it will be continue the services indexing.
        protected override string WriteParamWithIndexesForApplications()
        {
            return WriteListParamWithIndexes("service", (from o in Application select o.Name).ToList(), false, Service.Count);
        }

        protected override string WriteServicesParams()
        {
            return WriteListParamWithIndexes("service", (from o in Service select o.Name).ToList(), true, 0);//add indexes to services in case applications present as well
        }

        //specific extension for cloning applications
        protected override void CloneApplicationsToRule(CheckPoint_Rule newRule)
        {
            if (newRule is CheckPoint_RuleWithApplication)
            {
                foreach (CheckPointObject obj in Application)
                {
                    ((CheckPoint_RuleWithApplication)newRule).Application.Add(obj);
                }
            }
        }

        //specific extension for comparing applications
        protected override bool CompareApplications(CheckPoint_Rule other)
        {
            if (other is CheckPoint_RuleWithApplication)
            {
                return CompareLists(Application, ((CheckPoint_RuleWithApplication)other).Application);
            }

            return false;
        }

        //specific extension to check if the applications list contains only ANY parameter.
        protected override bool IsApplicationsClean()
        {
            return (Application.Count == 1 && Application[0].Name == Any || Application.Count == 0);
        }

    }

    public class CheckPoint_Layer : CheckPointObject
    {
        public List<CheckPoint_Rule> Rules = new List<CheckPoint_Rule>();
        public bool ApplicationsAndUrlFiltering { get; set; }
        public bool Shared { get; set; }

        public override string ToCLIScript()
        {
            return "add access-layer " + WriteParam("name", Name, "") + WriteParam("comments", Comments, "")
                + WriteParam("add-default-rule", false, true)
                + WriteParam("applications-and-url-filtering", ApplicationsAndUrlFiltering, false)
                + WriteParam("shared", Shared, false)
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create layer [" + Name + "]";
        }
    }

    public class CheckPoint_NAT_Rule : CheckPointObject
    {
        public enum NatMethod { Static, Hide, Nat64, Nat46 };

        public bool Enabled { get; set; }
        public string Package { get; set; }
        public NatMethod Method { get; set; }
        public object VendorCustomData { get; set; }

        public CheckPointObject Source;
        public CheckPointObject Destination;
        public CheckPointObject Service;
        public CheckPointObject TranslatedSource;
        public CheckPointObject TranslatedDestination;
        public CheckPointObject TranslatedService;

        public List<string> Target = new List<string>();

        public CheckPoint_NAT_Rule()
        {
            Enabled = true;
        }

        public override string ToCLIScript()
        {
            return "add nat-rule " + WriteParam("package", Package, "")
                + WriteParam("original-source", (Source != null) ? Source.Name : "", "")
                + WriteParam("original-destination", (Destination != null) ? Destination.Name : "", "")
                + WriteParam("original-service", (Service != null) ? Service.Name : "", "")
                + WriteParam("translated-source", (TranslatedSource != null) ? TranslatedSource.Name : "", "")
                + WriteParam("translated-destination", (TranslatedDestination != null) ? TranslatedDestination.Name : "", "")
                + WriteParam("translated-service", (TranslatedService != null) ? TranslatedService.Name : "", "")
                + WriteParam("comments", Comments, "")
                + WriteParam("method", Method.ToString().ToLower(), "")
                + WriteParam("enabled", Enabled, true)
                + WriteParam("position", "top", "")
                + WriteListParam("install-on", (from o in Target select o).ToList(), true);

        }

        public override string ToCLIScriptInstruction()
        {
            return "";
        }

        public CheckPoint_NAT_Rule Clone()
        {
            var newRule = new CheckPoint_NAT_Rule();
            newRule.Name = Name;
            newRule.Comments = Comments;
            newRule.Enabled = Enabled;
            newRule.Method = Method;
            newRule.Source = Source;
            newRule.Destination = Destination;
            newRule.Service = Service;
            newRule.TranslatedSource = TranslatedSource;
            newRule.TranslatedDestination = TranslatedDestination;
            newRule.TranslatedService = TranslatedService;
            newRule.ConvertedCommandId = ConvertedCommandId;
            newRule.ConversionIncidentType = ConversionIncidentType;
            newRule.Target = Target;

            return newRule;
        }
    }

    public class CheckPoint_Package : CheckPointObject
    {
        public string NameOfAccessLayer
        {
            get { return Name + " Network"; }
        }

        public CheckPoint_Layer ParentLayer = new CheckPoint_Layer();
        public List<CheckPoint_Layer> SubPolicies = new List<CheckPoint_Layer>();

        public override string ToCLIScript()
        {
            return "add package " + WriteParam("name", Name, "")
                + WriteParam("threat-prevention", false, true)
                + WriteListParam("tags", Tags, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create package [" + Name + "]";
        }

        public int TotalRules()
        {
            int count = ParentLayer.Rules.Count();
            foreach (var layer in SubPolicies)
            {
                count += layer.Rules.Count();
            }
            return count;
        }
    }
}

