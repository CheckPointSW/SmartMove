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
        protected const string NameValidityRegex = @"[^A-Za-z0-9 _.-]";

        /// <summary>
        /// Regex: replace any char that is NOT any of the following to "_" char
        /// </summary>
        protected const string CommentsValidityRegex = @"[^A-Za-z0-9 @#*$(){}\[\]_.\-=:,/]";

        public const string Any = "any";

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

        public string Tag { get; set; }

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
            if (paramValues.Count == 0)
            {
                return "";
            }

            if (paramValues.Count == 1)
            {
                return WriteParam(paramName, paramValues[0], "");
            }

            string str = "";
            int i = 0;

            foreach (string paramValue in paramValues)
            {
                string val = paramValue;
                if (useSafeNames)
                {
                    val = GetSafeName(paramValue);
                }

                str += string.Format("{0}.{1} \"{2}\" ", paramName, i, val);
                i++;
            }

            return str;
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
            return "add security-zone " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "");
        }

        public override string ToCLIScriptInstruction()
        {
            return "create zone [" + Name + "]";
        }
    }

    public class CheckPoint_Domain : CheckPointObject
    {
        public string Fqdn { get; set; }

        public override string ToCLIScript()
        {
            return "add dns-domain " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("is-sub-domain", false, true);
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
                + WriteParam("ip-address", IpAddress, "");
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

        public override IPRanges GetIPRanges()
        {
            return new IPRanges(new IPRange(IPNetwork.Parse(Subnet, Netmask)));
        }

        public override string ToCLIScript()
        {
            return "add network " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("subnet", Subnet, "")
                + WriteParam("subnet-mask", Netmask , "");
        }

        public override string ToCLIScriptInstruction()
        {
            return "create network [" + Name + "]: subnet [" + Subnet + "] mask [" + Netmask + "]";
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
                + WriteParam("ipv4-address-last", RangeTo, "");
        }

        public override string ToCLIScriptInstruction()
        {
            return "create address range [" + Name + "]: from [" + RangeFrom + "] to [" + RangeTo + "]";
        }
    }

    public class CheckPoint_NetworkGroup : CheckPointObject
    {
        public List<string> Members = new List<string>();

        public override string ToCLIScript()
        {
            return "add group " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteListParam("members", Members, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create network group [" + Name + "]: " + Members.Count + " members";
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
                + WriteParam("except", Except, "");
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
                + WriteParam("ip-address", IpAddress, "");
        }

        public override string ToCLIScriptInstruction()
        {
            return "create simple gateway [" + Name + "] with ip-address [" + IpAddress + "]";
        }
    }

    public class CheckPoint_UdpService : CheckPointObject
    {
        public string Port { get; set; }
        public string SourePort { get; set; }
        public string SessionTimeout { get; set; }

        public override string ToCLIScript()
        {
            return "add service-udp " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("port", Port, "")
                + WriteParam("source-port", SourePort, "")
                + WriteParam("session-timeout", SessionTimeout, "0");
        }

        public override string ToCLIScriptInstruction()
        {
            return "create udp service [" + Name + "]: port [" + Port + "]";
        }
    }

    public class CheckPoint_TcpService : CheckPointObject
    {
        public string Port { get; set; }
        public string SourePort { get; set; }
        public string SessionTimeout { get; set; }

        public override string ToCLIScript()
        {
            return "add service-tcp " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("port", Port, "")
                + WriteParam("source-port", SourePort, "")
                + WriteParam("session-timeout", SessionTimeout, "0");
        }

        public override string ToCLIScriptInstruction()
        {
            return "create tcp service [" + Name + "]: port [" + Port + "]";
        }
    }

    public class CheckPoint_SctpService : CheckPointObject
    {
        public string Port { get; set; }
        public string SessionTimeout { get; set; }

        public override string ToCLIScript()
        {
            return "add service-sctp " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteParam("port", Port, "")
                + WriteParam("session-timeout", SessionTimeout, "0");
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
                + WriteParam("icmp-code", Code, "0");
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
                + WriteParam("program-number", ProgramNumber, "");
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
                + WriteParam("interface-uuid", InterfaceUuid, "");
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
                + WriteParam("match-for-any", true, false);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create other service [" + Name + "]: IP protocol [" + IpProtocol + "]";
        }
    }

    public class CheckPoint_ServiceGroup : CheckPointObject
    {
        public List<string> Members = new List<string>();

        public override string ToCLIScript()
        {
            return "add service-group " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "")
                + WriteListParam("members", Members, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create service group [" + Name + "]: " + Members.Count + " members";
        }
    }

    public class CheckPoint_TimeGroup : CheckPointObject
    {
        public override string ToCLIScript()
        {
            return "add time-group " + WriteParam("name", SafeName(), "") + WriteParam("comments", Comments, "");
        }

        public override string ToCLIScriptInstruction()
        {
            return "create time group [" + Name + "]";
        }
    }

    public class CheckPoint_Rule : CheckPointObject
    {
        public enum ActionType { Accept, Drop, SubPolicy };
        public enum TrackTypes { None, Log };

        public const string SubPolicyCleanupRuleName = "Sub-Policy Cleanup rule";

        public bool Enabled { get; set; }
        public string Layer { get; set; }
        public string SubPolicyName { get; set; }
        public ActionType Action { get; set; }
        public TrackTypes Track { get; set; }
        public bool SourceNegated { get; set; }
        public bool DestinationNegated { get; set; }

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
                case ActionType.SubPolicy:
                    actionName = "apply layer";
                    break;
            }

            return "add access-rule " + WriteParam("layer", Layer, "") + WriteParam("comments", Comments, "")
                + WriteListParam("source", (from o in Source select o.Name).ToList(), true)
                + WriteListParam("destination", (from o in Destination select o.Name).ToList(), true)
                + WriteListParam("service", (from o in Service select o.Name).ToList(), true)
                + WriteListParam("time", (from o in Time select o.Name).ToList(), true)
                + WriteParam("action", actionName, "")
                + WriteParam("track-settings.type", Track.ToString(), "")
                + WriteParam("enabled", Enabled, true)
                + WriteParam("source-negate", SourceNegated, false)
                + WriteParam("destination-negate", DestinationNegated, false)
                + WriteParam("position", "top", "")
                + WriteParam("inline-layer", SubPolicyName, "")
                + WriteParam("name", Name, "")
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

            foreach(CheckPointObject obj in Source)
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

            return newRule;
        }

        public bool IsCleanupRule()
        {
            if (!string.IsNullOrEmpty(Name) && Name == SubPolicyCleanupRuleName)
            {
                return true;   // sub-policy's automatic cleanup rule
            }

            if ((Source.Count == 1 && Source[0].Name == Any) &&
                (Destination.Count == 1 && Destination[0].Name == Any) &&
                (Service.Count == 1 && Service[0].Name == Any) &&
                (Action == ActionType.Drop))
            {
                return true;   // user defined cleanup rule
            }

            return false;
        }
    }

    public class CheckPoint_Layer : CheckPointObject
    {
        public List<CheckPoint_Rule> Rules = new List<CheckPoint_Rule>();

        public override string ToCLIScript()
        {
            return "add access-layer " + WriteParam("name", Name, "") + WriteParam("comments", Comments, "")
                + WriteParam("add-default-rule", false, true);
        }

        public override string ToCLIScriptInstruction()
        {
            return "create layer [" + Name + "]";
        }
    }

    public class CheckPoint_NAT_Rule : CheckPointObject
    {
        public enum NatMethod { Static, Hide };

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
                + WriteParam("translated-source", (TranslatedSource != null) ? TranslatedSource.Name :"", "")
                + WriteParam("translated-destination", (TranslatedDestination != null) ? TranslatedDestination.Name : "", "")
                + WriteParam("translated-service", (TranslatedService != null) ? TranslatedService.Name : "", "")
                + WriteParam("comments", Comments, "")
                + WriteParam("method", Method.ToString().ToLower(), "")
                + WriteParam("enabled", Enabled, true)
                + WriteParam("position", "top", "");
        }

        public override string ToCLIScriptInstruction()
        {
            return "";
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
                + WriteParam("threat-prevention", false, true);
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
