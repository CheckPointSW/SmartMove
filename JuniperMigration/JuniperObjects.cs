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
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using CommonUtils;

namespace JuniperMigration
{
    /// <summary>
    /// Represents a basic Juniper object.
    /// Parses the name and description fields for all objects.
    /// Each derived object auto-parses the appropriate configuration element for additional fields.
    /// </summary>
    public class JuniperObject
    {
        public const string GlobalZoneName = "global";
        public const string AccessManagementInterfaceName = "fxp0";
        public const string Any = "any";
        public const string AnyIPv4 = "any-ipv4";

        public string Name { get; set; }
        public string ZoneName { get; set; }
        public string Description { get; set; }
        public ConversionIncidentType ConversionIncidentType { get; set; }
        public string ConversionIncidentMessage { get; set; }
        public int LineNumber { get; set; }

        public JuniperObject()
        {
            Name = "";
            ZoneName = "";
            Description = "";
            LineNumber = 0;
        }

        public virtual void Parse(XElement objectNode, string zoneName)
        {
            if (objectNode == null)
            {
                throw new InvalidDataException("Invalid XML structure: cannot parse empty XML element");
            }

            LineNumber = ((IXmlLineInfo)objectNode).LineNumber;

            var nameNode = objectNode.Element("name");
            if (nameNode == null || string.IsNullOrEmpty(nameNode.Value))
            {
                throw new InvalidDataException(string.Format("Invalid XML structure - line {0}: cannot extract object name from XML element '{1}'", LineNumber, objectNode));
            }

            Name = nameNode.Value;
            ZoneName = string.IsNullOrEmpty(zoneName) ? GlobalZoneName : zoneName;

            var descNode = objectNode.Element("description");
            if (descNode != null && !string.IsNullOrEmpty(descNode.Value))
            {
                Description = descNode.Value;
            }
        }
    }

    public class Subnet
    {
        public string IpAddress { get; set; }
        public string Netmask { get; set; }
        
        public Subnet(string ipAddress, string netmask)
        {
            IpAddress = ipAddress;
            Netmask = netmask;
        }

        public bool IsHost()
        {
            return NetworkUtils.GetMaskLength(Netmask) == 32;
        }
    }

    public class Juniper_Fqdn : JuniperObject
    {
        public string DnsName { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var dnsNameNode = objectNode.Element("dns-name");
            if (dnsNameNode == null)
            {
                throw new InvalidDataException("Unexpected!!!");
            }

            var nameNode = dnsNameNode.Element("name");
            if (nameNode == null || string.IsNullOrEmpty(nameNode.Value))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing dns name for fqdn object.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }

            DnsName = nameNode.Value;
        }
    }

    public class Juniper_Host : JuniperObject
    {
        public string IpAddress { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var ipPrefixNode = objectNode.Element("ip-prefix");
            if (ipPrefixNode == null)
            {
                throw new InvalidDataException("Unexpected!!!");
            }

            string ipPrefixText = ipPrefixNode.Value;
            if (string.IsNullOrEmpty(ipPrefixText))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing IP address for host object. Using IP 1.1.1.1.";
                Console.WriteLine(ConversionIncidentMessage);
                IpAddress = "1.1.1.1";
                return;
            }

            int pos = ipPrefixText.IndexOf('/');
            IpAddress = (pos == -1) ? ipPrefixText : ipPrefixText.Substring(0, pos);

            if (!NetworkUtils.IsValidIpv4(IpAddress))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = string.Format("Invalid IP address '{0}' for host object. Using IP 1.1.1.1.", IpAddress);
                Console.WriteLine(ConversionIncidentMessage);
                IpAddress = "1.1.1.1";
            }
        }
    }

    public class Juniper_Network : JuniperObject
    {
        public string IpAddress { get; set; }
        public string Netmask { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var ipPrefixNode = objectNode.Element("ip-prefix");
            if (ipPrefixNode == null || string.IsNullOrEmpty(ipPrefixNode.Value) || ipPrefixNode.Value.IndexOf('/') == -1)
            {
                throw new InvalidDataException("Unexpected!!!");
            }

            string[] ipPrefixParts = ipPrefixNode.Value.Split('/');
            if (ipPrefixParts.Length != 2 || ipPrefixParts[1] == "32")
            {
                throw new InvalidDataException("Unexpected!!!");
            }

            IpAddress = ipPrefixParts[0];

            if (!NetworkUtils.IsValidIpv4(IpAddress))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = string.Format("Invalid IP address '{0}' for network object. Using subnet 1.1.1.0/255.255.255.0.", IpAddress);
                Console.WriteLine(ConversionIncidentMessage);
                IpAddress = "1.1.1.0";
                Netmask = "255.255.255.0";
                return;
            }

            // Wildcard netmask is NOT supported...
            if (ipPrefixParts[1].Contains("."))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = string.Format("Wildcard address is not supported: {0}. Using subnet 1.1.1.0/255.255.255.0.", ipPrefixNode.Value);
                Console.WriteLine(ConversionIncidentMessage);
                IpAddress = "1.1.1.0";
                Netmask = "255.255.255.0";
                return;
            }

            int netmask;
            int.TryParse(ipPrefixParts[1], out netmask);

            Netmask = NetworkUtils.MaskLength2Netmask(netmask);
        }
    }

    public class Juniper_Range : JuniperObject
    {
        public string RangeFrom { get; set; }
        public string RangeTo { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var rengeAddressNode = objectNode.Element("range-address");
            if (rengeAddressNode == null)
            {
                throw new InvalidDataException("Unexpected!!!");
            }

            var fromNode = rengeAddressNode.Element("name");
            if (fromNode == null || string.IsNullOrEmpty(fromNode.Value))
            {
                RangeFrom = "0.0.0.0";
            }
            else
            {
                RangeFrom = fromNode.Value;

                if (!NetworkUtils.IsValidIpv4(RangeFrom))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid starting IP range '{0}' for range object. Using IP 0.0.0.0.", RangeFrom);
                    Console.WriteLine(ConversionIncidentMessage);
                    RangeFrom = "0.0.0.0";
                }
            }

            var toNode = rengeAddressNode.XPathSelectElement("./to/range-high");
            if (toNode == null || string.IsNullOrEmpty(toNode.Value))
            {
                RangeTo = "255.255.255.255";
            }
            else
            {
                RangeTo = toNode.Value;

                if (!NetworkUtils.IsValidIpv4(RangeTo))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid ending IP range '{0}' for range object. Using IP 255.255.255.255.", RangeTo);
                    Console.WriteLine(ConversionIncidentMessage);
                    RangeTo = "255.255.255.255";
                }
            }
        }
    }

    public class Juniper_AddressGroup : JuniperObject
    {
        public List<string> Members = new List<string>();
        public List<string> MemberGroupNames = new List<string>();

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var nameNodes = objectNode.XPathSelectElements("./address/name");
            foreach (var nameNode in nameNodes)
            {
                if (!string.IsNullOrEmpty(nameNode.Value))
                {
                    Members.Add(nameNode.Value);
                }
            }

            nameNodes = objectNode.XPathSelectElements("./address-set/name");
            foreach (var nameNode in nameNodes)
            {
                if (!string.IsNullOrEmpty(nameNode.Value))
                {
                    MemberGroupNames.Add(nameNode.Value);
                }
            }
        }
    }

    public class Juniper_Zone : JuniperObject
    {
        public List<string> Interfaces = new List<string>();
        public bool LeadsToInternet { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var interfaceNodes = objectNode.XPathSelectElements("./interfaces/name");
            foreach (var interfaceNode in interfaceNodes)
            {
                Interfaces.Add(interfaceNode.Value);
            }
        }
    }

    public class Juniper_Interface : JuniperObject
    {
        public List<Subnet> Topology = new List<Subnet>();
        public List<Subnet> Routes = new List<Subnet>();
        public string MainIpAddress { get; set; }
        public bool LeadsToInternet { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            string primaryIpAddress = "", preferredIpAddress = "", firstpAddress = "";

            var addressNodes = objectNode.XPathSelectElements("./family/inet/address");
            foreach (var addressNode in addressNodes)
            {
                var ipNode = addressNode.Element("name");
                if (ipNode == null || string.IsNullOrEmpty(ipNode.Value))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = "Missing IPv4 address for interface object.";
                    Console.WriteLine(ConversionIncidentMessage);
                    continue;
                }

                string[] ipInfo = ipNode.Value.Split('/');
                if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for interface object.", ipNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                    continue;
                }

                string sIp = ipInfo[0];

                int netmask;
                int.TryParse(ipInfo[1], out netmask);
                string sNetmask = NetworkUtils.MaskLength2Netmask(netmask);

                if (addressNode.Element("primary") != null)
                {
                    primaryIpAddress = sIp;
                }
                else if (addressNode.Element("preferred") != null)
                {
                    preferredIpAddress = sIp;
                }

                if (string.IsNullOrEmpty(firstpAddress))
                {
                    firstpAddress = sIp;
                }

                Topology.Add(new Subnet(NetworkUtils.GetNetwork(sIp, sNetmask), sNetmask));
            }

            if (!string.IsNullOrEmpty(primaryIpAddress))
            {
                MainIpAddress = primaryIpAddress;
            }
            else if (!string.IsNullOrEmpty(preferredIpAddress))
            {
                MainIpAddress = preferredIpAddress;
            }
            else if (!string.IsNullOrEmpty(firstpAddress))
            {
                MainIpAddress = firstpAddress;
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = string.Format("Cannot resolve primary nor preferred IP address for interface object. Using a first IP address as a main address.");
                Console.WriteLine(ConversionIncidentMessage);
            }
            else
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = string.Format("Cannot resolve a main IP address for interface object.");
                Console.WriteLine(ConversionIncidentMessage);
            }
        }
    }

    public class Juniper_Route : JuniperObject
    {
        public string IpAddress { get; set; }
        public string Netmask { get; set; }
        public string NextHop { get; set; }
        public string InterfaceName { get; set; }
        public bool DefaultRoute { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var ipNode = objectNode.Element("name");
            if (ipNode == null || string.IsNullOrEmpty(ipNode.Value))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing IPv4 address for route object. Using IP 1.1.1.1.";
                Console.WriteLine(ConversionIncidentMessage);
                IpAddress = "1.1.1.1";
                Netmask = "255.255.255.255";
                return;
            }

            string[] ipInfo = ipNode.Value.Split('/');
            if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for route object. Using IP 1.1.1.1.", ipNode.Value);
                Console.WriteLine(ConversionIncidentMessage);
                IpAddress = "1.1.1.1";
                Netmask = "255.255.255.255";
                return;
            }

            var nextHopNode = objectNode.Element("next-hop");
            var qualifiedNextHopNode = objectNode.XPathSelectElement("qualified-next-hop/name");
            string nextHopAddress;

            if (nextHopNode != null)
            {
                if (!string.IsNullOrEmpty(nextHopNode.Value) && NetworkUtils.IsValidIpv4(nextHopNode.Value))
                {
                    nextHopAddress = nextHopNode.Value;
                }
                else
                {
                    ConversionIncidentType = ConversionIncidentType.Informative;
                    ConversionIncidentMessage = string.Format("Invalid next hop '{0}' for route object.", nextHopNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                    return;
                }
            }
            else if (qualifiedNextHopNode != null)
            {
                if (!string.IsNullOrEmpty(qualifiedNextHopNode.Value) && NetworkUtils.IsValidIpv4(qualifiedNextHopNode.Value))
                {
                    nextHopAddress = qualifiedNextHopNode.Value;
                }
                else
                {
                    ConversionIncidentType = ConversionIncidentType.Informative;
                    ConversionIncidentMessage = string.Format("Invalid qualified next hop '{0}' for route object.", qualifiedNextHopNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                    return;
                }
            }
            else
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "Missing next hop address for route object.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }

            int netmask;
            int.TryParse(ipInfo[1], out netmask);

            IpAddress = ipInfo[0];
            Netmask = NetworkUtils.MaskLength2Netmask(netmask);
            NextHop = nextHopAddress;

            if (IpAddress == "0.0.0.0" && Netmask == "0.0.0.0")
            {
                DefaultRoute = true;
            }
        }
    }

    public class Juniper_Application : JuniperObject
    {
        public const string TemporaryTermName = "_APPLICATION_TERM_";

        public bool IsJunosDefault { get; set; }
        public bool IsFromTerm { get; set; }
        public string Protocol { get; set; }
        public string Port { get; set; }
        public string IcmpType { get; set; }
        public string IcmpCode { get; set; }
        public string ProgramNumber { get; set; }
        public string InterfaceUuid { get; set; }
        public int InactivityTimeout { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);
            IsJunosDefault = Name.StartsWith("junos-");

            ParseInternal(objectNode, false);
        }

        public void ParseFromTerm(XElement objectNode, bool autoGenerateName)
        {
            ParseInternal(objectNode, autoGenerateName);
        }

        /// <summary>
        /// If the autoGenerateName parameter is true, then the Name is empty at this point.
        /// </summary>
        private void ParseInternal(XElement objectNode, bool autoGenerateName)
        {
            if (objectNode == null)
            {
                return;
            }

            if (autoGenerateName)
            {
                IsFromTerm = true;
                Name = TemporaryTermName + LineNumber;
            }

            var protocolNode = objectNode.Element("protocol");
            if (protocolNode == null || string.IsNullOrEmpty(protocolNode.Value))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing protocol for application object.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }

            Protocol = JuniperKnownApplications.ConvertProtocolOrPortNumberToName(protocolNode.Value);

            XElement portNode, timeoutNode;

            switch (Protocol)
            {
                case "tcp":
                case "udp":
                    var rpcNode = objectNode.Element("rpc-program-number");
                    if (rpcNode != null && !string.IsNullOrEmpty(rpcNode.Value))
                    {
                        ProgramNumber = rpcNode.Value;
                        break;
                    }

                    var uuidNode = objectNode.Element("uuid");
                    if (uuidNode != null && !string.IsNullOrEmpty(uuidNode.Value))
                    {
                        InterfaceUuid = uuidNode.Value;
                        break;
                    }

                    portNode = objectNode.Element("destination-port");
                    if (portNode == null || string.IsNullOrEmpty(portNode.Value))
                    {
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = "Missing destination port for application object.";
                        Console.WriteLine(ConversionIncidentMessage);
                        return;
                    }

                    Port = JuniperKnownApplications.ConvertProtocolOrPortNameToNumber(portNode.Value);

                    if (autoGenerateName)
                    {
                        Name = Protocol + "_" + Port;
                    }

                    var sourcePortNode = objectNode.Element("source-port");
                    if (sourcePortNode != null && !string.IsNullOrEmpty(sourcePortNode.Value))
                    {
                        ConversionIncidentType = ConversionIncidentType.Informative;
                        ConversionIncidentMessage = string.Format("Cannot convert an application defined as both source port and destination port. Ignoring source port '{0}'.", sourcePortNode.Value);
                    }

                    timeoutNode = objectNode.Element("inactivity-timeout");
                    ParseInactivityTimeout(timeoutNode);
                    break;

                case "sctp":
                    portNode = objectNode.Element("destination-port");
                    if (portNode == null || string.IsNullOrEmpty(portNode.Value) || portNode.Value == "0")
                    {
                        Port = Any;
                    }
                    else
                    {
                        Port = JuniperKnownApplications.ConvertProtocolOrPortNameToNumber(portNode.Value);
                    }

                    if (autoGenerateName)
                    {
                        Name = Protocol + "_" + Port;
                    }

                    timeoutNode = objectNode.Element("inactivity-timeout");
                    ParseInactivityTimeout(timeoutNode);
                    break;

                case "icmp":
                    var icmpTypeNode = objectNode.Element("icmp-type");
                    if (icmpTypeNode == null || string.IsNullOrEmpty(icmpTypeNode.Value))
                    {
                        IcmpType = "99";   // will be converted to generic icmp-proto!!!
                    }
                    else
                    {
                        IcmpType = JuniperKnownApplications.ConvertIcmpNameToType(icmpTypeNode.Value);
                    }

                    var icmpCodeNode = objectNode.Element("icmp-code");
                    if (icmpCodeNode != null && !string.IsNullOrEmpty(icmpCodeNode.Value))
                    {
                        IcmpCode = JuniperKnownApplications.ConvertIcmpNameToCode(icmpCodeNode.Value);
                    }

                    if (autoGenerateName)
                    {
                        Name = Protocol + "_" + IcmpType + (string.IsNullOrEmpty(IcmpCode) ? "" : "_" + IcmpCode);
                    }
                    break;

                default:
                    // General IP protocol name or number:
                    // In this case, the 'Protocol' will always hold the name, and the 'Port' will hold the number.
                    string protocolName;
                    if (JuniperKnownApplications.IsKnownProtocolOrPortName(Protocol))
                    {
                        Port = JuniperKnownApplications.ConvertProtocolOrPortNameToNumber(Protocol);
                    }
                    else if (JuniperKnownApplications.IsKnownProtocolOrPortNumber(Protocol, out protocolName))   // protocol number is used!!!
                    {
                        Port = Protocol;
                        Protocol = protocolName;
                    }
                    else
                    {
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = string.Format("Unrecognized protocol '{0}' for application object.", Protocol);
                        Console.WriteLine(ConversionIncidentMessage);
                    }
                    break;
            }
        }

        private void ParseInactivityTimeout(XElement timeoutNode)
        {
            if (timeoutNode != null && !string.IsNullOrEmpty(timeoutNode.Value))
            {
                string timeout = timeoutNode.Value;
                if (timeout == "never")
                {
                    ConversionIncidentType = ConversionIncidentType.Informative;
                    ConversionIncidentMessage = "Application 'inactivity-timeout' value 'never' is not supported. Using a maximum value '86400' instead.";
                    InactivityTimeout = 86400;
                }
                else
                {
                    int inactivityTimeout;
                    if (int.TryParse(timeout, out inactivityTimeout))
                    {
                        if (inactivityTimeout > 86400)
                        {
                            ConversionIncidentType = ConversionIncidentType.Informative;
                            ConversionIncidentMessage = "Application 'inactivity-timeout' value greater than '86400' is not supported. Using a maximum value '86400' instead.";
                            inactivityTimeout = 86400;
                        }

                        InactivityTimeout = inactivityTimeout;
                    }
                    else
                    {
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = string.Format("Invalid inactivity-timeout '{0}' for application object.", timeout);
                        Console.WriteLine(ConversionIncidentMessage);
                    }
                }
            }
        }
    }

    public class Juniper_ApplicationGroup : JuniperObject
    {
        public bool IsJunosDefault { get; set; }
        public List<string> Members = new List<string>();
        public List<string> MemberGroupNames = new List<string>();

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            IsJunosDefault = Name.StartsWith("junos-");

            var nameNodes = objectNode.XPathSelectElements("./application/name");
            foreach (var nameNode in nameNodes)
            {
                if (!string.IsNullOrEmpty(nameNode.Value))
                {
                    Members.Add(nameNode.Value);
                }
            }

            nameNodes = objectNode.XPathSelectElements("./application-set/name");
            foreach (var nameNode in nameNodes)
            {
                if (!string.IsNullOrEmpty(nameNode.Value))
                {
                    MemberGroupNames.Add(nameNode.Value);
                }
            }
        }
    }
	
    public class Juniper_Scheduler : JuniperObject
    {        
        public List<string> StartStopDates = new List<string>();

        public Dictionary<string, List<string>> patternDictionary = new Dictionary<string, List<string>>();               
        
        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);            

            var startDates = objectNode.Elements("start-date").ToList();
                       
            if (startDates.Count > 0)
            {                
                List<string> startStop = new List<string>();
                string startStopDateString;
                foreach (var startDate in startDates)
                {
                    startStopDateString = startDate.Element("start-date").Value + ";" + startDate.Element("stop-date").Value;                 
                    StartStopDates.Add(startStopDateString);
                }
            }
            
            List<string> days = new List<string> { "daily", "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday" };            

            foreach (string dayKey in days)
            {
                List<string> daysValue = new List<string>();
                var day = objectNode.Element(dayKey);
                if (day != null)
                {
                    if (day.Element("all-day") != null)
                    {                        
                        daysValue.Add("all-day");                        
                    }
                    else if (day.Element("exclude") != null)
                    {                        
                        daysValue.Add("exclude");                        
                    }
                    else if (day.Elements("start-time").ToList() != null)
                    {
                        List<string> startStopTime = new List<string>();
                        string startStopTimeString;
                        foreach (var startTime in day.Elements("start-time").ToList())
                        {
                            startStopTimeString = startTime.Element("start-time-value").Value + ";" + startTime.Element("stop-time").Value;
                            startStopTime.Add(startStopTimeString);
                        }                                        
                        daysValue.AddRange(startStopTime);                        
                    }
                    patternDictionary.Add(dayKey, daysValue);
                }
            }      
        }
    }

    public class Juniper_PolicyRule : JuniperObject
    {
        public enum ActionType { NA, Deny, Reject, Permit };

        public bool Inactive { get; set; }
        public List<string> Sources = new List<string>();
        public List<string> Destinations = new List<string>();
        public List<string> Applications = new List<string>();
        public bool SourceNegate { get; set; }
        public bool DestinationNegate { get; set; }
        public bool Log { get; set; }
        public ActionType Action { get; set; }
        public List<string> Scheduler = new List<string>();


        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var matchNode = objectNode.Element("match");
            if (matchNode == null)
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing match information for policy rule object.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }

            var actionNode = objectNode.Element("then");
            if (actionNode == null)
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing action information for policy rule object.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }
			
            //add scheduler
            var schedulerNode = objectNode.Elements("scheduler-name");

            if (schedulerNode != null)
            {
                foreach (var scheduler in schedulerNode) { 
                Scheduler.Add(scheduler.Value);                
                }
            }

            var inactiveAttribute = objectNode.Attribute("inactive");
            if (inactiveAttribute != null && inactiveAttribute.Value == "inactive")
            {
                Inactive = true;
            }

            var sourceNodes = matchNode.Elements("source-address");
            foreach (var sourceNode in sourceNodes)
            {
                Sources.Add(sourceNode.Value);
            }

            var destNodes = matchNode.Elements("destination-address");
            foreach (var destNode in destNodes)
            {
                Destinations.Add(destNode.Value);
            }

            var applicationNodes = matchNode.Elements("application");
            foreach (var applicationNode in applicationNodes)
            {
                Applications.Add(applicationNode.Value);
            }

            if (matchNode.Element("source-address-excluded") != null)
            {
                SourceNegate = true;
            }

            if (matchNode.Element("destination-address-excluded") != null)
            {
                DestinationNegate = true;
            }

            if (actionNode.Element("log") != null)
            {
                Log = true;
            }

            if (actionNode.Element("deny") != null)
            {
                Action = ActionType.Deny;
            }
            else if (actionNode.Element("reject") != null)
            {
                Action = ActionType.Reject;
            }
            else if (actionNode.Element("permit") != null)
            {
                Action = ActionType.Permit;
            }
        }
    }

    public class Juniper_GlobalPolicyRule : Juniper_PolicyRule
    {
        public const string DefaultActionRuleName = "Default action rule";

        public List<string> SourceZones = new List<string>();
        public List<string> DestinationZones = new List<string>();

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, null);

            var sourceZoneNodes = objectNode.XPathSelectElements("match/from-zone");
            foreach (var sourceZoneNode in sourceZoneNodes)
            {
                SourceZones.Add(sourceZoneNode.Value);
            }

            var destZoneNodes = objectNode.XPathSelectElements("match/to-zone");
            foreach (var destZoneNode in destZoneNodes)
            {
                DestinationZones.Add(destZoneNode.Value);
            }

            // Pure global rule - no zone is specified...
            if (SourceZones.Count == 0 && DestinationZones.Count == 0)
            {
                SourceZones.Add(Any);
                DestinationZones.Add(Any);
            }
        }

        public void GenerateDefaultActionRule(ActionType defaultAction)
        {
            Name = DefaultActionRuleName;
            SourceZones.Add(Any);
            DestinationZones.Add(Any);
            Action = defaultAction;
            Log = true;
        }
    }

    public class Juniper_ZonePolicy : JuniperObject
    {
        public string SourceZone { get; set; }
        public string DestinationZone { get; set; }
        public bool IsManagementAccessPolicy { get; set; }

        public List<Juniper_PolicyRule> Rules = new List<Juniper_PolicyRule>();

        public override void Parse(XElement objectNode, string zoneName)
        {
            // No need to call the base class parser, there are no Name neither Description fields.
            LineNumber = ((IXmlLineInfo)objectNode).LineNumber;

            var sourceZoneNode = objectNode.Element("from-zone-name");
            if (sourceZoneNode == null)
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing source zone name for policy object.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }

            var destZoneNode = objectNode.Element("to-zone-name");
            if (destZoneNode == null)
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing destination zone name for policy object.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }

            SourceZone = sourceZoneNode.Value;
            DestinationZone = destZoneNode.Value;

            IsManagementAccessPolicy = (DestinationZone == "junos-host");
        }
    }

    public class Juniper_NatPool : JuniperObject
    {
        public class PoolAddress
        {
            public enum NetworkType { None, Host, Subnet, Range };

            public string IpAddress { get; set; }
            public string Netmask { get; set; }
            public string RangeTo { get; set; }
            public NetworkType AddressType { get; set; }
        }

        protected PoolAddress ParseAddress(XElement addressNode, bool isSourceNat)
        {
            var ipNode = addressNode.Element(isSourceNat ? "name" : "ipaddr");
            if (ipNode == null || string.IsNullOrEmpty(ipNode.Value))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing IPv4 address for NAT pool object.";
                Console.WriteLine(ConversionIncidentMessage);
                return null;
            }

            string[] ipInfo = ipNode.Value.Split('/');
            if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for NAT pool object.", ipNode.Value);
                Console.WriteLine(ConversionIncidentMessage);
                return null;
            }

            var address = new PoolAddress { IpAddress = ipInfo[0] };

            int netmask;
            int.TryParse(ipInfo[1], out netmask);

            if (netmask == 32)
            {
                address.AddressType = PoolAddress.NetworkType.Host;
                // Do NOT quit here, check for range type option below...
            }
            else
            {
                address.Netmask = NetworkUtils.MaskLength2Netmask(netmask);
                address.AddressType = PoolAddress.NetworkType.Subnet;
                return address;
            }

            var rangeToNode = addressNode.XPathSelectElement("./to/ipaddr");
            if (rangeToNode != null)
            {
                address.AddressType = PoolAddress.NetworkType.Range;

                if (string.IsNullOrEmpty(rangeToNode.Value) || rangeToNode.Value.IndexOf('/') == -1)
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid ending IP range '{0}' for destination NAT pool object. Using IP 255.255.255.255.", rangeToNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                    address.RangeTo = "255.255.255.255";
                }
                else
                {
                    string[] rangeToInfo = rangeToNode.Value.Split('/');
                    if (rangeToInfo.Length != 2 || !NetworkUtils.IsValidIpv4(rangeToInfo[0]) || rangeToInfo[1] != "32")
                    {
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = string.Format("Invalid ending IP range '{0}' for destination NAT pool object. Using IP 255.255.255.255.", rangeToNode.Value);
                        Console.WriteLine(ConversionIncidentMessage);
                        address.RangeTo = "255.255.255.255";
                    }
                    else
                    {
                        address.RangeTo = rangeToInfo[0];
                    }
                }
            }

            return address;
        }
    }

    public class Juniper_SourceNatPool : Juniper_NatPool
    {
        public List<PoolAddress> Addresses = new List<PoolAddress>();
        public string HostAddressBase { get; set; }
        public bool TranslatePort { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var addressNodes = objectNode.Elements("address");
            foreach (var addressNode in addressNodes)
            {
                var address = ParseAddress(addressNode, true);
                if (address != null)
                {
                    Addresses.Add(address);
                }
            }

            var hostAddressBaseNode = objectNode.XPathSelectElement("./host-address-base/ipaddr");
            if (hostAddressBaseNode != null && !string.IsNullOrEmpty(hostAddressBaseNode.Value))
            {
                string[] ipInfo = hostAddressBaseNode.Value.Split('/');
                if (ipInfo.Length == 2 && NetworkUtils.IsValidIpv4(ipInfo[0]))
                {
                    HostAddressBase = ipInfo[0];
                }
                else
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for source NAT pool's host address object.", hostAddressBaseNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                }
            }

            TranslatePort = true;

            var portNode = objectNode.Element("port");
            if (portNode != null)
            {
                if (portNode.Element("no-translation") != null)
                {
                    TranslatePort = false;
                }
            }
        }
    }

    public class Juniper_DestinationNatPool : Juniper_NatPool
    {
        public PoolAddress Address { get; set; }
        public string Port { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var addressNode = objectNode.Element("address");
            if (addressNode != null)
            {
                Address = ParseAddress(addressNode, false);

                var portNode = addressNode.Element("port");
                if (portNode != null && !string.IsNullOrEmpty(portNode.Value))
                {
                    Port = portNode.Value;
                }
            }
        }
    }

    public class Juniper_NatRule : JuniperObject
    {
        public bool Inactive { get; set; }
        public bool NoMatchInfo { get; set; }
        public bool NoActionInfo { get; set; }
        public List<string> SourceAddressNames = new List<string>();
        public List<Subnet> SourceAddresses = new List<Subnet>();
        public List<string> SourcePorts = new List<string>();
        public List<string> DestinationAddressNames = new List<string>();
        public List<Subnet> DestinationAddresses = new List<Subnet>();
        public List<string> DestinationPorts = new List<string>();
    }

    public class Juniper_SourceNatRule : Juniper_NatRule
    {
        public enum SourceTranslationMode { None, Interface, Pool };

        public List<string> Applications = new List<string>();
        public List<string> Protocols = new List<string>();
        public SourceTranslationMode TranslationMode { get; set; }
        public string TranslatedSource { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var matchNode = objectNode.Element("src-nat-rule-match");
            if (matchNode == null)
            {
                NoMatchInfo = true;
                return;
            }

            var actionNode = objectNode.XPathSelectElement("./then/source-nat");
            if (actionNode == null)
            {
                NoActionInfo = true;
                return;
            }

            var inactiveAttribute = objectNode.Attribute("inactive");
            if (inactiveAttribute != null && inactiveAttribute.Value == "inactive")
            {
                Inactive = true;
            }

            var sourceAddressNameNodes = matchNode.Elements("source-address-name");
            foreach (var sourceAddressNameNode in sourceAddressNameNodes)
            {
                SourceAddressNames.Add(sourceAddressNameNode.Value);
            }

            var sourceAddressNodes = matchNode.Elements("source-address");
            foreach (var sourceAddressNode in sourceAddressNodes)
            {
                string[] ipInfo = sourceAddressNode.Value.Split('/');
                if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for source NAT rule's source address object.", sourceAddressNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                }
                else
                {
                    int netmask;
                    int.TryParse(ipInfo[1], out netmask);

                    SourceAddresses.Add(new Subnet(ipInfo[0], NetworkUtils.MaskLength2Netmask(netmask)));
                }
            }

            var sourcePortNodes = matchNode.XPathSelectElements("./source-port/name");
            foreach (var sourcePortNode in sourcePortNodes)
            {
                SourcePorts.Add(sourcePortNode.Value);
            }

            var destAddressNameNodes = matchNode.Elements("destination-address-name");
            foreach (var destAddressNameNode in destAddressNameNodes)
            {
                DestinationAddressNames.Add(destAddressNameNode.Value);
            }

            var destAddressNodes = matchNode.Elements("destination-address");
            foreach (var destAddressNode in destAddressNodes)
            {
                string[] ipInfo = destAddressNode.Value.Split('/');
                if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for source NAT rule's destination address object.", destAddressNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                }
                else
                {
                    int netmask;
                    int.TryParse(ipInfo[1], out netmask);

                    DestinationAddresses.Add(new Subnet(ipInfo[0], NetworkUtils.MaskLength2Netmask(netmask)));
                }
            }

            var destPortNodes = matchNode.XPathSelectElements("./destination-port/name");
            foreach (var destPortNode in destPortNodes)
            {
                DestinationPorts.Add(destPortNode.Value);
            }

            var applicationNodes = matchNode.Elements("application");
            foreach (var applicationNode in applicationNodes)
            {
                Applications.Add(applicationNode.Value);
            }

            var protocolNodes = matchNode.Elements("protocol");
            foreach (var protocolNode in protocolNodes)
            {
                Protocols.Add(protocolNode.Value);
            }

            if (actionNode.Element("off") != null)
            {
                TranslationMode = SourceTranslationMode.None;
            }
            else if (actionNode.Element("interface") != null)
            {
                TranslationMode = SourceTranslationMode.Interface;
            }
            else
            {
                TranslationMode = SourceTranslationMode.Pool;

                var poolNode = actionNode.XPathSelectElement("./pool/pool-name");
                if (poolNode != null && !string.IsNullOrEmpty(poolNode.Value))
                {
                    TranslatedSource = poolNode.Value;
                }
            }
        }
    }

    public class Juniper_DestinationNatRule : Juniper_NatRule
    {
        public List<string> Applications = new List<string>();
        public List<string> Protocols = new List<string>();
        public bool TranslateDestination { get; set; }
        public string TranslatedDestination { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var matchNode = objectNode.Element("dest-nat-rule-match");
            if (matchNode == null)
            {
                NoMatchInfo = true;
                return;
            }

            var actionNode = objectNode.XPathSelectElement("./then/destination-nat");
            if (actionNode == null)
            {
                NoActionInfo = true;
                return;
            }

            var inactiveAttribute = objectNode.Attribute("inactive");
            if (inactiveAttribute != null && inactiveAttribute.Value == "inactive")
            {
                Inactive = true;
            }

            var sourceAddressNameNodes = matchNode.Elements("source-address-name");
            foreach (var sourceAddressNameNode in sourceAddressNameNodes)
            {
                SourceAddressNames.Add(sourceAddressNameNode.Value);
            }

            var sourceAddressNodes = matchNode.Elements("source-address");
            foreach (var sourceAddressNode in sourceAddressNodes)
            {
                string[] ipInfo = sourceAddressNode.Value.Split('/');
                if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for destination NAT rule's source address object.", sourceAddressNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                }
                else
                {
                    int netmask;
                    int.TryParse(ipInfo[1], out netmask);

                    SourceAddresses.Add(new Subnet(ipInfo[0], NetworkUtils.MaskLength2Netmask(netmask)));
                }
            }

            var destAddressNameNodes = matchNode.XPathSelectElements("./destination-address-name/dst-addr-name");
            foreach (var destAddressNameNode in destAddressNameNodes)
            {
                DestinationAddressNames.Add(destAddressNameNode.Value);
            }

            var destAddressNodes = matchNode.XPathSelectElements("./destination-address/dst-addr");
            foreach (var destAddressNode in destAddressNodes)
            {
                string[] ipInfo = destAddressNode.Value.Split('/');
                if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for destination NAT rule's destination address object.", destAddressNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                }
                else
                {
                    int netmask;
                    int.TryParse(ipInfo[1], out netmask);

                    DestinationAddresses.Add(new Subnet(ipInfo[0], NetworkUtils.MaskLength2Netmask(netmask)));
                }
            }

            var destPortNodes = matchNode.XPathSelectElements("./destination-port/name");
            foreach (var destPortNode in destPortNodes)
            {
                DestinationPorts.Add(destPortNode.Value);
            }

            var applicationNodes = matchNode.Elements("application");
            foreach (var applicationNode in applicationNodes)
            {
                Applications.Add(applicationNode.Value);
            }

            var protocolNodes = matchNode.Elements("protocol");
            foreach (var protocolNode in protocolNodes)
            {
                Protocols.Add(protocolNode.Value);
            }

            if (actionNode.Element("off") != null)
            {
                TranslateDestination = false;
            }
            else
            {
                TranslateDestination = true;

                var poolNode = actionNode.XPathSelectElement("./pool/pool-name");
                if (poolNode != null && !string.IsNullOrEmpty(poolNode.Value))
                {
                    TranslatedDestination = poolNode.Value;
                }
            }
        }
    }

    public class Juniper_StaticNatRule : Juniper_NatRule
    {
        public Subnet TranslatedDestination { get; set; }
        public string TranslatedDestinationName { get; set; }
        public string TranslatedPort { get; set; }

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            var matchNode = objectNode.Element("static-nat-rule-match");
            if (matchNode == null)
            {
                NoMatchInfo = true;
                return;
            }

            var actionNode = objectNode.XPathSelectElement("./then/static-nat");
            if (actionNode == null)
            {
                NoActionInfo = true;
                return;
            }

            var inactiveAttribute = objectNode.Attribute("inactive");
            if (inactiveAttribute != null && inactiveAttribute.Value == "inactive")
            {
                Inactive = true;
            }

            var sourceAddressNameNodes = matchNode.Elements("source-address-name");
            foreach (var sourceAddressNameNode in sourceAddressNameNodes)
            {
                SourceAddressNames.Add(sourceAddressNameNode.Value);
            }

            var sourceAddressNodes = matchNode.Elements("source-address");
            foreach (var sourceAddressNode in sourceAddressNodes)
            {
                string[] ipInfo = sourceAddressNode.Value.Split('/');
                if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for static NAT rule's source address object.", sourceAddressNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                }
                else
                {
                    int netmask;
                    int.TryParse(ipInfo[1], out netmask);

                    SourceAddresses.Add(new Subnet(ipInfo[0], NetworkUtils.MaskLength2Netmask(netmask)));
                }
            }

            var sourcePortNodes = matchNode.Elements("source-port");
            foreach (var sourcePortNode in sourcePortNodes)
            {
                string port = ParsePort(sourcePortNode);
                if (!string.IsNullOrEmpty(port))
                {
                    SourcePorts.Add(port);
                }
            }

            var destAddressNameNodes = matchNode.XPathSelectElements("./destination-address-name/dst-addr-name");
            foreach (var destAddressNameNode in destAddressNameNodes)
            {
                DestinationAddressNames.Add(destAddressNameNode.Value);
            }

            var destAddressNodes = matchNode.XPathSelectElements("./destination-address/dst-addr");
            foreach (var destAddressNode in destAddressNodes)
            {
                string[] ipInfo = destAddressNode.Value.Split('/');
                if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for static NAT rule's destination address object.", destAddressNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                }
                else
                {
                    int netmask;
                    int.TryParse(ipInfo[1], out netmask);

                    DestinationAddresses.Add(new Subnet(ipInfo[0], NetworkUtils.MaskLength2Netmask(netmask)));
                }
            }

            var destPortNodes = matchNode.Elements("destination-port");
            foreach (var destPortNode in destPortNodes)
            {
                string port = ParsePort(destPortNode);
                if (!string.IsNullOrEmpty(port))
                {
                    DestinationPorts.Add(port);
                }
            }

            var prefixNode = actionNode.XPathSelectElement("./prefix/addr-prefix");
            if (prefixNode != null)
            {
                string[] ipInfo = prefixNode.Value.Split('/');
                if (ipInfo.Length != 2 || !NetworkUtils.IsValidIpv4(ipInfo[0]))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = string.Format("Invalid IPv4 address '{0}' for static NAT rule's prefix object.", prefixNode.Value);
                    Console.WriteLine(ConversionIncidentMessage);
                }
                else
                {
                    int netmask;
                    int.TryParse(ipInfo[1], out netmask);

                    TranslatedDestination = new Subnet(ipInfo[0], NetworkUtils.MaskLength2Netmask(netmask));
                }
            }
            else
            {
                prefixNode = actionNode.XPathSelectElement("./prefix-name/addr-prefix-name");
                if (prefixNode != null)
                {
                    TranslatedDestinationName = prefixNode.Value;
                }
            }

            if (prefixNode != null)
            {
                var portNode = prefixNode.Element("mapped-port");
                if (portNode != null)
                {
                    TranslatedPort = ParsePort(portNode);
                }
            }
        }

        private string ParsePort(XElement portNode)
        {
            string port = "";

            var lowNode = portNode.Element("low");
            if (lowNode != null && !string.IsNullOrEmpty(lowNode.Value))
            {
                port = lowNode.Value;
            }

            var highNode = portNode.XPathSelectElement("./to/high");
            if (highNode != null && !string.IsNullOrEmpty(highNode.Value))
            {
                if (string.IsNullOrEmpty(port))
                {
                    port = "1";
                }
                port = string.Format("{0}-{1}", port, highNode.Value);
            }

            return port;
        }
    }

    public class Juniper_NatPolicy : JuniperObject
    {
        public bool Inactive { get; set; }
        public List<string> SourceZones = new List<string>();
        public List<string> SourceInterfaces = new List<string>();
        public bool IsRoutingInstanceDefined { get; set; }
    }

    public class Juniper_SourceNatPolicy : Juniper_NatPolicy
    {
        public List<string> DestinationZones = new List<string>();
        public List<string> DestinationInterfaces = new List<string>();

        public List<Juniper_SourceNatRule> Rules = new List<Juniper_SourceNatRule>();

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            if (objectNode.XPathSelectElement("./from/routing-instance") != null || objectNode.XPathSelectElement("./to/routing-instance") != null)
            {
                IsRoutingInstanceDefined = true;
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "Not converting source NAT policy object which specifies a routing instance as a source or destination of the traffic.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }

            var inactiveAttribute = objectNode.Attribute("inactive");
            if (inactiveAttribute != null && inactiveAttribute.Value == "inactive")
            {
                Inactive = true;
            }

            var sourceZoneNodes = objectNode.XPathSelectElements("./from/zone");
            foreach (var sourceZoneNode in sourceZoneNodes)
            {
                if (!string.IsNullOrEmpty(sourceZoneNode.Value))
                {
                    SourceZones.Add(sourceZoneNode.Value);
                }
            }

            var sourceInterfaceNodes = objectNode.XPathSelectElements("./from/interface");
            foreach (var sourceInterfaceNode in sourceInterfaceNodes)
            {
                if (!string.IsNullOrEmpty(sourceInterfaceNode.Value))
                {
                    SourceInterfaces.Add(sourceInterfaceNode.Value);
                }
            }

            if (SourceZones.Count == 0 && SourceInterfaces.Count == 0)
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing a source of the traffic for source NAT policy object.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }

            var destinationZoneNodes = objectNode.XPathSelectElements("./to/zone");
            foreach (var destinationZoneNode in destinationZoneNodes)
            {
                if (!string.IsNullOrEmpty(destinationZoneNode.Value))
                {
                    DestinationZones.Add(destinationZoneNode.Value);
                }
            }

            var destinationInterfaceNodes = objectNode.XPathSelectElements("./to/interface");
            foreach (var destinationInterfaceNode in destinationInterfaceNodes)
            {
                if (!string.IsNullOrEmpty(destinationInterfaceNode.Value))
                {
                    DestinationInterfaces.Add(destinationInterfaceNode.Value);
                }
            }

            if (DestinationZones.Count == 0 && DestinationInterfaces.Count == 0)
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing a destination of the traffic for source NAT policy object.";
                Console.WriteLine(ConversionIncidentMessage);
            }
        }
    }

    public class Juniper_DestinationNatPolicy : Juniper_NatPolicy
    {
        public List<Juniper_DestinationNatRule> Rules = new List<Juniper_DestinationNatRule>();

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            if (objectNode.XPathSelectElement("./from/routing-instance") != null)
            {
                IsRoutingInstanceDefined = true;
                return;
            }

            var inactiveAttribute = objectNode.Attribute("inactive");
            if (inactiveAttribute != null && inactiveAttribute.Value == "inactive")
            {
                Inactive = true;
            }

            var sourceZoneNodes = objectNode.XPathSelectElements("./from/zone");
            foreach (var sourceZoneNode in sourceZoneNodes)
            {
                if (!string.IsNullOrEmpty(sourceZoneNode.Value))
                {
                    SourceZones.Add(sourceZoneNode.Value);
                }
            }

            var sourceInterfaceNodes = objectNode.XPathSelectElements("./from/interface");
            foreach (var sourceInterfaceNode in sourceInterfaceNodes)
            {
                if (!string.IsNullOrEmpty(sourceInterfaceNode.Value))
                {
                    SourceInterfaces.Add(sourceInterfaceNode.Value);
                }
            }
        }
    }

    public class Juniper_StaticNatPolicy : Juniper_NatPolicy
    {
        public List<Juniper_StaticNatRule> Rules = new List<Juniper_StaticNatRule>();

        public override void Parse(XElement objectNode, string zoneName)
        {
            base.Parse(objectNode, zoneName);

            if (objectNode.XPathSelectElement("./from/routing-instance") != null)
            {
                IsRoutingInstanceDefined = true;
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "Not converting static NAT policy object which specifies a routing instance as a source of the traffic.";
                Console.WriteLine(ConversionIncidentMessage);
                return;
            }

            var inactiveAttribute = objectNode.Attribute("inactive");
            if (inactiveAttribute != null && inactiveAttribute.Value == "inactive")
            {
                Inactive = true;
            }

            var sourceZoneNodes = objectNode.XPathSelectElements("./from/zone");
            foreach (var sourceZoneNode in sourceZoneNodes)
            {
                if (!string.IsNullOrEmpty(sourceZoneNode.Value))
                {
                    SourceZones.Add(sourceZoneNode.Value);
                }
            }

            var sourceInterfaceNodes = objectNode.XPathSelectElements("./from/interface");
            foreach (var sourceInterfaceNode in sourceInterfaceNodes)
            {
                if (!string.IsNullOrEmpty(sourceInterfaceNode.Value))
                {
                    SourceInterfaces.Add(sourceInterfaceNode.Value);
                }
            }

            if (SourceZones.Count == 0 && SourceInterfaces.Count == 0)
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Missing a source of the traffic for static NAT policy object.";
                Console.WriteLine(ConversionIncidentMessage);
            }
        }
    }
}
