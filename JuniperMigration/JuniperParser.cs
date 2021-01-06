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
using System.Net;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using CommonUtils;
using Newtonsoft.Json;
using MigrationBase;

namespace JuniperMigration
{
    /// <summary>
    /// Parses the Juniper SRX XML configuration file and creates corresponding Juniper objects repository.
    /// </summary>
    public class JuniperParser : VendorParser
    {
        #region Private Members

        private readonly List<JuniperObject> _juniperObjects = new List<JuniperObject>();
        private readonly List<Juniper_GlobalPolicyRule> _juniperGlobalPolicyRules = new List<Juniper_GlobalPolicyRule>();
        private readonly Dictionary<string, List<string>> _addressNamesOverZonesLookup = new Dictionary<string, List<string>>(StringComparer.InvariantCultureIgnoreCase);
        
        #endregion

        #region Public Methods

        public override void Parse(string filename)
        {
            LoadDefaultApplicationsAndGroups();   // this must be the FIRST call!!!
            var configNode = LoadConfig(filename);

            ParseVersion(configNode);
            bool isParsed = ParseAddressBooks(configNode);
            ParseZones(configNode, !isParsed);
            ParseInterfaces(configNode);
            ParseRoutes(configNode);
            ParseApplicationsAndGroups(configNode);
            parseSchedulers(configNode);			
            ParsePolicy(configNode);
            ParseNat(configNode);
            AttachRoutesToInterfacesTopology();
        }

        public override void Export(string filename)
        {
            File.WriteAllText(filename, JsonConvert.SerializeObject(_juniperObjects, Newtonsoft.Json.Formatting.Indented));
        }

        public List<JuniperObject> Filter(string objectTypeAlias)
        {
            var filter = new List<JuniperObject>();

            foreach (var juniperObject in _juniperObjects)
            {
                if (juniperObject.GetType().ToString().EndsWith(objectTypeAlias))
                {
                    filter.Add(juniperObject);
                }
            }

            return filter;
        }

        public List<Juniper_GlobalPolicyRule> GetGlobalPolicyRules()
        {
            return _juniperGlobalPolicyRules;
        }

        public bool IsNetworkObjectContainedInMultipleZones(string name)
        {
            List<string> addressZones;
            return (_addressNamesOverZonesLookup.TryGetValue(name, out addressZones) && addressZones.Count > 1);
        }
        
        #endregion

        #region Private Methods

        private void LoadDefaultApplicationsAndGroups()
        {
            var applicationsAndGroupsDoc = XDocument.Load("junos-defaults.xml", LoadOptions.SetLineInfo);
            if (applicationsAndGroupsDoc.Root == null)
            {
                throw new ApplicationException("Cannot find Juniper default applications file 'junos-defaults.xml'.");
            }

            // The "applications" element is an inner element and NOT a direct child...
            // Just grab the first and only item from the results list.
            var applicationsNode = applicationsAndGroupsDoc.Root.Descendants("applications").ToList()[0];
            if (applicationsNode == null)
            {
                throw new InvalidDataException("Invalid XML structure: default 'applications' element is missing.");
            }

            var applications = applicationsNode.Elements("application");
            foreach (var application in applications)
            {
                ParseApplication(application);
            }

            var groups = applicationsNode.Elements("application-set");
            foreach (var group in groups)
            {
                JuniperObject juniperApplicationGroup = new Juniper_ApplicationGroup();
                juniperApplicationGroup.Parse(group, null);
                _juniperObjects.Add(juniperApplicationGroup);
            }
        }

        private XElement LoadConfig(string filename)
        {
            var configDoc = XDocument.Load(filename, LoadOptions.SetLineInfo);
            if (configDoc.Root == null)
            {
                throw new InvalidDataException("Invalid XML structure: XML root element is missing.");
            }

            var configNode = configDoc.Root.Element("configuration");
            if (configNode == null)
            {
                throw new InvalidDataException("Invalid XML structure: 'configuration' element is missing.");
            }

            return configNode;
        }

        protected override void ParseVersion(object versionProvider)
        {
            var configNode = (XElement)versionProvider;
            if (configNode != null)
            {
                var versionNode = configNode.Element("version");
                if (versionNode != null && versionNode.Value.Length > 0)
                {
                    VendorVersion = Regex.Match(versionNode.Value, @"\d+(\.\d+)?").Value;
                }
            }
        }

        private bool ParseAddressBooks(XElement configNode)
        {
            var addressBooks = configNode.XPathSelectElements("./security/address-book");
            if (!addressBooks.Any())
            {
                return false;
            }

            foreach (var addressBook in addressBooks)
            {
                string addressBookName = JuniperObject.GlobalZoneName;
                string addressBookZone = JuniperObject.GlobalZoneName;

                var addressBookNameNode = addressBook.Element("name");
                if (addressBookNameNode != null && !string.IsNullOrEmpty(addressBookNameNode.Value))
                {
                    addressBookName = addressBookNameNode.Value;
                }

                var zoneNameNode = addressBook.XPathSelectElement("./attach/zone/name");
                if (zoneNameNode != null && !string.IsNullOrEmpty(zoneNameNode.Value))
                {
                    addressBookZone = zoneNameNode.Value;
                }
                else if (addressBookName != JuniperObject.GlobalZoneName)
                {
                    // Found non global address-book without a zone attached!!!
                    Console.WriteLine("Found non global address-book without a zone attached: {0}", addressBookName);
                    continue;
                }

                var addresses = addressBook.Elements("address");
                ParseAddresses(addresses, addressBookZone);

                var addressGroups = addressBook.Elements("address-set");
                foreach (var group in addressGroups)
                {
                    JuniperObject juniperAddressGroup = new Juniper_AddressGroup();
                    juniperAddressGroup.Parse(group, addressBookZone);
                    _juniperObjects.Add(juniperAddressGroup);

                    HandleDuplicatedAddressName(juniperAddressGroup.Name, addressBookZone);
                }
            }

            return true;
        }

        private void ParseAddresses(IEnumerable<XElement> addresses, string zoneName)
        {
            foreach (var address in addresses)
            {
                var dnsName = address.Element("dns-name");
                var ipPrefix = address.Element("ip-prefix");
                var rengeAddress = address.Element("range-address");

                JuniperObject juniperObject = null;

                if (dnsName != null)
                {
                    juniperObject = new Juniper_Fqdn();
                }
                else if (ipPrefix != null)
                {
                    if (IsHostObject(ipPrefix.Value))
                    {
                        juniperObject = new Juniper_Host();
                    }
                    else
                    {
                        juniperObject = new Juniper_Network();
                    }
                }
                else if (rengeAddress != null)
                {
                    juniperObject = new Juniper_Range();
                }

                if (juniperObject != null)
                {
                    juniperObject.Parse(address, zoneName);
                    _juniperObjects.Add(juniperObject);

                    HandleDuplicatedAddressName(juniperObject.Name, zoneName);
                }
            }
        }

        private void ParseZones(XElement configNode, bool parseAddressBook)
        {
            var zones = configNode.XPathSelectElements("./security/zones/security-zone");
            foreach (var zone in zones)
            {
                JuniperObject juniperZone = new Juniper_Zone();
                juniperZone.Parse(zone, null);
                _juniperObjects.Add(juniperZone);

                if (parseAddressBook)
                {
                    var addresses = zone.XPathSelectElements("address-book/address");
                    ParseAddresses(addresses, juniperZone.Name);

                    var addressGroups = zone.XPathSelectElements("address-book/address-set");
                    foreach (var group in addressGroups)
                    {
                        JuniperObject juniperAddressGroup = new Juniper_AddressGroup();
                        juniperAddressGroup.Parse(group, juniperZone.Name);
                        _juniperObjects.Add(juniperAddressGroup);

                        HandleDuplicatedAddressName(juniperAddressGroup.Name, juniperZone.Name);
                    }
                }
            }
        }

        private void ParseInterfaces(XElement configNode)
        {
            var physicalInterfaces = configNode.XPathSelectElements("./interfaces/interface");
            foreach (var physicalInterface in physicalInterfaces)
            {
                // For a valid interface there should be at least one IP address node...
                if (physicalInterface.XPathSelectElement("./unit/family/inet/address/name") == null)
                {
                    continue;
                }

                // Use a temporary object to parse a name from the parent physical interface node.
                var tempObject = new JuniperObject();
                tempObject.Parse(physicalInterface, null);

                var logicalInterfaces = physicalInterface.Elements("unit");
                foreach (var logicalInterface in logicalInterfaces)
                {
                    JuniperObject juniperInterface = new Juniper_Interface();
                    juniperInterface.Parse(logicalInterface, null);
                    juniperInterface.Name = string.Format("{0}.{1}", tempObject.Name, juniperInterface.Name);
                    _juniperObjects.Add(juniperInterface);
                }
            }
        }

        private void ParseRoutes(XElement configNode)
        {
            var routes = configNode.XPathSelectElements("./routing-options/static/route");
            foreach (var route in routes)
            {
                JuniperObject juniperRoute = new Juniper_Route();
                juniperRoute.Parse(route, null);
                _juniperObjects.Add(juniperRoute);
            }
        }

        private void ParseApplicationsAndGroups(XElement configNode)
        {
            var applications = configNode.XPathSelectElements("./applications/application");
            foreach (var application in applications)
            {
                ParseApplication(application);
            }

            var applicationGroups = configNode.XPathSelectElements("./applications/application-set");
            foreach (var group in applicationGroups)
            {
                JuniperObject juniperApplicationGroup = new Juniper_ApplicationGroup();
                juniperApplicationGroup.Parse(group, null);
                _juniperObjects.Add(juniperApplicationGroup);
            }
        }

        private void ParseApplication(XElement application)
        {
            JuniperObject juniperObject;

            var terms = application.Elements("term").ToList();
            if (terms.Count > 0)
            {
                // Use a temporary object to parse name and description from the parent application node.
                var termApplicationObject = new JuniperObject();
                termApplicationObject.Parse(application, null);

                if (terms.Count > 1)
                {
                    // Create a group only for multiple terms!!!
                    var members = new List<string>();

                    foreach (var term in terms)
                    {
                        juniperObject = new Juniper_Application { LineNumber = ((IXmlLineInfo) term).LineNumber };
                        ((Juniper_Application)juniperObject).IsJunosDefault = termApplicationObject.Name.StartsWith("junos-");   // must come before parsing!!!
                        ((Juniper_Application)juniperObject).ParseFromTerm(term, true);
                        _juniperObjects.Add(juniperObject);

                        members.Add(juniperObject.Name);
                    }

                    juniperObject = new Juniper_ApplicationGroup
                    {
                        Name = termApplicationObject.Name,
                        Description = termApplicationObject.Description,
                        LineNumber = termApplicationObject.LineNumber,
                    };

                    ((Juniper_ApplicationGroup)juniperObject).IsJunosDefault = termApplicationObject.Name.StartsWith("junos-");
                    ((Juniper_ApplicationGroup)juniperObject).Members.AddRange(members);   // add the members manually
                    _juniperObjects.Add(juniperObject);
                }
                else
                {
                    juniperObject = new Juniper_Application
                    {
                        Name = termApplicationObject.Name,
                        Description = termApplicationObject.Description,
                        LineNumber = termApplicationObject.LineNumber
                    };

                    ((Juniper_Application)juniperObject).IsJunosDefault = termApplicationObject.Name.StartsWith("junos-");   // must come before parsing!!!
                    ((Juniper_Application)juniperObject).ParseFromTerm(terms[0], false);
                    _juniperObjects.Add(juniperObject);
                }
            }
            else
            {
                juniperObject = new Juniper_Application();
                juniperObject.Parse(application, null);
                _juniperObjects.Add(juniperObject);
            }
        }
		
        private void parseSchedulers(XElement configNode)
        {
            var schedulers = configNode.XPathSelectElements("./schedulers/scheduler");
            foreach (var scheduler in schedulers)
            {
                JuniperObject juniperScheduler = new Juniper_Scheduler();                                
                
                juniperScheduler.Parse(scheduler, null);
                _juniperObjects.Add(juniperScheduler);
            }
        }

        private void ParsePolicy(XElement configNode)
        {
            // First, parse the zone based policy.
            var zonePolicies = configNode.XPathSelectElements("./security/policies/policy");
            foreach (var zonePolicy in zonePolicies)
            {
                JuniperObject juniperZonePolicy = new Juniper_ZonePolicy();
                juniperZonePolicy.Parse(zonePolicy, null);
                _juniperObjects.Add(juniperZonePolicy);

                var policies = zonePolicy.Elements("policy");
                foreach (var policy in policies)
                {
                    var juniperRule = new Juniper_PolicyRule();
                    juniperRule.Parse(policy, null);
                    ((Juniper_ZonePolicy)juniperZonePolicy).Rules.Add(juniperRule);
                }
            }

            // Then, parse the global policy.
            var globalPolicies = configNode.XPathSelectElements("./security/policies/global/policy");
            foreach (var globalPolicy in globalPolicies)
            {
                var juniperGlobalRule = new Juniper_GlobalPolicyRule();
                juniperGlobalRule.Parse(globalPolicy, null);
                _juniperGlobalPolicyRules.Add(juniperGlobalRule);
            }

            // Resolve the policy default action.
            var defaultAction = Juniper_PolicyRule.ActionType.Deny;
            var policyDefaultAction = configNode.XPathSelectElement("./security/policies/default-policy");
            if (policyDefaultAction != null && policyDefaultAction.Element("permit-all") != null)
            {
                defaultAction = Juniper_PolicyRule.ActionType.Permit;
            }

            // Append the policy default action as a global rule!!!
            var juniperDefaultActionRule = new Juniper_GlobalPolicyRule();
            juniperDefaultActionRule.GenerateDefaultActionRule(defaultAction);
            _juniperGlobalPolicyRules.Add(juniperDefaultActionRule);
        }

        private void ParseNat(XElement configNode)
        {
            var nat = configNode.XPathSelectElement("./security/nat");
            if (nat == null)
            {
                return;
            }

            var sourceNat = nat.Element("source");
            if (sourceNat != null)
            {
                var sourceNatPools = sourceNat.Elements("pool");
                foreach (var sourceNatPool in sourceNatPools)
                {
                    var natPool = new Juniper_SourceNatPool();
                    natPool.Parse(sourceNatPool, null);
                    _juniperObjects.Add(natPool);
                }

                var sourceNatPolicies = sourceNat.Elements("rule-set");
                foreach (var sourceNatPolicy in sourceNatPolicies)
                {
                    JuniperObject juniperSourceNatPolicy = new Juniper_SourceNatPolicy();
                    juniperSourceNatPolicy.Parse(sourceNatPolicy, null);
                    _juniperObjects.Add(juniperSourceNatPolicy);

                    var rules = sourceNatPolicy.Elements("rule");
                    foreach (var rule in rules)
                    {
                        var juniperNatRule = new Juniper_SourceNatRule();
                        juniperNatRule.Parse(rule, null);
                        ((Juniper_SourceNatPolicy)juniperSourceNatPolicy).Rules.Add(juniperNatRule);
                    }
                }
            }

            var destinationNat = nat.Element("destination");
            if (destinationNat != null)
            {
                var destinationNatPools = destinationNat.Elements("pool");
                foreach (var destinationNatPool in destinationNatPools)
                {
                    var natPool = new Juniper_DestinationNatPool();
                    natPool.Parse(destinationNatPool, null);
                    _juniperObjects.Add(natPool);
                }

                var destinationNatPolicies = destinationNat.Elements("rule-set");
                foreach (var destinationNatPolicy in destinationNatPolicies)
                {
                    JuniperObject juniperDestinationNatPolicy = new Juniper_DestinationNatPolicy();
                    juniperDestinationNatPolicy.Parse(destinationNatPolicy, null);
                    _juniperObjects.Add(juniperDestinationNatPolicy);

                    var rules = destinationNatPolicy.Elements("rule");
                    foreach (var rule in rules)
                    {
                        var juniperNatRule = new Juniper_DestinationNatRule();
                        juniperNatRule.Parse(rule, null);
                        ((Juniper_DestinationNatPolicy)juniperDestinationNatPolicy).Rules.Add(juniperNatRule);
                    }
                }
            }

            var staticNat = nat.Element("static");
            if (staticNat != null)
            {
                var staticNatPolicies = staticNat.Elements("rule-set");
                foreach (var staticNatPolicy in staticNatPolicies)
                {
                    JuniperObject juniperStaticNatPolicy = new Juniper_StaticNatPolicy();
                    juniperStaticNatPolicy.Parse(staticNatPolicy, null);
                    _juniperObjects.Add(juniperStaticNatPolicy);

                    var rules = staticNatPolicy.Elements("rule");
                    foreach (var rule in rules)
                    {
                        var juniperNatRule = new Juniper_StaticNatRule();
                        juniperNatRule.Parse(rule, null);
                        ((Juniper_StaticNatPolicy)juniperStaticNatPolicy).Rules.Add(juniperNatRule);
                    }
                }
            }
        }

        private bool IsHostObject(string ipPrefix)
        {
            if (string.IsNullOrEmpty(ipPrefix))
            {
                // No IP address: will create a host with IP 1.1.1.1 and issue a conversion incident.
                return true;
            }

            int pos = ipPrefix.IndexOf('/');
            if (pos == -1)
            {
                // No prefix length indicator: will create a host.
                return true;
            }

            string ipPrefixLength = ipPrefix.Substring(pos + 1);
            if (string.IsNullOrEmpty(ipPrefixLength))
            {
                // Empty prefix length indicator: will create a host.
                return true;
            }

            return (ipPrefixLength == "32");
        }

        private void AttachRoutesToInterfacesTopology()
        {
            // Add related static routing information to interface's routing table.
            IEnumerable<JuniperObject> juniperInterfaces = Filter("_Interface");
            IEnumerable<JuniperObject> juniperRoutes = Filter("_Route");
            var unmatchedRoutes = new List<Juniper_Route>();

            foreach (Juniper_Interface juniperInterface in juniperInterfaces)
            {
                // Build a list of current interface networks, where we will lookup for routes to match.
                var interfaceNetworks = new List<IPNetwork>();
                foreach (var topology in juniperInterface.Topology)
                {
                    IPNetwork network;
                    if (IPNetwork.TryParse(topology.IpAddress, topology.Netmask, out network))
                    {
                        interfaceNetworks.Add(network);
                    }
                }

                if (interfaceNetworks.Count == 0)
                {
                    continue;
                }

                // Iterate over the list of routes and match with the current interface topology.
                foreach (Juniper_Route juniperRoute in juniperRoutes)
                {
                    if (string.IsNullOrEmpty(juniperRoute.NextHop))
                    {
                        continue;
                    }

                    foreach (var interfaceNetwork in interfaceNetworks)
                    {
                        IPAddress nextHop = IPAddress.Parse(juniperRoute.NextHop);
                        if (IPNetwork.Contains(interfaceNetwork, nextHop))
                        {
                            juniperInterface.Routes.Add(new Subnet(juniperRoute.IpAddress, juniperRoute.Netmask));
                            juniperRoute.InterfaceName = juniperInterface.Name;   // recall the matched interface name

                            if (juniperRoute.DefaultRoute)
                            {
                                juniperInterface.LeadsToInternet = true;
                            }

                            if (juniperRoute.ConversionIncidentType != ConversionIncidentType.None)
                            {
                                juniperInterface.ConversionIncidentType = juniperRoute.ConversionIncidentType;
                                juniperInterface.ConversionIncidentMessage = juniperRoute.ConversionIncidentMessage;
                            }

                            break;
                        }
                    }

                    if (string.IsNullOrEmpty(juniperRoute.InterfaceName))   // no match...
                    {
                        unmatchedRoutes.Add(juniperRoute);
                    }
                }
            }

            // Iterate over the list of unmatched routes and try to match with other route, which was already matched.
            foreach (Juniper_Route unmatchedRoute in unmatchedRoutes)
            {
                IPAddress nextHop = IPAddress.Parse(unmatchedRoute.NextHop);

                foreach (Juniper_Route juniperRoute in juniperRoutes)
                {
                    if (juniperRoute.DefaultRoute)   // do NOT match with default route
                    {
                        continue;
                    }

                    if (string.IsNullOrEmpty(juniperRoute.InterfaceName))   // this route has no matched interface
                    {
                        continue;
                    }

                    IPNetwork network;
                    if (IPNetwork.TryParse(juniperRoute.IpAddress, juniperRoute.Netmask, out network) && IPNetwork.Contains(network, nextHop))
                    {
                        // Route matched, get the related interface and add our route to its routes list.
                        foreach (Juniper_Interface juniperInterface in juniperInterfaces)
                        {
                            if (juniperInterface.Name == juniperRoute.InterfaceName)
                            {
                                juniperInterface.Routes.Add(new Subnet(unmatchedRoute.IpAddress, unmatchedRoute.Netmask));
                                break;
                            }
                        }

                        break;
                    }
                }
            }

            // Finally, append the Routes collection to the Topology collection of each interface.
            foreach (Juniper_Interface juniperInterface in juniperInterfaces)
            {
                if (juniperInterface.Topology.Count > 0 && juniperInterface.Routes.Count > 0)
                {
                    juniperInterface.Topology.AddRange(juniperInterface.Routes);
                }
            }
        }

        private void HandleDuplicatedAddressName(string addressName, string zoneName)
        {
            List<string> addressZones;
            if (_addressNamesOverZonesLookup.TryGetValue(addressName, out addressZones))
            {
                addressZones.Add(zoneName);
                _addressNamesOverZonesLookup[addressName] = addressZones;
            }
            else
            {
                _addressNamesOverZonesLookup.Add(addressName, new List<string> { zoneName });
            }
        }

        #endregion
    }
}
