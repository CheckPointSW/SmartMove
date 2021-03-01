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

using CheckPointObjects;
using CommonUtils;
using MigrationBase;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace NetScreenMigration
{
    /// <summary>
    /// Converts ScreenOS SSG objects repository into Check Point objects repository.
    /// Generates conversion reports for objects and policy packages.
    /// </summary>
    public class ScreenOSConverter : VendorConverter
    {
        #region Helper Classes

        private class NamesAppearanceInfo
        {
            public int NamesAppearanceCount { get; set; }
            public bool IsCPPredefinedName { get; set; }

            public NamesAppearanceInfo(bool isCPPredefinedName)
            {
                NamesAppearanceCount = 0;
                IsCPPredefinedName = isCPPredefinedName;
            }
        }

        public class ScreenOSNetworkUtil
        {
            public static bool IsMask(string maskLength)
            {
                int n;
                return (int.TryParse(maskLength, out n) && NetworkUtils.IsValidNetmaskv4(NetworkUtils.MaskLength2Netmask(n)));
            }

            public static bool IsHost(string host)
            {
                string[] hostArray = host.Split('/');
                return (hostArray.Length == 2 && NetworkUtils.IsValidIpv4(hostArray[0]) && IsMask(hostArray[1]) && int.Parse(hostArray[1]) == 32);
            }

            public static bool IsNetwork(string host)
            {
                string[] hostArray = host.Split('/');
                return (hostArray.Length == 2 && NetworkUtils.IsValidIpv4(hostArray[0]) && IsMask(hostArray[1]) && int.Parse(hostArray[1]) < 32);
            }

            public static bool IsIPv6(string ip)
            {
                IPAddress address;
                if (IPAddress.TryParse(ip, out address))
                {
                    return System.Net.Sockets.AddressFamily.InterNetworkV6 == address.AddressFamily;
                }
                return false;
            }

            public static string GetIPv4LastOfRangeByOtherRange(string ipSrtart, string ipEnd, string ip)
            {
                return NetworkUtils.Number2Ip(NetworkUtils.Ip2Number(ip) + (NetworkUtils.Ip2Number(ipEnd) - NetworkUtils.Ip2Number(ipSrtart)));
            }

            public static string HostMask()
            {
                return "255.255.255.255";
            }
        }

        public class ObjectNameGenerator
        {
            private Dictionary<string, NamesAppearanceInfo> _nameAppearance = new Dictionary<string, NamesAppearanceInfo>();

            public int GetAppearanceCount(string objName)
            {
                NamesAppearanceInfo count;
                _nameAppearance.TryGetValue(objName, out count);
                if (count == null)
                {
                    return 0;
                }

                return count.NamesAppearanceCount;
            }

            public void AddAppearanceCount(string objName, bool isCPPredefinedName)
            {
                NamesAppearanceInfo count;
                _nameAppearance.TryGetValue(objName, out count);
                if (count == null)
                {
                    count = new NamesAppearanceInfo(isCPPredefinedName);
                }

                count.IsCPPredefinedName = isCPPredefinedName;
                count.NamesAppearanceCount++;
                _nameAppearance[objName] = count;
            }

            public string GetAppearanceName(string objName)
            {
                NamesAppearanceInfo count;
                _nameAppearance.TryGetValue(objName, out count);

                if (count == null)
                {
                    return objName;
                }

                return objName + "_" + (count.NamesAppearanceCount - 1);
            }

            public bool IsAppearancePredefined(string objName)
            {
                NamesAppearanceInfo count;
                _nameAppearance.TryGetValue(objName, out count);
                if (count == null)
                {
                    return false;
                }

                return count.IsCPPredefinedName;
            }

            public static string ZoneName(string zone)
            {
                return "GRP_SM_" + zone;
            }

            public static string InterfaceName(string interfaceName)
            {
                return "GRP_SM_Interface_" + interfaceName.Replace("/", "_");
            }

            public static string NetworkName(string network, string mask)
            {
                return "Net_SM_" + network + "_" + NetworkUtils.GetMaskLength(mask);
            }

            public static string StaticRouteName(string network, string mask)
            {
                return "Static_Net_SM_" + network + "_" + NetworkUtils.GetMaskLength(mask);
            }

            public static string HostInterface(string interfaceName)
            {
                return "HOST_SM_Interface_" + interfaceName.Replace("/", "_");
            }

            public static string DomainName(string fqdn)
            {
                string validName = fqdn;
                if (validName.StartsWith(".") == false)
                {
                    validName = "." + validName;
                }
                if (validName.Count(f => f == '.') < 2)
                {
                    validName = validName + ".local";
                }

                return validName;
            }

            public static string ServiceGroup(string serviceName)
            {
                return "GRP_SM_Service_" + serviceName;
            }

            public static string ServiceName(string name, ServiceProtocolObject serviceObj)
            {
                if (serviceObj == null)
                {
                    return "";
                }
                return "Service_SM_" + serviceObj.ToString() + "_" + name;
            }

            public static string PackageName()
            {
                return "SSG_policy_package";
            }

            public static string UnknownHostName(string host)
            {
                return "SM_host_" + host.Replace("/", "_").Replace(".", "_");
            }

            public static string UnknownNetworkName(string network)
            {
                return "SM_network_" + network.Replace("/", "_").Replace(".", "_");
            }

            public static string SubPolicyByZonesName(string fromZone, string toZone)
            {
                const string subPolicy = "_sub_policy";
                if (fromZone == toZone)
                {
                    return fromZone + subPolicy;
                }
                return fromZone + "_to_" + toZone + subPolicy;
            }

            public static string MipOriginalName(string ip, string mask)
            {
                string ipType = "";
                if (NetworkUtils.GetMaskLength(mask) == 32)
                {
                    ipType = "HOST";
                }
                else
                {
                    ipType = "NET";
                }
                return ipType + "_SM_INTERFACE_ORIGINAL_MIP_" + ip;
            }

            public static string MipTranslatedName(string ip, string mask)
            {
                string ipType = "";
                if (NetworkUtils.GetMaskLength(mask) == 32)
                {
                    ipType = "HOST";
                }
                else
                {
                    ipType = "NET";
                }
                return ipType + "_SM_INTERFACE_TRANSLATED_MIP_" + ip;
            }

            public static string DipOriginalName(string ip, string objectType)
            {
                return "SM_" + objectType + "_ORIG_" + ip;
            }

            public static string DipTranslatedName(int dipId, string objectType)
            {
                return "SM_" + objectType + "_DIP_" + dipId.ToString();
            }

            public static string VipOriginalName(string ip)
            {
                return "HOST_SM_INTERFACE_ORIGINAL_VIP_" + ip;
            }

            public static string VipTranslatedName(string vip, string ip)
            {
                return "HOST_SM_INTERFACE_TRANSLATED_VIP_" + vip + "_" + ip;
            }

            public static string PolicyBasedNatTranslatedName(string ipFirst, string ipLast = "")
            {
                if (string.IsNullOrEmpty(ipLast))
                {
                    return "HOST_SM_INTERFACE_TRANSLATED_" + ipFirst;
                }
                return "RANGE_SM_INTERFACE_TRANSLATED_" + ipFirst + "_" + ipLast;
            }
        }

        public class ServiceCommandSimplifier
        {
            public List<ServiceProtocolObject> Services = new List<ServiceProtocolObject>();
            public string Name { get; set; }
            public int TimeOut { get; set; }
            public ScreenOSCommand_Service.TimeOutUnitsEnum TimeUnits { get; set; }
            public ScreenOSCommand_Service OrigServiceCommand { get; set; }

            public int Size
            {
                get { return Services != null ? Services.Count : 0; }
            }

            public ServiceCommandSimplifier(ScreenOSCommand_Service service)
            {
                Name = service.ServiceName;
                TimeOut = 0;
                TimeUnits = ScreenOSCommand_Service.TimeOutUnitsEnum.Minutes;
                OrigServiceCommand = service;

                if (!service.NotAnInterestingCommand)
                {
                    if (service.TimeOut != 0)
                    {
                        TimeOut = service.TimeOut;
                    }

                    if (service.TimeOutUnits != ScreenOSCommand_Service.TimeOutUnitsEnum.Minutes)
                    {
                        TimeUnits = service.TimeOutUnits;
                    }

                    if (service.ServiceProtocol != null && service.ServiceProtocol.ProtocolType != ServiceProtocolObject.ProtocolTypeEnum.NA)
                    {
                        service.ServiceProtocol.OrigService = service;
                        Services.Add(service.ServiceProtocol);
                    }
                }

                if (service.HasAdditionalRealatedObjects)
                {
                    foreach (ScreenOSCommand_Service subService in service.AdditionalRealatedObjects)
                    {
                        if (subService.NotAnInterestingCommand)
                        {
                            continue;
                        }

                        if (subService.TimeOut != 0)
                        {
                            TimeOut = subService.TimeOut;
                        }

                        if (subService.TimeOutUnits != ScreenOSCommand_Service.TimeOutUnitsEnum.Minutes)
                        {
                            TimeUnits = subService.TimeOutUnits;
                        }

                        if (subService.ServiceProtocol != null && subService.ServiceProtocol.ProtocolType != ServiceProtocolObject.ProtocolTypeEnum.NA)
                        {
                            subService.ServiceProtocol.OrigService = subService;
                            Services.Add(subService.ServiceProtocol);
                        }
                    }
                }
            }
        }

        public class PolicyCommandSimplifier
        {
            public enum ZoneDirectionEnum { Intra, Inter, Global, Na }

            public int PolicyId { get; set; }
            public string PolicyName { get; set; }
            public bool SourceNegated { get; set; }
            public bool DestinationNegated { get; set; }
            public string FromZone { get; set; }
            public string ToZone { get; set; }
            public bool IsGlobal { get; set; }
            public bool IsLogEnabled { get; set; }
            public bool IsEnabled { get; set; }
            public ScreenOSCommand_Policy.ActoinEnum Action { get; set; }

            public List<string> SrcAddr;
            public List<string> DstAddr;
            public List<string> Services;

            public ZoneDirectionEnum ZoneDirection
            {
                get
                {
                    if (IsGlobal)
                    {
                        return ZoneDirectionEnum.Global;
                    }

                    if (!string.IsNullOrEmpty(FromZone))
                    {
                        if (FromZone == ToZone)
                        {
                            return ZoneDirectionEnum.Intra;
                        }

                        return ZoneDirectionEnum.Inter;
                    }

                    return ZoneDirectionEnum.Na;
                }
            }

            public ScreenOSCommand_Policy OrigPolicy { get; set; }

            public PolicyCommandSimplifier(ScreenOSCommand_Policy command)
            {
                PolicyId = -1;
                SrcAddr = new List<string>();
                DstAddr = new List<string>();
                SourceNegated = false;
                DestinationNegated = false;
                Services = new List<string>();
                FromZone = "";
                ToZone = "";
                IsGlobal = false;
                IsLogEnabled = false;
                IsEnabled = true;
                Action = ScreenOSCommand_Policy.ActoinEnum.Na;
                OrigPolicy = command;

                if (command.NotAnInterestingCommand)
                {
                    if (command.HasAdditionalRealatedObjects)
                    {
                        foreach (ScreenOSCommand subPolicyCommad in command.AdditionalRealatedObjects)
                        {
                            subPolicyCommad.NotAnInterestingCommand = true;
                        }
                    }
                    return;
                }

                PolicyId = command.PolicyId;
                if (!string.IsNullOrEmpty(command.PolicyName))
                {
                    PolicyName = command.PolicyName;
                }

                IsGlobal = command.IsGlobal;
                FromZone = command.SrcZone.Trim('"');
                ToZone = command.DestZone.Trim('"');
                SrcAddr.Add(command.SrcObject.Trim('"'));
                DstAddr.Add(command.DestObject.Trim('"'));
                Services.Add(command.ServiceName.Trim('"'));
                IsLogEnabled = command.IsLogEnabled;
                Action = command.Action;

                if (command.HasAdditionalRealatedObjects)
                {
                    int i = 0;
                    foreach (ScreenOSCommand subPolicyCommad in command.AdditionalRealatedObjects)
                    {
                        if (subPolicyCommad.NotAnInterestingCommand == true)
                        {
                            continue;
                        }

                        if (i == 0 && subPolicyCommad.Name() == "policy")
                        {
                            IsEnabled = !((ScreenOSCommand_Policy)subPolicyCommad).IsDisabled;
                        }
                        else
                        {
                            string tmpStr = "";
                            switch (subPolicyCommad.ObjectWord)
                            {
                                case "src-address":
                                    tmpStr = subPolicyCommad.GetParam(2);
                                    if (tmpStr == "negate")
                                    {
                                        SourceNegated = true;
                                    }
                                    else
                                    {
                                        SrcAddr.Add(tmpStr.Trim('"'));
                                    }
                                    break;

                                case "dst-address":
                                    tmpStr = subPolicyCommad.GetParam(2);
                                    if (tmpStr == "negate")
                                    {
                                        DestinationNegated = true;
                                    }
                                    else
                                    {
                                        DstAddr.Add(tmpStr.Trim('"'));
                                    }
                                    break;

                                case "service":
                                    Services.Add(subPolicyCommad.GetParam(2).Trim('"'));
                                    break;

                                case "policy":
                                case "exit":
                                    break;

                                default:
                                    subPolicyCommad.NotAnInterestingCommand = true;
                                    break;
                            }
                        }
                        ++i;
                    }
                }
            }
        }

        public class NatVipForCheckPoint
        {
            public class VipInfoInCpObjects
            {
                public CheckPointObject portOrig { get; set; }
                public CheckPointObject portTranslated { get; set; }
                public CheckPointObject IpTranslated { get; set; }
            }

            public CheckPointObject OrigDestination { get; set; }
            public List<VipInfoInCpObjects> VipInfoInCpObjectsList { get; set; }
        }

        #endregion

        #region Private Members

        private enum CheckPointDummyObjectType { Host, Network, Service, Zone };

        private ScreenOSParser _screenOSParser;
        private ObjectNameGenerator _objectNameGenerator = new ObjectNameGenerator();
        private Dictionary<CheckPointObject, ScreenOSCommand> _cpNetworkObjectsInMultipleZones = new Dictionary<CheckPointObject, ScreenOSCommand>();
        private List<string> _cpUnsafeNames = new List<string>();
        private ScreenOSKnownServices _screenOsKnownServices = new ScreenOSKnownServices();
        private List<CheckPoint_Rule> _convertedNatPolicy2Rules = new List<CheckPoint_Rule>();
        private Dictionary<string, CheckPoint_NetworkGroup> _zonesNetworkGroups = new Dictionary<string, CheckPoint_NetworkGroup>();

        private IEnumerable<ScreenOSCommand> _screenOSAllCommands;
        private IEnumerable<ScreenOSCommand> ScreenOSAllCommands
        {
            get
            {
                return _screenOSAllCommands ?? (_screenOSAllCommands = _screenOSParser.ScreenOSAllCommands);
            }
        }

        private IEnumerable<ScreenOSCommand> _screenOSAdderssCommands;
        private IEnumerable<ScreenOSCommand> ScreenOSAdderssCommands
        {
            get
            {
                return _screenOSAdderssCommands ?? (_screenOSAdderssCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOSCommand_Address>());
            }
        }

        private IEnumerable<ScreenOSCommand> _screenOSGroupAddressCommands;
        private IEnumerable<ScreenOSCommand> screenOSGroupAddressCommands
        {
            get
            {
                return _screenOSGroupAddressCommands ?? (_screenOSGroupAddressCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOSCommand_GroupAddress>());
            }
        }

        private IEnumerable<ScreenOSCommand> _screenOSServiceCommands;
        private IEnumerable<ScreenOSCommand> ScreenOSServiceCommands
        {
            get
            {
                return _screenOSServiceCommands ?? (_screenOSServiceCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOSCommand_Service>());
            }
        }

        private IEnumerable<ScreenOSCommand> _screenOSGroupServiceCommands;
        private IEnumerable<ScreenOSCommand> ScreenOSGroupServiceCommands
        {
            get
            {
                return _screenOSGroupServiceCommands ?? (_screenOSGroupServiceCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOSCommand_GroupService>());
            }
        }

        private IEnumerable<ScreenOSCommand> _screenOSIpPoolCommands;
        private IEnumerable<ScreenOSCommand> ScreenOSIpPoolCommands
        {
            get
            {
                return _screenOSIpPoolCommands ?? (_screenOSIpPoolCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOSCommand_IPpool>());
            }
        }

        private IEnumerable<ScreenOSCommand> _screenOSZoneCommands;
        private IEnumerable<ScreenOSCommand> ScreenOSZoneCommands
        {
            get
            {
                return _screenOSZoneCommands ?? (_screenOSZoneCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOSCommand_Zone>());
            }
        }

        private IEnumerable<ScreenOSCommand> _screenOSInterfaceCommands;
        private IEnumerable<ScreenOSCommand> ScreenOSInterfaceCommands
        {
            get
            {
                return _screenOSInterfaceCommands ?? (_screenOSInterfaceCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOSCommand_Interface>());
            }
        }

        private IEnumerable<ScreenOSCommand> _screenOSRouteCommands;
        private IEnumerable<ScreenOSCommand> ScreenOSRouteCommands
        {
            get
            {
                return _screenOSRouteCommands ?? (_screenOSRouteCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOSCommand_Route>());
            }
        }

        private IEnumerable<ScreenOSCommand_Policy> _screenOSPolicyCommands;
        private IEnumerable<ScreenOSCommand_Policy> ScreenOSPolicyCommands
        {
            get
            {
                return _screenOSPolicyCommands ?? (_screenOSPolicyCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOSCommand_Policy>());
            }
        }

        private IEnumerable<ScreenOsCommand_GroupNatDIP> _screenOSGroupDipCommands;
        private IEnumerable<ScreenOsCommand_GroupNatDIP> ScreenOSGroupDipCommands
        {
            get
            {
                return _screenOSGroupDipCommands ?? (_screenOSGroupDipCommands = _screenOSParser.ScreenOSProcessedCommands.OfType<ScreenOsCommand_GroupNatDIP>());
            }
        }

        private Dictionary<string, string> _ssg2cpServicesName = null;
        private Dictionary<string, string> ScreenOS2CheckPointServicesNameDic
        {
            get
            {
                if (_ssg2cpServicesName == null)
                {
                    _ssg2cpServicesName = new Dictionary<string, string>();
                }
                return _ssg2cpServicesName;
            }
        }

        private List<string> _blockedZones;
        private List<string> BlockedZones
        {
            get
            {
                if (_blockedZones == null)
                {
                    _blockedZones = new List<string>();
                }

                return _blockedZones;
            }
        }

        private List<PolicyCommandSimplifier> _policySimplifiedList;
        private List<PolicyCommandSimplifier> PolicySimplifiedList
        {
            get
            {
                if (_policySimplifiedList == null)
                {
                    _policySimplifiedList = new List<PolicyCommandSimplifier>();
                    foreach (ScreenOSCommand_Policy policy in ScreenOSPolicyCommands)
                    {
                        if (policy.PolicyId != 0 && policy.PolicyNatType == ScreenOSCommand_Policy.PolicyNatTypeEnum.Policy)
                        {
                            _policySimplifiedList.Add(new PolicyCommandSimplifier(policy));
                        }
                    }
                }
                return _policySimplifiedList;
            }
        }

        protected override string GetVendorName()
        {
            return Vendor.JuniperScreenOS.ToString();
        }
        #endregion

        #region Private Methods

        protected override bool AddCheckPointObject(CheckPointObject cpObject)
        {
            if (base.AddCheckPointObject(cpObject))
            {
                string vendor = Vendor.JuniperScreenOS.ToString();
                if (!cpObject.Tags.Contains(vendor))
                {
                    cpObject.Tags.Add(vendor);
                }
            }

            return false;
        }

        private CheckPointObject GetCheckPointObjectOrCreateDummy(string cpObjectName, CheckPointDummyObjectType dummyObjectType, ScreenOSCommand sosCommand, string errorTitle, string errorDescription)
        {
            var cpObject = _cpObjects.GetObject(cpObjectName);
            if (cpObject != null)
            {
                return cpObject;
            }

            CheckPointObject cpDummyObject = null;

            switch (dummyObjectType)
            {
                case CheckPointDummyObjectType.Host:
                    cpDummyObject = new CheckPoint_Host { Name = "_Err_in_network-line_" + sosCommand.Id, IpAddress = "1.1.1.1" };
                    break;

                case CheckPointDummyObjectType.Network:
                    cpDummyObject = new CheckPoint_NetworkGroup { Name = "_Err_in_topology-line_" + sosCommand.Id };
                    break;

                case CheckPointDummyObjectType.Service:
                    cpDummyObject = new CheckPoint_ServiceGroup { Name = "_Err_in_service-line_" + sosCommand.Id };
                    break;

                case CheckPointDummyObjectType.Zone:
                    cpDummyObject = new CheckPoint_Zone { Name = "_Err_in_zone_name_" + sosCommand.Id };
                    break;
            }

            if (cpDummyObject != null)
            {
                cpDummyObject.ConvertedCommandId = sosCommand.Id;
                cpDummyObject.ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                AddCheckPointObject(cpDummyObject);

                sosCommand.ConversionIncidentType = ConversionIncidentType.ManualActionRequired;

                errorDescription = string.Format("{0} Using dummy object: {1}.", errorDescription, cpDummyObject.Name);
                _conversionIncidents.Add(new ConversionIncident(sosCommand.Id, errorTitle, errorDescription, sosCommand.ConversionIncidentType));
            }

            return cpDummyObject;
        }

        private void CheckObjectNameValidity(CheckPointObject cpObject, ScreenOSCommand screenOSCommand, bool inMultipleZones = false)
        {
            string originalName = cpObject.Name;

            if (string.IsNullOrEmpty(originalName))
            {
                screenOSCommand.ConversionIncidentType = ConversionIncidentType.ManualActionRequired;

                string errorDescription = string.Format("ScreenOS command: {0}.", screenOSCommand.Text);
                _conversionIncidents.Add(new ConversionIncident(screenOSCommand.Id,
                                                                "Object name cannot be empty. Please review for further possible modifications to objects before migration.",
                                                                errorDescription,
                                                                screenOSCommand.ConversionIncidentType));

                return;
            }

            if (originalName != cpObject.SafeName())
            {
                _cpUnsafeNames.Add(originalName);
            }

            if (_objectNameGenerator.GetAppearanceCount(originalName) != 0)
            {
                _objectNameGenerator.AddAppearanceCount(originalName, false);

                string uniqueName = _objectNameGenerator.GetAppearanceName(originalName);
                cpObject.Name = uniqueName;

                screenOSCommand.ConversionIncidentType = ConversionIncidentType.ManualActionRequired;

                string errorTitle = _objectNameGenerator.IsAppearancePredefined(originalName)
                                        ? "Detected an object with a same name in Check Point's predefined service objects repository."
                                        : "Detected an object with a non unique name. Check Point names should be case insensitive.";
                errorTitle += " Please review for further possible modifications to objects before migration.";
                string errorDescription = string.Format("Original name: {0}. Using unique name: {1}.", originalName, uniqueName);

                _conversionIncidents.Add(new ConversionIncident(screenOSCommand.Id, errorTitle, errorDescription, screenOSCommand.ConversionIncidentType));

                return;
            }

            _objectNameGenerator.AddAppearanceCount(originalName, false);
        }

        private bool IsNetworkObjectContainedInMultipleZones(CheckPointObject cpObject, ScreenOSCommand screenOSCommand)
        {
            if (_screenOSParser.IsNetworkObjectContainedInMultipleZones(cpObject.Name))
            {
                _cpNetworkObjectsInMultipleZones.Add(cpObject, screenOSCommand);

                screenOSCommand.ConversionIncidentType = ConversionIncidentType.Informative;
                cpObject.ConversionIncidentType = ConversionIncidentType.Informative;   // report on converted object as well!!!

                string errorDescription = string.Format("Object name: {0}, attached zone: {1}. Modified name: {0}_{1}", cpObject.Name, cpObject.Tag);
                _conversionIncidents.Add(new ConversionIncident(screenOSCommand.Id,
                                                                "ScreenOs object with the same name is attached to different zones. Applying zone name to object name for Check Point name uniqueness.",
                                                                errorDescription,
                                                                screenOSCommand.ConversionIncidentType));
                return true;
            }

            return false;
        }

        private void EnforceObjectNameValidity()
        {
            // Fix ScreenOs DNS names to be valid check point domain names
            foreach (var domain in _cpDomains)
            {
                string originalName = domain.Name;
                string validName = ObjectNameGenerator.DomainName(domain.Fqdn);
                domain.Name = validName;
                domain.ConversionIncidentType = ConversionIncidentType.Informative;

                // Search references in network groups
                foreach (var networkGroup in _cpNetworkGroups)
                {
                    if (domain.Tag == networkGroup.Tag)   // search in the same zone only...
                    {
                        int pos = networkGroup.Members.IndexOf(originalName);
                        if (pos != -1)
                        {
                            networkGroup.Members[pos] = validName;
                        }
                    }
                }
            }

            // Fix unsafe names
            foreach (string unsafeName in _cpUnsafeNames)
            {
                CheckPointObject cpObject = _cpObjects.GetObject(unsafeName);
                if (cpObject != null)
                {
                    cpObject.Name = cpObject.SafeName();

                    // Search references in service groups
                    foreach (CheckPoint_ServiceGroup serviceGroup in _cpServiceGroups)
                    {
                        int pos = serviceGroup.Members.IndexOf(unsafeName);
                        if (pos != -1)
                        {
                            serviceGroup.Members[pos] = cpObject.Name;
                        }
                    }

                    // Search references in network groups
                    foreach (CheckPoint_NetworkGroup networkGroup in _cpNetworkGroups)
                    {
                        int pos = networkGroup.Members.IndexOf(unsafeName);
                        if (pos != -1)
                        {
                            networkGroup.Members[pos] = cpObject.Name;
                        }
                    }
                }
            }
        }

        private void ApplyConversionIncidentOnCheckPointObject(CheckPointObject cpObject, ScreenOSCommand screenOsCommand)
        {
            cpObject.ConvertedCommandId = screenOsCommand.Id;

            if (screenOsCommand.ConversionIncidentType != ConversionIncidentType.None)
            {
                cpObject.ConversionIncidentType = screenOsCommand.ConversionIncidentType;

                if (!string.IsNullOrEmpty(screenOsCommand.ConversionIncidentMessage))
                {
                    string errorDesc = screenOsCommand.Name() + " details: " + screenOsCommand.Text + ".";
                    _conversionIncidents.Add(new ConversionIncident(screenOsCommand.Id,
                                                                    screenOsCommand.ConversionIncidentMessage,
                                                                    errorDesc,
                                                                    screenOsCommand.ConversionIncidentType));
                }
            }
        }

        private void ApplyConversionIncidentOnCheckPointNestedObject(CheckPointObject cpObject, ScreenOSCommand screenOsCommand)
        {
            cpObject.ConvertedCommandId = screenOsCommand.Id;

            if (screenOsCommand.ConversionIncidentType != ConversionIncidentType.None)
            {
                cpObject.ConversionIncidentType = screenOsCommand.ConversionIncidentType;

                if (!string.IsNullOrEmpty(screenOsCommand.ConversionIncidentMessage))
                {
                    List<string> incidents = screenOsCommand.ConversionIncidentMessage.Split('\n').ToList();

                    foreach (string incident in incidents)
                    {
                        string errorDesc = screenOsCommand.Name() + " details: " + screenOsCommand.Text + ".";
                        _conversionIncidents.Add(new ConversionIncident(screenOsCommand.Id,
                                                                        incident,
                                                                        errorDesc,
                                                                        screenOsCommand.ConversionIncidentType));
                    }
                }
            }

            if (screenOsCommand.HasAdditionalRealatedObjects)
            {
                foreach (ScreenOSCommand subCommand in screenOsCommand.AdditionalRealatedObjects)
                {
                    if (subCommand.ConversionIncidentType != ConversionIncidentType.None && !string.IsNullOrEmpty(subCommand.ConversionIncidentMessage))
                    {
                        List<string> incidents = subCommand.ConversionIncidentMessage.Split('\n').ToList();

                        foreach (string incident in incidents)
                        {
                            string errorDesc = screenOsCommand.Name() + " details: " + subCommand.Text + ".";
                            _conversionIncidents.Add(new ConversionIncident(subCommand.Id,
                                                                            incident,
                                                                            errorDesc,
                                                                            subCommand.ConversionIncidentType));
                        }
                    }
                }
            }
        }

        private void AlertOnDomainNameModification(ScreenOSCommand_Address fqdn, bool inMultipleZones)
        {
            fqdn.ConversionIncidentType = ConversionIncidentType.Informative;

            string errorDescription = inMultipleZones
                ? string.Format("ScreenOS name: {0}, attached to zone {1}. New name: {2}", fqdn.ObjectName, fqdn.Zone, ObjectNameGenerator.DomainName(fqdn.Domain))
                : string.Format("ScreenOS name: {0}. New name: {1}", fqdn.ObjectName, ObjectNameGenerator.DomainName(fqdn.Domain));

            _conversionIncidents.Add(new ConversionIncident(fqdn.Id,
                                                            "ScreenOS Domain object is converted to Check Point Domain object using dns-name prefixed with a dot as converted object name.",
                                                            errorDescription,
                                                            fqdn.ConversionIncidentType));
        }

        private bool GetMipObjByMipName(string mip, out ScreenOSCommand_Interface ifcCommand)
        {
            ifcCommand = null;

            foreach (ScreenOSCommand_Interface ifc in ScreenOSInterfaceCommands)
            {
                if (ifc.HasAdditionalRealatedObjects)
                {
                    foreach (ScreenOSCommand_Interface subIfc in ifc.AdditionalRealatedObjects)
                    {
                        if (subIfc.InterfaceObjectType == ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Mip)
                        {
                            string netMask = "";
                            if (NetworkUtils.GetMaskLength(((ScreenOsCommand_InterfceNatMIP)subIfc.NatObject).Mask) != 32)
                            {
                                netMask = "/" + NetworkUtils.GetMaskLength(((ScreenOsCommand_InterfceNatMIP)subIfc.NatObject).Mask).ToString();
                            }
                            if ("MIP(" + ((ScreenOsCommand_InterfceNatMIP)subIfc.NatObject).Mip + netMask + ")" == mip)
                            {
                                ifcCommand = subIfc;
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }

        private bool GetDipObjByDipId(int dip, out ScreenOSCommand_Interface ifcCommand)
        {
            ifcCommand = null;

            /* Check if dip is a group, if yes take the first member*/
            List<ScreenOsCommand_GroupNatDIP> groupDip = ScreenOSGroupDipCommands.Where(g => g.GroupDipId == dip).ToList();
            if (groupDip.Any())
            {
                if (groupDip.First().HasAdditionalRealatedObjects == true)
                {
                    foreach (ScreenOsCommand_GroupNatDIP subDipGroup in groupDip.First().AdditionalRealatedObjects)
                    {
                        if (subDipGroup.DipMember != 0)
                        {
                            dip = subDipGroup.DipMember;
                            break;
                        }
                    }
                }
            }

            /* Find ScreenOs Interface object of wanted dip id*/
            foreach (ScreenOSCommand_Interface ifc in ScreenOSInterfaceCommands)
            {
                if (ifc.HasAdditionalRealatedObjects)
                {
                    foreach (ScreenOSCommand_Interface subIfc in ifc.AdditionalRealatedObjects)
                    {
                        if (subIfc.InterfaceObjectType == ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Dip)
                        {
                            if (((ScreenOsCommand_InterfceNatDIP)subIfc.NatObject).DipId == dip)
                            {
                                ifcCommand = subIfc;
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }

        private bool GetVipObjByVipName(string vip, out List<ScreenOSCommand_Interface> ifcCommand)
        {
            ifcCommand = null;
            string ifcIp = "";

            foreach (ScreenOSCommand_Interface ifc in ScreenOSInterfaceCommands)
            {
                if (ifc.HasAdditionalRealatedObjects)
                {
                    foreach (ScreenOSCommand_Interface subIfc in ifc.AdditionalRealatedObjects)
                    {
                        if (subIfc.NotAnInterestingCommand)
                        {
                            continue;
                        }

                        /* Get interface Ip*/
                        if (subIfc.InterfaceObjectType == ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Ip)
                        {
                            ifcIp = subIfc.IP;
                        }

                        if (subIfc.InterfaceObjectType == ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Vip)
                        {
                            /* If use interface IP enabled, take ip from interface ip command*/
                            if (((ScreenOsCommand_InterfceNatVIP)subIfc.NatObject).ShuoldUseInterfcaeIp
                                || string.IsNullOrEmpty(((ScreenOsCommand_InterfceNatVIP)subIfc.NatObject).Vip))
                            {
                                ((ScreenOsCommand_InterfceNatVIP)subIfc.NatObject).Vip = ifcIp;
                            }

                            if ("VIP(" + ((ScreenOsCommand_InterfceNatVIP)subIfc.NatObject).Vip + ")" == vip
                                || vip.Contains(subIfc.InterfaceObjName))
                            {
                                if (ifcCommand == null)
                                {
                                    ifcCommand = new List<ScreenOSCommand_Interface>();
                                }
                                ifcCommand.Add(subIfc);
                            }
                        }
                    }
                }
            }

            return ifcCommand != null;
        }

        private CheckPointObject GetNetworkGroupOfNameOrMembers(string groupName, List<string> members)
        {
            CheckPointObject existGroup = _cpObjects.GetObject(groupName);
            if (existGroup != null)
            {
                return existGroup;
            }

            foreach (CheckPoint_NetworkGroup group in _cpNetworkGroups)
            {
                if (group.Members.Count == members.Count && group.Members.All(members.Contains))
                {
                    return group;
                }
            }

            return null;
        }

        private CheckPointObject GetServiceGroupOfNameOrMembers(string groupName, List<string> members)
        {
            CheckPointObject existService = _cpObjects.GetObject(groupName);
            if (existService != null)
            {
                return existService;
            }

            var serviceListByCheckPointName = new List<string>();

            foreach (string service in members)
            {
                if (ScreenOS2CheckPointServicesNameDic.ContainsKey(service))
                {
                    serviceListByCheckPointName.Add(ScreenOS2CheckPointServicesNameDic[service]);
                }
                else
                {
                    serviceListByCheckPointName.Add(service);
                }
            }

            foreach (CheckPoint_ServiceGroup group in _cpServiceGroups)
            {
                if (group.Members.Count == members.Count && group.Members.All(serviceListByCheckPointName.Contains))
                {
                    return group;
                }
            }

            return null;
        }

        private CheckPointObject GetCheckPointObjByIp(string ip, string mask)
        {
            /* Find Checkpoint Host/Network object by IP & Mask*/
            if (NetworkUtils.GetMaskLength(mask) == 32)
            {
                /* Search as host obj*/
                foreach (CheckPoint_Host host in _cpHosts)
                {
                    if (host.IpAddress == ip)
                    {
                        return host;
                    }
                }
            }
            else
            {
                /* Search as Network obj*/
                string network = NetworkUtils.GetNetwork(ip, mask);
                foreach (CheckPoint_Network net in _cpNetworks)
                {
                    if (net.Subnet == network)
                    {
                        return net;
                    }
                }
            }

            return null;
        }

        private CheckPointObject CreateCheckPointObjByIp(string ip, string mask, string objName)
        {
            CheckPointObject cpObj = null;

            if (NetworkUtils.GetMaskLength(mask) == 32)
            {
                CheckPoint_Host cpHost = new CheckPoint_Host();
                cpHost.Name = objName;
                cpHost.IpAddress = ip;
                cpObj = cpHost;
            }
            else
            {
                CheckPoint_Network cpNetwork = new CheckPoint_Network();
                cpNetwork.Name = objName;
                cpNetwork.Subnet = NetworkUtils.GetNetwork(ip, mask);
                cpNetwork.Netmask = mask;
                cpObj = cpNetwork;
            }

            CheckObjectNameValidity(cpObj, new ScreenOSCommand());
            AddCheckPointObject(cpObj);
            return cpObj;
        }

        private CheckPointObject GetCheckPointServiceObjByName(string serviceName)
        {
            if (string.IsNullOrEmpty(serviceName))
            {
                return null;
            }

            if (!ScreenOS2CheckPointServicesNameDic.ContainsKey(serviceName))
            {
                CreateCheckPointServiceOrGroupForPredefinedScreenOsService(serviceName);
                if (!ScreenOS2CheckPointServicesNameDic.ContainsKey(serviceName))
                {
                    return null;
                }
            }
                
            string objName = ScreenOS2CheckPointServicesNameDic[serviceName];
            return _cpObjects.GetObject(objName);
        }

        private CheckPointObject GetCheckPointServiceObjByPort(int servicePort, string type)
        {
            /* Check if predefined port*/
            string serviceName = "";
            if (DoesServiceIsPredefinedInCheckPoint(type + "_" + servicePort.ToString(), out serviceName))
            {
                return _cpObjects.GetObject(serviceName);
            }

            /* Find custom service in checkpoint objects*/
            switch (type)
            {
                case "TCP":
                    foreach (CheckPoint_TcpService cpTcpService in _cpTcpServices)
                    {
                        if (cpTcpService.Port == servicePort.ToString())
                        {
                            return cpTcpService;
                        }
                    }
                    break;

                case "UDP":
                    foreach (CheckPoint_UdpService cpUdpService in _cpUdpServices)
                    {
                        if (cpUdpService.Port == servicePort.ToString())
                        {
                            return cpUdpService;
                        }
                    }
                    break;

                case "OTHER":
                    foreach (CheckPoint_OtherService cpOtherService in _cpOtherServices)
                    {
                        if (cpOtherService.IpProtocol == servicePort.ToString())
                        {
                            return cpOtherService;
                        }
                    }
                    break;

                default:
                    return null;
            }

            return null;
        }

        private CheckPointObject GetCheckPointObjByIpRange(string startIp, string endIp, string objName)
        {
            /* Search an existing Check Point range object*/
            foreach (CheckPoint_Range range in _cpRanges)
            {
                if (range.RangeFrom == startIp && range.RangeTo == endIp)
                {
                    return range;
                }
            }

            /* Range not found create new Check Point range object*/
            CheckPoint_Range cpRange = new CheckPoint_Range();
            cpRange.Name = objName;
            cpRange.RangeFrom = startIp;
            cpRange.RangeTo = endIp;
            CheckObjectNameValidity(cpRange, new ScreenOSCommand());
            AddCheckPointObject(cpRange);
            return cpRange;
        }

        private CheckPointObject GetSrcObjectByNameFromPolicy(string srcName, PolicyCommandSimplifier policy, bool isNAT = false)
        {
            CheckPointObject cpObject;
            string sourceName = srcName;

            if (srcName == "Any")
            {
                if (isNAT)
                {
                    cpObject = _cpObjects.GetObject(ObjectNameGenerator.ZoneName(policy.FromZone));
                    if (cpObject == null || cpObject.Tag == "DefaultGateway")
                    {
                        cpObject = _cpObjects.GetObject(CheckPointObject.Any);
                    }
                }
                else
                {
                    cpObject = _cpObjects.GetObject(CheckPointObject.Any);
                }
                return cpObject;
            }

            if (_screenOSParser.IsNetworkObjectContainedInMultipleZones(srcName))
            {
                sourceName = srcName + "_" + policy.FromZone;   // original name combined with the zone name
            }

            cpObject = GetCheckPointObjectOrCreateDummy(sourceName,
                                                        CheckPointDummyObjectType.Network,
                                                        policy.OrigPolicy,
                                                        "Error creating a rule, missing information for source ScreenOS object",
                                                        "Source object details: " + sourceName + ".");
            return cpObject;

        }

        private CheckPointObject GetSrcObjectFromPolicyForNAT(PolicyCommandSimplifier policy)
        {
            /* Check source checkpoint object for NAT rule*/
            CheckPointObject srcOrig = null;
            if (policy.SrcAddr.Count > 1)
            {
                string groupName = "GRP_SM_SRC_RULE_" + policy.PolicyId.ToString();
                srcOrig = GetNetworkGroupOfNameOrMembers(groupName, policy.SrcAddr);
                if (srcOrig == null)
                {
                    /* Create group*/
                    CheckPoint_NetworkGroup srcGroup = new CheckPoint_NetworkGroup();
                    srcGroup.Name = groupName;

                    foreach (string src in policy.SrcAddr)
                    {
                        srcGroup.Members.Add(GetSrcObjectByNameFromPolicy(src, policy,true).Name);
                    }

                    AddCheckPointObject(srcGroup);
                    srcOrig = srcGroup;
                }
            }
            else
            {
                srcOrig = GetSrcObjectByNameFromPolicy(policy.SrcAddr.First(), policy, true);
            }

            return srcOrig;
        }

        private CheckPointObject GetDstObjectByNameFromPolicy(string dstName, PolicyCommandSimplifier policy, bool isNAT = false)
        {
            CheckPointObject cpObject;

            string destName = dstName;
            if (dstName == "Any")
            {
                if (isNAT)
                {
                    cpObject = _cpObjects.GetObject(ObjectNameGenerator.ZoneName(policy.ToZone));
                    if (cpObject == null || cpObject.Tag == "DefaultGateway")
                    {
                        cpObject = _cpObjects.GetObject(CheckPointObject.Any);
                    }
                }
                else
                {
                    cpObject = _cpObjects.GetObject(CheckPointObject.Any);
                }
                return cpObject;
            }

            if (_screenOSParser.IsNetworkObjectContainedInMultipleZones(destName))
            {
                destName = dstName + "_" + policy.ToZone;   // original name combined with the zone name
            }

            cpObject = GetCheckPointObjectOrCreateDummy(destName,
                                                        CheckPointDummyObjectType.Network,
                                                        policy.OrigPolicy,
                                                        "Error creating a rule, missing information for destination Screen OS object",
                                                        "Object details: " + destName + ".");

            return cpObject;
        }

        private CheckPointObject GetDstObjectFromPolicyForNAT(PolicyCommandSimplifier policy)
        {
            /* Check destination checkpoint object for NAT rule*/
            CheckPointObject dstOrig = null;
            if (policy.DstAddr.Count > 1)
            {
                string groupName = "GRP_SM_DST_RULE_" + policy.PolicyId.ToString();
                dstOrig = GetNetworkGroupOfNameOrMembers(groupName, policy.DstAddr);
                if (dstOrig == null)
                {
                    /* Create group*/
                    CheckPoint_NetworkGroup dstGroup = new CheckPoint_NetworkGroup();
                    dstGroup.Name = groupName;

                    foreach (string dst in policy.DstAddr)
                    {
                        dstGroup.Members.Add(GetDstObjectByNameFromPolicy(dst, policy,true).Name);
                    }

                    AddCheckPointObject(dstGroup);
                    dstOrig = dstGroup;
                }
            }
            else
            {
                dstOrig = GetDstObjectByNameFromPolicy(policy.DstAddr.First(), policy,true);
            }

            return dstOrig;
        }

        private CheckPointObject GetServiceObjectByNameFromPolicy(string serviceName, PolicyCommandSimplifier policy)
        {
            CheckPointObject cpObject;

            if (serviceName == "ANY")
            {
                cpObject = _cpObjects.GetObject(CheckPointObject.Any);
            }
            else
            {
                string srcObjectName = ScreenOS2CheckPointServicesNameDic.ContainsKey(serviceName) ? ScreenOS2CheckPointServicesNameDic[serviceName] : CreateCheckPointServiceOrGroupForPredefinedScreenOsService(serviceName);
                cpObject = GetCheckPointObjectOrCreateDummy(srcObjectName,
                                                            CheckPointDummyObjectType.Service,
                                                            policy.OrigPolicy,
                                                            "Error creating a rule, missing information for service Screen OS object",
                                                            "Object details: " + serviceName + ".");
            }

            return cpObject;
        }

        private CheckPointObject GetServiceObjectFromPolicyForNAT(PolicyCommandSimplifier policy)
        {
            /* Check service checkpoint object for NAT rule*/
            CheckPointObject serviceOrig = null;
            if (policy.Services.Count > 1)
            {
                string groupName = "GRP_SM_Service_RULE_" + policy.PolicyId.ToString();
                serviceOrig = GetServiceGroupOfNameOrMembers(groupName, policy.Services);
                if (serviceOrig == null)
                {
                    /* Create group*/
                    CheckPoint_ServiceGroup serviceGroup = new CheckPoint_ServiceGroup();
                    serviceGroup.Name = groupName;

                    foreach (string service in policy.Services)
                    {
                        serviceGroup.Members.Add(GetServiceObjectByNameFromPolicy(service, policy).Name);
                    }

                    AddCheckPointObject(serviceGroup);
                    serviceOrig = serviceGroup;
                }
            }
            else
            {
                serviceOrig = GetServiceObjectByNameFromPolicy(policy.Services.First(), policy);
            }

            return serviceOrig;
        }

        private CheckPointObject IfTranslatedServiceIsGroupReturnDummy(CheckPointObject translatedService, PolicyCommandSimplifier natPolicy)
        {
            CheckPointObject retObj = translatedService;
            if (translatedService.GetType().ToString() == "CheckPoint_ServiceGroup")
            {
                retObj = GetCheckPointObjectOrCreateDummy(translatedService.Name + "_Group_Err",
                                                          CheckPointDummyObjectType.Service,
                                                          natPolicy.OrigPolicy,
                                                          "Error creating  NAT rule. Translated service object of NAT rule can not be group of services",
                                                          "Policy NAT object details: " + natPolicy.OrigPolicy.Text + ".");
            }
            return retObj;
        }

        private string CreateCheckPointServiceByNameAndPort(string serviceName, string port)
        {
            string[] words = port.Split('_');

            CheckPointObject cpService = null;
            ServiceProtocolObject sosService = null;

            switch (words[0])
            {
                case "TCP":
                    cpService = new CheckPoint_TcpService();
                    sosService = new ServiceProtocolObject_Tcp()
                    {
                        ProtocolType = ServiceProtocolObject.ProtocolTypeEnum.Tcp,
                        DstPort = words[1]
                    };
                    ((CheckPoint_TcpService)cpService).Port = ((ServiceProtocolObject_Tcp)sosService).DstPort;
                    break;

                case "UDP":
                    cpService = new CheckPoint_UdpService();
                    sosService = new ServiceProtocolObject_Udp()
                    {
                        ProtocolType = ServiceProtocolObject.ProtocolTypeEnum.Udp,
                        DstPort = words[1]
                    };
                    ((CheckPoint_UdpService)cpService).Port = ((ServiceProtocolObject_Udp)sosService).DstPort;
                    break;

                case "OTHER":
                    cpService = new CheckPoint_OtherService();
                    sosService = new ServiceProtocolObject_Ip()
                    {
                        ProtocolType = ServiceProtocolObject.ProtocolTypeEnum.Ip,
                        DstPort = words[1]
                    };
                    ((CheckPoint_OtherService)cpService).IpProtocol = ((ServiceProtocolObject_Ip)sosService).DstPort;
                    break;

                case "ICMP":
                    cpService = new CheckPoint_IcmpService();
                    sosService = new ServiceProtocolObject_Icmp()
                    {
                        IcmpType = byte.Parse(words[1]),
                        IcmpCode = byte.Parse(words[2])
                    };
                    ((CheckPoint_IcmpService)cpService).Type = ((ServiceProtocolObject_Icmp)sosService).IcmpType.ToString();
                    ((CheckPoint_IcmpService)cpService).Code = ((ServiceProtocolObject_Icmp)sosService).IcmpCode.ToString();
                    break;

                case "MS-RPC":
                    cpService = new CheckPoint_DceRpcService();
                    sosService = new ServiceProtocolObject_MsRPC()
                    {
                        Uuid = words[1]
                    };
                    ((CheckPoint_DceRpcService)cpService).InterfaceUuid = ((ServiceProtocolObject_MsRPC)sosService).Uuid;
                    break;

                case "SUN-RPC":
                    cpService = new CheckPoint_RpcService();
                    sosService = new ServiceProtocolObject_SunRPC()
                    {
                        Program = words[1]
                    };
                    ((CheckPoint_RpcService)cpService).ProgramNumber = ((ServiceProtocolObject_SunRPC)sosService).Program;
                    break;
            }

            sosService.Protocol = sosService.Name();
            cpService.Name = ObjectNameGenerator.ServiceName(serviceName, sosService);
            ScreenOS2CheckPointServicesNameDic[serviceName] = cpService.Name;

            AddCheckPointObject(cpService);
            return cpService.Name;
        }

        private string CreateCheckPointServiceOrGroupForPredefinedScreenOsService(string sosServiceName)
        {
            /* Check if predefined service is a group*/
            List<string> preDefinedServices = new List<string>();
            preDefinedServices = ScreenOSKnownServices.ConvertPredefinedServiceGroupNameToList(sosServiceName);

            /* If not a group check for service name*/
            if (preDefinedServices.Any() == false)
            {
                return CreateCheckPointServiceForPredefinedScreenOsService(sosServiceName);
            }

            /* Create Checkpoint GroupService*/
            CheckPoint_ServiceGroup cpServiceGroup = new CheckPoint_ServiceGroup();
            cpServiceGroup.Name = ObjectNameGenerator.ServiceGroup(sosServiceName);
            foreach (string preDefinedService in preDefinedServices)
            {
                cpServiceGroup.Members.Add(CreateCheckPointServiceForPredefinedScreenOsService(preDefinedService));
            }

            ScreenOS2CheckPointServicesNameDic[sosServiceName] = cpServiceGroup.Name;
            CheckObjectNameValidity(cpServiceGroup, new ScreenOSCommand());
            AddCheckPointObject(cpServiceGroup);
            return cpServiceGroup.Name;
        }

        private string CreateCheckPointServiceForPredefinedScreenOsService(string sosServiceName)
        {
            string cpObjectName = "";

            var ports = ScreenOSKnownServices.ConvertPredefinedServiceNameToPort(sosServiceName);
            if (!ports.Any())
            {
                return sosServiceName;
            }

            var port2cpPredefinedService = new Dictionary<string, string>();

            foreach (string portParam in ports)
            {
                string cpServiceName = "";
                if (DoesServiceIsPredefinedInCheckPoint(portParam, out cpServiceName))
                {
                    port2cpPredefinedService[portParam] = cpServiceName;
                }
                else
                {
                    port2cpPredefinedService[portParam] = "";
                }
            }

            if (ports.Count == 1)
            {
                if (string.IsNullOrEmpty(port2cpPredefinedService.First().Value))
                {
                    cpObjectName = CreateCheckPointServiceByNameAndPort(sosServiceName, port2cpPredefinedService.First().Key);
                }
                else
                {
                    cpObjectName = port2cpPredefinedService.First().Value;
                }
            }
            else
            {
                CheckPoint_ServiceGroup cpServiceGroup = new CheckPoint_ServiceGroup();
                cpServiceGroup.Name = ObjectNameGenerator.ServiceGroup(sosServiceName);
                cpObjectName = cpServiceGroup.Name;

                foreach (KeyValuePair<string, string> cpServiceName in port2cpPredefinedService)
                {
                    string serviceName = "";
                    if (string.IsNullOrEmpty(cpServiceName.Value))
                    {
                        serviceName = CreateCheckPointServiceByNameAndPort(sosServiceName, cpServiceName.Key);
                    }
                    else
                    {
                        serviceName = cpServiceName.Value;
                    }
                    cpServiceGroup.Members.Add(serviceName);
                }
                ScreenOS2CheckPointServicesNameDic[sosServiceName] = cpServiceGroup.Name;
                CheckObjectNameValidity(cpServiceGroup, new ScreenOSCommand());
                AddCheckPointObject(cpServiceGroup);
            }

            return cpObjectName;
        }

        private bool DoesServiceIsPredefinedInCheckPoint(string sosService, out string cpServiceName)
        {
            cpServiceName = "";
            string portParam = "";
            string[] parts = sosService.Split('_');

            if (parts[0] == "MS-RPC")
            {
                return false;
            }

            if (parts[0] == "ICMP")
            {
                int type;
                if (int.TryParse(parts[2], out type))
                {
                    if (type != 0)
                    {
                        return false;
                    }
                    portParam = parts[0] + "_" + parts[1];
                }
                else if (parts[1] == "any" && parts[2] == "any")
                {
                    portParam = parts[0] + "_99";
                }
                else
                {
                    return false;
                }
            }
            else
            {
                portParam = sosService;
            }

            bool isExist = false;
            cpServiceName = _cpObjects.GetKnownServiceName(portParam, out isExist);
            return isExist;
        }

        private void UploadPredefinedServices()
        {
            /* Add known check point service groups to service name map*/
            foreach (KeyValuePair<string, string> screenOsServiceGroupName in _screenOsKnownServices.ScreenOSPredefinedServicesGroupToCpGroup)
            {
                if (_cpObjects.HasObject(screenOsServiceGroupName.Value))
                {
                    ScreenOS2CheckPointServicesNameDic[screenOsServiceGroupName.Key] = screenOsServiceGroupName.Value;
                }
            }

            /* Add known check point services to service name map*/
            foreach (KeyValuePair<string, List<string>> preService in _screenOsKnownServices.ScreenOSPredefinedServicesByName)
            {
                List<string> cpServices = new List<string>();
                foreach (string port in preService.Value)
                {
                    string portParam = "";
                    if (DoesServiceIsPredefinedInCheckPoint(port, out portParam))
                    {
                        cpServices.Add(portParam);
                    }
                }

                if (cpServices.Count == 1 && preService.Value.Count == cpServices.Count)
                {
                    ScreenOS2CheckPointServicesNameDic[preService.Key] = cpServices[0];
                }
            }
        }

        private bool IsZoneAvailable(string zoneName, ScreenOSCommand command)
        {
            CheckPointObject cpZone = _cpObjects.GetObject(zoneName);
            if (zoneName != ScreenOSCommand_Zone.Global && cpZone == null)
            {
                if(ScreenOSCommand_Zone.SpecialPredefinedZones.Contains(zoneName))
                {
                    /* Create predefined special zone*/
                    cpZone = new CheckPoint_Zone();
                    cpZone.Name = zoneName;
                    ApplyConversionIncidentOnCheckPointObject(cpZone, command);
                    CheckObjectNameValidity(cpZone, command);
                    AddCheckPointObject(cpZone);
                    return true;
                }

                command.ConversionIncidentType = ConversionIncidentType.Informative;
                string errorTitle = string.Format("ScreenOS command using unknown zone. Ignoring this command");
                string errorDescription = string.Format("Object details: {0}.", command.Text);
                _conversionIncidents.Add(new ConversionIncident(command.Id, errorTitle, errorDescription, ConversionIncidentType.Informative));
                return false;
            }

            return true;
        }

        private void Add_Zones()
        {
            foreach (ScreenOSCommand_Zone command in ScreenOSZoneCommands)
            {
                if (command.NotAnInterestingCommand)
                {
                    continue;
                }

                if (command.OfPolicyContext)
                {
                    BlockedZones.Add(command.ZoneName);
                }
                else
                {
                    CheckPoint_Zone cpZone = new CheckPoint_Zone();
                    cpZone.Name = command.ZoneName;
                    ApplyConversionIncidentOnCheckPointObject(cpZone, command);
                    CheckObjectNameValidity(cpZone, command);
                    AddCheckPointObject(cpZone);
                }
            }
        }

        private void Add_AddressAndGroupAddress()
        {
            bool inMultipleZones = false;

            foreach (ScreenOSCommand_Address address in ScreenOSAdderssCommands)
            {
                if (address.NotAnInterestingCommand || !IsZoneAvailable(address.Zone, address))
                {
                    continue;
                }

                /* Add Host/Network/Domain*/
                switch (address.AddressType)
                {
                    case ScreenOSCommand_Address.AddressTypeEnum.Host:
                        CheckPoint_Host cpHost = new CheckPoint_Host();
                        cpHost.Name = address.ObjectName;
                        cpHost.IpAddress = address.IpAddress;
                        cpHost.ConvertedCommandId = address.Id;
                        cpHost.Comments = address.Comment;
                        cpHost.Tag = address.Zone;
                        ApplyConversionIncidentOnCheckPointObject(cpHost, address);
                        inMultipleZones = IsNetworkObjectContainedInMultipleZones(cpHost, address);
                        if (!inMultipleZones)
                        {
                            CheckObjectNameValidity(cpHost, address, false);
                            AddCheckPointObject(cpHost);
                        }
                        break;

                    case ScreenOSCommand_Address.AddressTypeEnum.Network:
                        CheckPoint_Network cpNetwork = new CheckPoint_Network();
                        cpNetwork.Name = address.ObjectName;
                        cpNetwork.Subnet = address.IpAddress;
                        cpNetwork.Netmask = address.Netmask;
                        cpNetwork.Tag = address.Zone;
                        cpNetwork.ConvertedCommandId = address.Id;
                        cpNetwork.Comments = address.Comment;
                        ApplyConversionIncidentOnCheckPointObject(cpNetwork, address);
                        inMultipleZones = IsNetworkObjectContainedInMultipleZones(cpNetwork, address);               
                        if (!inMultipleZones)
                        {
                            CheckObjectNameValidity(cpNetwork, address, false);
                            AddCheckPointObject(cpNetwork);
                        }
                        break;

                    case ScreenOSCommand_Address.AddressTypeEnum.Domain:
                        CheckPoint_Domain cpDomain = new CheckPoint_Domain();
                        cpDomain.Name = address.ObjectName;
                        cpDomain.Fqdn = address.Domain;
                        cpDomain.Tag = address.Zone;
                        cpDomain.ConvertedCommandId = address.Id;
                        cpDomain.Comments = address.Comment;
                        ApplyConversionIncidentOnCheckPointObject(cpDomain, address);
                        inMultipleZones = IsNetworkObjectContainedInMultipleZones(cpDomain, address);
                        AlertOnDomainNameModification(address, inMultipleZones);
                        if (!inMultipleZones)
                        {
                            AddCheckPointObject(cpDomain);
                        }
                        break;

                    default:
                        continue;
                }
            }

            /* Add Address groups*/
            foreach (ScreenOSCommand_GroupAddress command in screenOSGroupAddressCommands)
            {
                if (command.NotAnInterestingCommand || !IsZoneAvailable(command.Zone, command))
                {
                    continue;
                }

                CheckPoint_NetworkGroup cpNetworkGroup = new CheckPoint_NetworkGroup();
                cpNetworkGroup.Name = command.GroupName;
                cpNetworkGroup.Comments = command.Comment;
                cpNetworkGroup.Tag = command.Zone;

                if (command.HasAdditionalRealatedObjects)
                {
                    foreach (ScreenOSCommand_GroupAddress groupAddr in command.AdditionalRealatedObjects)
                    {
                        if (groupAddr.NotAnInterestingCommand)
                        {
                            continue;
                        }

                        /* Check if child object has Address name*/
                        if (!string.IsNullOrEmpty(groupAddr.AddressObjectName))
                        {
                            cpNetworkGroup.Members.Add(groupAddr.AddressObjectName);
                        }
                    }
                }

                ApplyConversionIncidentOnCheckPointObject(cpNetworkGroup, command);
                inMultipleZones = IsNetworkObjectContainedInMultipleZones(cpNetworkGroup, command);
                if (!inMultipleZones)
                {
                    CheckObjectNameValidity(cpNetworkGroup, command, inMultipleZones);
                    AddCheckPointObject(cpNetworkGroup);
                }
            }

            // Now, add the objects with the same name that exist in multiple zones.
            foreach (KeyValuePair<CheckPointObject, ScreenOSCommand> cpNetworkObject in _cpNetworkObjectsInMultipleZones)
            {
                string originalName = cpNetworkObject.Key.Name;
                string uniqueName = originalName + "_" + cpNetworkObject.Key.Tag;   // original name combined with the zone name
                cpNetworkObject.Key.Name = uniqueName;   // replace the original name with the unique one
                CheckObjectNameValidity(cpNetworkObject.Key, cpNetworkObject.Value, true);
                AddCheckPointObject(cpNetworkObject.Key);
            }

            // Finally, search and update references in network groups, AFTER all objects are added.
            foreach (KeyValuePair<CheckPointObject, ScreenOSCommand> cpNetworkObject in _cpNetworkObjectsInMultipleZones)
            {
                foreach (CheckPoint_NetworkGroup networkGroup in _cpNetworkGroups)
                {
                    if (cpNetworkObject.Key.Tag == networkGroup.Tag)   // search in the same zone only...
                    {
                        string zoneSuffix = "_" + cpNetworkObject.Key.Tag;
                        string originalName = cpNetworkObject.Key.Name.Replace(zoneSuffix, "");
                        int pos = networkGroup.Members.IndexOf(originalName);
                        if (pos != -1)
                        {
                            networkGroup.Members[pos] = cpNetworkObject.Key.Name;
                        }
                    }
                }
            }
        }

        private void Add_InterfacesAndRoutes()
        {
            foreach (ScreenOSCommand_Interface ifc in ScreenOSInterfaceCommands)
            {
                if (ifc.NotAnInterestingCommand)
                {
                    continue;
                }

                if (ifc.InterfaceObjectType == ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Zone)
                {
                    if (!IsZoneAvailable(ifc.Zone, ifc))
                    {
                        continue;
                    }
                    
                    /* Create check point Network group for interface */
                    CheckPoint_NetworkGroup netGroup = new CheckPoint_NetworkGroup();
                    netGroup.Name = ObjectNameGenerator.InterfaceName(ifc.InterfaceObjName);

                    /* Find / Create check point Network group of related zone*/
                    CheckPoint_NetworkGroup ZoneGroup;
                    if (!_zonesNetworkGroups.TryGetValue(ifc.Zone, out ZoneGroup))
                    {
                        ZoneGroup = new CheckPoint_NetworkGroup();
                        ZoneGroup.Name = ObjectNameGenerator.ZoneName(ifc.Zone);
                        _zonesNetworkGroups[ifc.Zone] = ZoneGroup;
                    }

                    /* Add interface to zone group*/
                    ZoneGroup.Members.Add(netGroup.Name);

                    /* If zone has an interface that leads to the internet, mark it*/
                    if (ifc.LeadsToInternet)
                    {
                        ZoneGroup.Tag = "DefaultGateway";
                    }

                    /* Add static routes to interface group*/
                    foreach (ScreenOSCommand_Interface.Subnet subnet in ifc.Topology)
                    {
                        CheckPoint_Network staticNet = new CheckPoint_Network();
                        staticNet.Name = ObjectNameGenerator.StaticRouteName(subnet.Network, subnet.Netmask);
                        staticNet.Subnet = subnet.Network;
                        staticNet.Netmask = subnet.Netmask;
                        ApplyConversionIncidentOnCheckPointObject(staticNet, subnet.RouteOrig);
                        AddCheckPointObject(staticNet);
                        netGroup.Members.Add(staticNet.Name);
                    }

                    /* Add all sub networks in interfaces*/
                    if (ifc.HasAdditionalRealatedObjects)
                    {
                        foreach (ScreenOSCommand_Interface child in ifc.AdditionalRealatedObjects)
                        {
                            if (child.InterfaceObjectType == ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Ip && !child.NotAnInterestingCommand)
                            {
                                CheckPoint_Network staticNet = new CheckPoint_Network();
                                staticNet.Subnet = NetworkUtils.GetNetwork(child.IP, child.Mask);
                                staticNet.Netmask = child.Mask;
                                staticNet.Name = ObjectNameGenerator.NetworkName(staticNet.Subnet, staticNet.Netmask = child.Mask);
                                ApplyConversionIncidentOnCheckPointObject(netGroup, child);
                                AddCheckPointObject(staticNet);

                                netGroup.Members.Add(staticNet.Name);
                                if (child.IsSecondery == false)
                                {
                                    CheckPoint_Host host = new CheckPoint_Host();
                                    host.Name = ObjectNameGenerator.HostInterface(ifc.InterfaceObjName);
                                    host.IpAddress = child.IP;
                                    AddCheckPointObject(host);
                                }
                            }
                            else if (child.InterfaceObjectType == ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Nat && !child.NotAnInterestingCommand)
                            {
                                netGroup.Tag = "NAT";
                            }
                        }
                    }

                    ApplyConversionIncidentOnCheckPointObject(netGroup,ifc);
                    CheckObjectNameValidity(netGroup, ifc);
                    AddCheckPointObject(netGroup);
                }
            }
        }

        private void Add_or_Modify_InterfaceNetworkGroups()
        {
            var interfaceGroupObjects = new List<CheckPoint_NetworkGroup>();
            //_cpNetworkGroups
            foreach (ScreenOSCommand_Interface ifc in ScreenOSInterfaceCommands)
            {
                string interfaceGroupName = ObjectNameGenerator.InterfaceName(ifc.InterfaceObjName);
                var cpObject = _cpObjects.GetObject(interfaceGroupName);
                if (cpObject != null)
                {
                    interfaceGroupObjects.Add((CheckPoint_NetworkGroup)cpObject);
                }
            }

            var modifiedNetworkGroups = Add_or_Modify_InterfaceNetworkGroups(interfaceGroupObjects);

            // Apply object name verification.
            foreach (var modifiedNetworkGroup in modifiedNetworkGroups)
            {
                if (_cpUnsafeNames.Contains(modifiedNetworkGroup))
                {
                    _cpUnsafeNames.Add(modifiedNetworkGroup + "_include");
                    _cpUnsafeNames.Add(modifiedNetworkGroup + "_exclude");
                }
            }
        }

        private void Add_ZonesNetworkGroups()
        {
            foreach (KeyValuePair<string, CheckPoint_NetworkGroup> entry in _zonesNetworkGroups)
            {
                entry.Value.CreateAfterGroupsWithExclusion = true;
                CheckObjectNameValidity(entry.Value, new ScreenOSCommand());
                AddCheckPointObject(entry.Value);
            }
        }

        private void Add_IpPool()
        {
            foreach (ScreenOSCommand_IPpool command in ScreenOSIpPoolCommands)
            {
                if (command.NotAnInterestingCommand == false)
                {
                    CheckPoint_Range cpRange = new CheckPoint_Range();
                    cpRange.Name = command.ObjectName;
                    cpRange.Comments = command.Comment;
                    cpRange.RangeFrom = command.IpAddressFirst;
                    cpRange.RangeTo = command.IpAddressLast;
                    ApplyConversionIncidentOnCheckPointObject(cpRange, command);
                    CheckObjectNameValidity(cpRange, command);
                    AddCheckPointObject(cpRange);
                }
            }
        }

        private void Add_Services()
        {
            foreach (ScreenOSCommand_Service service in ScreenOSServiceCommands)
            {
                List<CheckPointObject> serviceObjects = new List<CheckPointObject>();
                List<string> cpPredefinedServiceName = new List<string>();
                ServiceCommandSimplifier simplifiedService = new ServiceCommandSimplifier(service);

                if (simplifiedService.Size == 0)
                {
                    continue;
                }

                foreach (ServiceProtocolObject subService in simplifiedService.Services)
                {
                    /* Check if service is predefined in Checkpoint*/
                    string cpKnownService = "";
                    if (DoesServiceIsPredefinedInCheckPoint(subService.ToCheckPointPortInfo(), out cpKnownService))
                    {
                        cpPredefinedServiceName.Add(cpKnownService);
                        subService.OrigService.ConversionIncidentType = ConversionIncidentType.Informative;
                        string errorTitle = string.Format("ScreenOS service is predefined in Check Point. In any use of service, predefined service will be used");
                        string errorDescription = string.Format("Service object details: {0}| Predefined service name: {1}.", subService.OrigService.Text, cpKnownService);
                        _conversionIncidents.Add(new ConversionIncident(subService.OrigService.Id, errorTitle, errorDescription, ConversionIncidentType.Informative));
                        continue;
                    }

                    switch (subService.ProtocolType)
                    {
                        case ServiceProtocolObject.ProtocolTypeEnum.Tcp:
                            serviceObjects.Add(new CheckPoint_TcpService());
                            ((CheckPoint_TcpService)serviceObjects.Last()).Port = ((ServiceProtocolObject_Tcp)subService).DstPort;
                            break;

                        case ServiceProtocolObject.ProtocolTypeEnum.Udp:
                            serviceObjects.Add(new CheckPoint_UdpService());
                            ((CheckPoint_UdpService)serviceObjects.Last()).Port = ((ServiceProtocolObject_Udp)subService).DstPort;
                            break;

                        case ServiceProtocolObject.ProtocolTypeEnum.Ip:
                            serviceObjects.Add(new CheckPoint_OtherService());
                            ((CheckPoint_OtherService)serviceObjects.Last()).IpProtocol = ((ServiceProtocolObject_Ip)subService).Protocol;
                            break;

                        case ServiceProtocolObject.ProtocolTypeEnum.Icmp:
                            serviceObjects.Add(new CheckPoint_IcmpService());
                            ((CheckPoint_IcmpService)serviceObjects.Last()).Type = ((ServiceProtocolObject_Icmp)subService).IcmpType.ToString();
                            ((CheckPoint_IcmpService)serviceObjects.Last()).Code = ((ServiceProtocolObject_Icmp)subService).IcmpCode.ToString();
                            break;

                        case ServiceProtocolObject.ProtocolTypeEnum.Sun_rpc:
                            serviceObjects.Add(new CheckPoint_RpcService());
                            ((CheckPoint_RpcService)serviceObjects.Last()).ProgramNumber = ((ServiceProtocolObject_SunRPC)subService).Program;
                            break;

                        case ServiceProtocolObject.ProtocolTypeEnum.Ms_rpc:
                            serviceObjects.Add(new CheckPoint_DceRpcService());
                            ((CheckPoint_DceRpcService)serviceObjects.Last()).InterfaceUuid = ((ServiceProtocolObject_MsRPC)subService).Uuid;
                            break;

                        default:
                            break;
                    }

                    serviceObjects.Last().Name = ObjectNameGenerator.ServiceName(simplifiedService.Name, subService);
                }

                /* If Multiple services under same service name*/
                CheckPoint_ServiceGroup serviceGroup = null;
                if (serviceObjects.Count + cpPredefinedServiceName.Count > 1)
                {
                    serviceGroup = new CheckPoint_ServiceGroup();
                    serviceGroup.Name = ObjectNameGenerator.ServiceGroup(simplifiedService.Name);
                    ScreenOS2CheckPointServicesNameDic[simplifiedService.Name] = serviceGroup.Name;
                }
                else if (serviceObjects.Count == 1)
                {
                    ScreenOS2CheckPointServicesNameDic[simplifiedService.Name] = serviceObjects[0].Name;
                }
                else if (cpPredefinedServiceName.Count == 1)
                {
                    ScreenOS2CheckPointServicesNameDic[simplifiedService.Name] = cpPredefinedServiceName.First();
                }

                /* Apply Incident to service objects*/
                if (serviceGroup != null || serviceObjects.Any())
                {
                    CheckPointObject cpServiceObj = serviceGroup != null ? serviceGroup : serviceObjects.First();
                    ApplyConversionIncidentOnCheckPointNestedObject(cpServiceObj, service);
                }

                /* Add check point services */
                foreach (CheckPointObject cpService in serviceObjects)
                {
                    CheckObjectNameValidity(cpService, service);
                    AddCheckPointObject(cpService);
                    if (serviceGroup != null)
                    {
                        serviceGroup.Members.Add(cpService.Name);
                    }
                }

                /* Add predefined services and add group if exist*/
                if (serviceGroup != null)
                {
                    foreach (string predefined in cpPredefinedServiceName)
                    {
                        serviceGroup.Members.Add(predefined);
                    }
                    CheckObjectNameValidity(serviceGroup, service);
                    AddCheckPointObject(serviceGroup);
                }
            }
        }

        private void Add_GroupServices()
        {
            foreach (ScreenOSCommand_GroupService command in ScreenOSGroupServiceCommands)
            {
                if (command.NotAnInterestingCommand)
                {
                    continue;
                }

                CheckPoint_ServiceGroup cpServiceGroup = new CheckPoint_ServiceGroup();
                cpServiceGroup.Name = command.GroupName;

                /* Check if head object has comment*/
                if (!string.IsNullOrEmpty(command.Comment))
                {
                    cpServiceGroup.Comments = command.Comment;
                }

                if (command.HasAdditionalRealatedObjects)
                {
                    foreach (ScreenOSCommand_GroupService groupService in command.AdditionalRealatedObjects)
                    {
                        if (groupService.NotAnInterestingCommand)
                        {
                            continue;
                        }

                        /* Check if child object has Address name*/
                        if (!string.IsNullOrEmpty(groupService.ServiceObjectName))
                        {
                            if (ScreenOS2CheckPointServicesNameDic.ContainsKey(groupService.ServiceObjectName))
                            {
                                cpServiceGroup.Members.Add(ScreenOS2CheckPointServicesNameDic[groupService.ServiceObjectName]);
                            }
                            else
                            {
                                cpServiceGroup.Members.Add(CreateCheckPointServiceOrGroupForPredefinedScreenOsService(groupService.ServiceObjectName));
                            }
                        }

                        /* Check for each child if there ConversionIncident*/
                        ApplyConversionIncidentOnCheckPointObject(cpServiceGroup, groupService);
                    }
                }

                ScreenOS2CheckPointServicesNameDic[cpServiceGroup.Name] = cpServiceGroup.Name;
                CheckObjectNameValidity(cpServiceGroup, command);
                AddCheckPointObject(cpServiceGroup);
            }
        }

        private void Convert_policies()
        {
            CheckPoint_Package cpPackage = new CheckPoint_Package();
            cpPackage.Name = _policyPackageName;

            Add_ParentLayer(cpPackage);

            Add_IntraZoneRules(cpPackage);

            Add_InterZoneRules(cpPackage);

            Add_GlubalRules(cpPackage);

            AddCheckPointObject(cpPackage);
        }

        private void Add_ParentLayer(CheckPoint_Package package)
        {
            package.ParentLayer.Name = ObjectNameGenerator.PackageName();

            /* Add all intra and inter Zone policies*/
            HashSet<string> intraPolicyZones = new HashSet<string>();
            HashSet<string> interPolicyZones = new HashSet<string>();

            foreach (PolicyCommandSimplifier policy in PolicySimplifiedList)
            {
                if (policy.ZoneDirection == PolicyCommandSimplifier.ZoneDirectionEnum.Intra)
                {
                    intraPolicyZones.Add(policy.FromZone);
                }
                else if (policy.ZoneDirection == PolicyCommandSimplifier.ZoneDirectionEnum.Inter)
                {
                    interPolicyZones.Add(policy.FromZone + "\"" + policy.ToZone);
                }
            }

            /* Add all Intra Zones with rules to parent layer*/
            foreach (string intra in intraPolicyZones)
            {
                CheckPointObject cpObject = _cpObjects.GetObject(intra);
                if (cpObject == null)
                {
                    continue;
                }

                CheckPoint_Rule cpRule = new CheckPoint_Rule();
                cpRule.Source.Add(cpObject);
                cpRule.Destination.Add(cpObject);
                cpRule.Action = CheckPoint_Rule.ActionType.SubPolicy;
                cpRule.SubPolicyName = ObjectNameGenerator.SubPolicyByZonesName(cpObject.Name, cpObject.Name);
                cpRule.Layer = package.NameOfAccessLayer;
                cpRule.Tag = "intra";
                package.ParentLayer.Rules.Add(cpRule);
            }

            /* Add all Intra Zones with block and with no rules to parent layer*/
            foreach (CheckPoint_Zone cpZone in _cpZones)
            {
                if (intraPolicyZones.Contains(cpZone.Name) == false)
                {
                    CheckPoint_Rule cpRule = new CheckPoint_Rule();
                    cpRule.Source.Add(cpZone);
                    cpRule.Destination.Add(cpZone);
                    cpRule.Action = CheckPoint_Rule.ActionType.SubPolicy;
                    cpRule.SubPolicyName = ObjectNameGenerator.SubPolicyByZonesName(cpZone.Name, cpZone.Name);
                    cpRule.Layer = package.NameOfAccessLayer;
                    cpRule.Tag = "intra";
                    package.ParentLayer.Rules.Add(cpRule);
                }
            }

            /* Add all Inter Zones with rules to parent layer*/
            foreach (string inter in interPolicyZones)
            {
                List<string> tempArrayList = inter.Split('"').ToList();

                if (tempArrayList.Count() != 2)
                {
                    continue;
                }

                CheckPointObject cpSrcObject = _cpObjects.GetObject(tempArrayList[0]);
                if (cpSrcObject == null)
                {
                    continue;
                }

                CheckPointObject cpDstObject = _cpObjects.GetObject(tempArrayList[1]);
                if (cpDstObject == null)
                {
                    continue;
                }

                CheckPoint_Rule cpRule = new CheckPoint_Rule();
                cpRule.Source.Add(cpSrcObject);
                cpRule.Destination.Add(cpDstObject);
                cpRule.Action = CheckPoint_Rule.ActionType.SubPolicy;
                cpRule.SubPolicyName = ObjectNameGenerator.SubPolicyByZonesName(cpSrcObject.Name, cpDstObject.Name);
                cpRule.Layer = package.NameOfAccessLayer;
                cpRule.Tag = "inter";
                package.ParentLayer.Rules.Add(cpRule);
            }

            /* Add implicit cleanup rule to parent layer*/
            CheckPoint_Rule cpCleanupRule = new CheckPoint_Rule();
            cpCleanupRule.Name = "Cleanup rule";
            if (ScreenOSPolicyCommands.Where(g => g.IsDefaultPermitAll == true).Any())
            {
                cpCleanupRule.Action = CheckPoint_Rule.ActionType.Accept;
                cpCleanupRule.Comments = "default-permit-all Enabled";
            }
            else
            {
                cpCleanupRule.Action = CheckPoint_Rule.ActionType.Drop;
                cpCleanupRule.Comments = "default-permit-all Disabled";
            }

            cpCleanupRule.Layer = package.NameOfAccessLayer;
            cpCleanupRule.Tag = "global";
            package.ParentLayer.Rules.Add(cpCleanupRule);
        }

        private void Add_IntraZoneRules(CheckPoint_Package package)
        {
            Dictionary<string, CheckPoint_Layer> zone2cpLayer = new Dictionary<string, CheckPoint_Layer>();

            foreach (PolicyCommandSimplifier policy in PolicySimplifiedList)
            {
                /* Make rules from only intra policies*/
                if (policy.ZoneDirection != PolicyCommandSimplifier.ZoneDirectionEnum.Intra)
                {
                    continue;
                }

                string zoneName = policy.FromZone;
                if (!IsZoneAvailable(zoneName, policy.OrigPolicy))
                {
                    continue;
                }

                /*  Check if layer exist, if not create new layer*/
                CheckPoint_Layer cpLayer = null;
                if (!zone2cpLayer.ContainsKey(zoneName))
                {
                    zone2cpLayer[zoneName] = new CheckPoint_Layer();
                    zone2cpLayer[zoneName].Name = ObjectNameGenerator.SubPolicyByZonesName(zoneName, zoneName);
                }

                /* Add rule to layer */
                cpLayer = zone2cpLayer[zoneName];
                CheckPoint_Rule cpRule = CreateRule(policy, cpLayer.Name);
                cpLayer.Rules.Add(cpRule);
            }

            /* Add zones that does not have policies*/
            foreach (CheckPoint_Zone cpZone in _cpZones)
            {
                if (zone2cpLayer.ContainsKey(cpZone.Name) == false)
                {
                    zone2cpLayer[cpZone.Name] = new CheckPoint_Layer();
                    zone2cpLayer[cpZone.Name].Name = ObjectNameGenerator.SubPolicyByZonesName(cpZone.Name, cpZone.Name);
                }
            }

            /* Add layers to sub policy package*/
            foreach (KeyValuePair<string, CheckPoint_Layer> cpLayer in zone2cpLayer)
            {
                /* Add implicit cleanup rule to layer*/
                CheckPoint_Rule cpInterBlockRule = new CheckPoint_Rule();
                cpInterBlockRule.Name = CheckPoint_Rule.SubPolicyCleanupRuleName;
                if (BlockedZones.Contains(cpLayer.Key) == true)
                {
                    cpInterBlockRule.Action = CheckPoint_Rule.ActionType.Drop;
                    cpInterBlockRule.Comments = "Intra Zone Blocking Enabled";
                }
                else
                {
                    cpInterBlockRule.Action = CheckPoint_Rule.ActionType.Accept;
                    cpInterBlockRule.Comments = "Intra Zone Blocking Disabled";
                }
                cpInterBlockRule.Layer = zone2cpLayer[cpLayer.Key].Name;
                cpLayer.Value.Rules.Add(cpInterBlockRule);

                package.SubPolicies.Add(cpLayer.Value);
                validatePackage(package);
            }
        }

        private void Add_InterZoneRules(CheckPoint_Package package)
        {
            Dictionary<string, CheckPoint_Layer> zone2cpLayer = new Dictionary<string, CheckPoint_Layer>();

            foreach (PolicyCommandSimplifier policy in PolicySimplifiedList)
            {
                /* Make rules from only intra and inter policies*/
                string zoneName = "";
                if (policy.ZoneDirection != PolicyCommandSimplifier.ZoneDirectionEnum.Inter)
                {
                    continue;
                }

                if (!IsZoneAvailable(policy.FromZone, policy.OrigPolicy) || !IsZoneAvailable(policy.ToZone, policy.OrigPolicy))
                {
                    continue;
                }

                zoneName = ObjectNameGenerator.SubPolicyByZonesName(policy.FromZone, policy.ToZone);

                /*  Check if layer exist, if not create new layer*/
                CheckPoint_Layer cpLayer = null;
                if (!zone2cpLayer.ContainsKey(zoneName))
                {
                    zone2cpLayer[zoneName] = new CheckPoint_Layer();
                    zone2cpLayer[zoneName].Name = zoneName;
                }

                /* Add rule to layer */
                cpLayer = zone2cpLayer[zoneName];
                CheckPoint_Rule cpRule = CreateRule(policy, zoneName);
                cpRule.Layer = cpLayer.Name;
                cpLayer.Rules.Add(cpRule);
            }

            /* Add layers to sub policy package*/
            foreach (CheckPoint_Layer cpLayer in zone2cpLayer.Values)
            {
                /* Add implicit cleanup rule to layer*/
                CheckPoint_Rule cpCleanupRule = new CheckPoint_Rule();
                cpCleanupRule.Name = CheckPoint_Rule.SubPolicyCleanupRuleName;
                if (ScreenOSPolicyCommands.Where(g => g.IsDefaultPermitAll == true).Any())
                {
                    cpCleanupRule.Action = CheckPoint_Rule.ActionType.Accept;
                    cpCleanupRule.Comments = "default-permit-all Enabled";
                }
                else
                {
                    cpCleanupRule.Action = CheckPoint_Rule.ActionType.Drop;
                    cpCleanupRule.Comments = "default-permit-all Disabled";
                }
                cpCleanupRule.Layer = cpLayer.Name;
                cpLayer.Rules.Add(cpCleanupRule);

                package.SubPolicies.Add(cpLayer);
                validatePackage(package);
            }
        }

        private void Add_GlubalRules(CheckPoint_Package package)
        {
            foreach (PolicyCommandSimplifier policy in PolicySimplifiedList)
            {
                /* Make rules from only global policies*/
                if (policy.ZoneDirection != PolicyCommandSimplifier.ZoneDirectionEnum.Global)
                {
                    continue;
                }

                /* Create check point rule object*/
                CheckPoint_Rule cpRule = CreateRule(policy, package.NameOfAccessLayer);
                cpRule.Name = "Global_Rule " + policy.PolicyId.ToString();
                cpRule.Tag = "global";

                /* Add to parent layer*/
                int parentLayerLength = package.ParentLayer.Rules.Count > 0 ? package.ParentLayer.Rules.Count : 1;
                package.ParentLayer.Rules.Insert(parentLayerLength - 1, cpRule);

                /* Add to Sub inter policies*/
                foreach (CheckPoint_Layer cpLayer in package.SubPolicies)
                {
                    CheckPoint_Rule cpSubPolicyRule = cpRule.Clone();
                    cpSubPolicyRule.Layer = cpLayer.Name;
                    int listLength = cpLayer.Rules.Count > 0 ? cpLayer.Rules.Count : 1;
                    cpLayer.Rules.Insert(listLength - 1, cpSubPolicyRule);
                }
            }
        }

        private CheckPoint_Rule CreateRule(PolicyCommandSimplifier policy, string layerName)
        {
            CheckPoint_Rule cpRule = new CheckPoint_Rule();

            cpRule.Enabled = policy.IsEnabled;
            cpRule.Name = string.IsNullOrEmpty(policy.PolicyName) ? "Rule" + policy.PolicyId.ToString() : policy.PolicyName.Trim('"');
            cpRule.Layer = layerName;
            cpRule.Tag = policy.FromZone + " " + policy.ToZone;

            if (policy.IsLogEnabled)
            {
                cpRule.Track = CheckPoint_Rule.TrackTypes.Log;
            }
            else
            {
                cpRule.Track = CheckPoint_Rule.TrackTypes.None;
            }

            switch (policy.Action)
            {
                case ScreenOSCommand_Policy.ActoinEnum.Permit:
                    cpRule.Action = CheckPoint_Rule.ActionType.Accept;
                    break;

                case ScreenOSCommand_Policy.ActoinEnum.Reject:
                    cpRule.Action = CheckPoint_Rule.ActionType.Reject;
                    break;

                case ScreenOSCommand_Policy.ActoinEnum.Deny:
                case ScreenOSCommand_Policy.ActoinEnum.Na:
                    cpRule.Action = CheckPoint_Rule.ActionType.Drop;
                    break;
            }

            cpRule.SourceNegated = policy.SourceNegated;
            cpRule.DestinationNegated = policy.DestinationNegated;

            ApplyConversionIncidentOnCheckPointObject(cpRule, policy.OrigPolicy);

            /* Source */
            foreach (string src in policy.SrcAddr)
            {
                cpRule.Source.Add(GetSrcObjectByNameFromPolicy(src, policy));
            }

            /* Destination */
            foreach (string dst in policy.DstAddr)
            {
                cpRule.Destination.Add(GetDstObjectByNameFromPolicy(dst, policy));
            }

            /* Services*/
            foreach (string serviceOs in policy.Services)
            {
                cpRule.Service.Add(GetServiceObjectByNameFromPolicy(serviceOs, policy));
            }

            return cpRule;
        }

        private void CreateRuleFromNATPolicy(PolicyCommandSimplifier policy)
        {
            if (!IsZoneAvailable(policy.FromZone, policy.OrigPolicy) || !IsZoneAvailable(policy.ToZone, policy.OrigPolicy))
            {
                return;
            }

            string subPolicyLayer = ObjectNameGenerator.SubPolicyByZonesName(policy.FromZone, policy.ToZone);
            _convertedNatPolicy2Rules.Add(CreateRule(policy, subPolicyLayer));
            _convertedNatPolicy2Rules.Last().Layer = subPolicyLayer;
        }

        private void MarkNatRulesNotIntersting()
        {
            /* Interface*/
            foreach (ScreenOSCommand interFace in ScreenOSInterfaceCommands)
            {
                ScreenOSCommand_Interface ssgInterface = (ScreenOSCommand_Interface)interFace;
                if (ssgInterface.InterfaceObjectType == ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Nat || ssgInterface.NatObject != null)
                {
                    ssgInterface.NotAnInterestingCommand = true;
                    ssgInterface.ConversionIncidentType = ConversionIncidentType.None;
                }

                if (ssgInterface.HasAdditionalRealatedObjects)
                {
                    foreach (ScreenOSCommand subInterface in ssgInterface.AdditionalRealatedObjects)
                    {
                        ScreenOSCommand_Interface ssgSubInterface = (ScreenOSCommand_Interface)subInterface;
                        if (ssgSubInterface.InterfaceObjectType == ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Nat || ssgSubInterface.NatObject != null)
                        {
                            subInterface.NotAnInterestingCommand = true;
                            subInterface.ConversionIncidentType = ConversionIncidentType.None;
                        }
                    }
                }
            }

            /* dip group*/
            foreach (ScreenOSCommand dip in ScreenOSGroupDipCommands)
            {
                dip.NotAnInterestingCommand = true;
                dip.ConversionIncidentType = ConversionIncidentType.None;
                if (dip.HasAdditionalRealatedObjects)
                {
                    foreach (ScreenOSCommand subDip in dip.AdditionalRealatedObjects)
                    {
                        subDip.NotAnInterestingCommand = true;
                        subDip.ConversionIncidentType = ConversionIncidentType.None;
                    }
                }
            }

            /* Policy*/
            foreach (ScreenOSCommand policy in ScreenOSPolicyCommands)
            {
                ScreenOSCommand_Policy natPolicy = (ScreenOSCommand_Policy)policy;
                if (natPolicy.PolicyNatType != ScreenOSCommand_Policy.PolicyNatTypeEnum.Policy)
                {
                    natPolicy.NotAnInterestingCommand = true;
                    natPolicy.ConversionIncidentType = ConversionIncidentType.None;
                    if (natPolicy.HasAdditionalRealatedObjects)
                    {
                        foreach (ScreenOSCommand subPolicy in natPolicy.AdditionalRealatedObjects)
                        {
                            subPolicy.NotAnInterestingCommand = true;
                            subPolicy.ConversionIncidentType = ConversionIncidentType.None;
                        }
                    }
                }
            }
        }

        private void Add_Mip_Nat()
        {        
            foreach (ScreenOSCommand_Policy natPolicy in ScreenOSPolicyCommands)
            {
                if (natPolicy.PolicyNatType == ScreenOSCommand_Policy.PolicyNatTypeEnum.Mip
                    && natPolicy.NotAnInterestingCommand == false)
                {
                    PolicyCommandSimplifier simpleMipPolicy = new PolicyCommandSimplifier(natPolicy);
                    Dictionary<string, List<CheckPointObject>> mip2CheckpointObj = new Dictionary<string, List<CheckPointObject>>();

                    /* Create Objects for Mip*/
                    for (int i = 0; i < simpleMipPolicy.DstAddr.Count; ++i)
                    {
                        CheckPoint_NAT_Rule natRuleInDirection = new CheckPoint_NAT_Rule();
                        natRuleInDirection.Enabled = simpleMipPolicy.IsEnabled;
                        natRuleInDirection.Method = CheckPoint_NAT_Rule.NatMethod.Static;
                        CheckPoint_NAT_Rule natRuleOutDirection = new CheckPoint_NAT_Rule();
                        natRuleOutDirection.Enabled = simpleMipPolicy.IsEnabled;
                        natRuleOutDirection.Method = CheckPoint_NAT_Rule.NatMethod.Static;

                        string destObj = simpleMipPolicy.DstAddr[i];

                        /* Find Mip in interface*/
                        if (!mip2CheckpointObj.ContainsKey(destObj))
                        {
                            mip2CheckpointObj[destObj] = new List<CheckPointObject>();

                            ScreenOSCommand_Interface ifc = null;
                            if (GetMipObjByMipName(destObj, out ifc))
                            {
                                ScreenOsCommand_InterfceNatMIP mipObj = (ScreenOsCommand_InterfceNatMIP)ifc.NatObject;

                                /* Get original checkpoint object*/
                                CheckPointObject cpMipIPObj = GetCheckPointObjByIp(mipObj.Mip, mipObj.Mask);
                                if (cpMipIPObj == null)
                                {
                                    /* Create new checkpoint object*/
                                    cpMipIPObj = CreateCheckPointObjByIp(mipObj.Mip, mipObj.Mask, ObjectNameGenerator.MipOriginalName(mipObj.Mip, mipObj.Mask));
                                }
                                mip2CheckpointObj[destObj].Add(cpMipIPObj);
                                simpleMipPolicy.DstAddr[i] = cpMipIPObj.Name;

                                /* Get translated checkpoint object*/
                                cpMipIPObj = GetCheckPointObjByIp(mipObj.Ip, mipObj.Mask);
                                if (cpMipIPObj == null)
                                {
                                    /* Create new checkpoint object*/
                                    cpMipIPObj = CreateCheckPointObjByIp(mipObj.Ip, mipObj.Mask, ObjectNameGenerator.MipTranslatedName(mipObj.Mip, mipObj.Mask));
                                }
                                mip2CheckpointObj[destObj].Add(cpMipIPObj);
                            }
                            else
                            {
                                /* Interface command with MIP info not exist*/
                                natPolicy.ConversionIncidentMessage = "Mip interface object: " + destObj + " does not exist";
                                natPolicy.ConversionIncidentType = ConversionIncidentType.ManualActionRequired;

                                mip2CheckpointObj[destObj].Add(GetCheckPointObjectOrCreateDummy(destObj + "_orig",
                                                        CheckPointDummyObjectType.Network,
                                                        simpleMipPolicy.OrigPolicy,
                                                        "Error creating  NAT rule, from ScreenOS NAT rules of type MIP",
                                                        "Interface MIP object details: " + destObj + "."));

                                mip2CheckpointObj[destObj].Add(GetCheckPointObjectOrCreateDummy(destObj + "_translated",
                                                        CheckPointDummyObjectType.Network,
                                                        simpleMipPolicy.OrigPolicy,
                                                        "Error creating  NAT rule, from ScreenOS NAT rules of type MIP",
                                                        "Interface MIP object details: " + destObj + "."));
                            }
                        }

                        if (simpleMipPolicy.OrigPolicy.MixedNAT)
                        {
                            /* No relevant info in interface Vip command*/
                            string errorTitle = string.Format("Complex ScreenOS NAT policy is not supported, only MIP NAT will be considered");
                            string errorDescription = string.Format("Policy NAT object details: {0}.", simpleMipPolicy.OrigPolicy.Text);
                            _conversionIncidents.Add(new ConversionIncident(simpleMipPolicy.OrigPolicy.Id, errorTitle, errorDescription, ConversionIncidentType.Informative));
                        }

                        /* Create Nat rule*/
                        CheckPointObject srcOrig = GetSrcObjectFromPolicyForNAT(simpleMipPolicy);
                        CheckPointObject serviceOrig = GetServiceObjectFromPolicyForNAT(simpleMipPolicy);

                        /* Nat in direction of MIP*/
                        natRuleInDirection.Service = serviceOrig;
                        natRuleInDirection.Source = srcOrig;
                        natRuleInDirection.Destination = mip2CheckpointObj[destObj][0];
                        natRuleInDirection.TranslatedDestination = mip2CheckpointObj[destObj][1];
                        natRuleInDirection.Tag = "MIP";
                        _cpNatRules.Add(natRuleInDirection);

                        /* Nat out direction of MIP*/
                        natRuleOutDirection.Source = mip2CheckpointObj[destObj][1];
                        natRuleOutDirection.Destination = srcOrig;
                        natRuleOutDirection.Service = serviceOrig;
                        natRuleOutDirection.TranslatedSource = mip2CheckpointObj[destObj][0];
                        natRuleOutDirection.Tag = "MIP";
                        _cpNatRules.Add(natRuleOutDirection);
                    }

                    /* Create Policy*/
                    CreateRuleFromNATPolicy(simpleMipPolicy);
                }
            }
        }

        private void Add_Vip_Nat()
        {
            foreach (ScreenOSCommand_Policy natPolicy in ScreenOSPolicyCommands)
            {
                if (natPolicy.PolicyNatType == ScreenOSCommand_Policy.PolicyNatTypeEnum.Vip && !natPolicy.NotAnInterestingCommand)
                {
                    PolicyCommandSimplifier simpleVipPolicy = new PolicyCommandSimplifier(natPolicy);
                    Dictionary<string, NatVipForCheckPoint> vip2CheckpointObj = new Dictionary<string, NatVipForCheckPoint>();

                    /* Create Objects for Vip*/
                    for (int i = 0; i < simpleVipPolicy.DstAddr.Count; ++i)
                    {
                        string destObj = simpleVipPolicy.DstAddr[i];

                        /* Check if VIP already arranged*/
                        if (!vip2CheckpointObj.ContainsKey(destObj))
                        {
                            /* Find Vip in interface Vip commands*/
                            List<ScreenOSCommand_Interface> ifcList = null;
                            if (GetVipObjByVipName(destObj, out ifcList))
                            {
                                ScreenOsCommand_InterfceNatVIP vipObj = (ScreenOsCommand_InterfceNatVIP)ifcList.First().NatObject;

                                /* Get original checkpoint object*/
                                CheckPointObject cpVipIPObj = GetCheckPointObjByIp(vipObj.Vip, ScreenOSNetworkUtil.HostMask());
                                if (cpVipIPObj == null)
                                {
                                    cpVipIPObj = CreateCheckPointObjByIp(vipObj.Vip, ScreenOSNetworkUtil.HostMask(), ObjectNameGenerator.VipOriginalName(vipObj.Vip));
                                }

                                /* Initiate Vip helper class*/
                                vip2CheckpointObj[destObj] = new NatVipForCheckPoint()
                                {
                                    OrigDestination = cpVipIPObj,
                                    VipInfoInCpObjectsList = new List<NatVipForCheckPoint.VipInfoInCpObjects>()
                                };

                                simpleVipPolicy.DstAddr[i] = cpVipIPObj.Name;

                                /* Move through all Same VIP id commands of that interface*/
                                foreach (ScreenOSCommand_Interface ifc in ifcList)
                                {
                                    if (((ScreenOsCommand_InterfceNatVIP)ifc.NatObject).VipData != null)
                                    {
                                        if (ifc.ConversionIncidentType != ConversionIncidentType.None && !string.IsNullOrEmpty(ifc.ConversionIncidentMessage))
                                        {
                                            string errorTitle = ifc.ConversionIncidentMessage;
                                            string errorDescription = string.Format("Interface VIP object details: {0}.", ifc.Text);
                                            _conversionIncidents.Add(new ConversionIncident(ifc.Id, errorTitle, errorDescription, ifc.ConversionIncidentType));
                                        }

                                        /* Get VIP rule information from Interface VIP command*/
                                        ScreenOsCommand_InterfceNatVIP.VipInfo vipInfo = ((ScreenOsCommand_InterfceNatVIP)ifc.NatObject).VipData;
                                        NatVipForCheckPoint.VipInfoInCpObjects vipInfoInCpObjects = new NatVipForCheckPoint.VipInfoInCpObjects();

                                        /* Get translated address object*/
                                        cpVipIPObj = GetCheckPointObjByIp(vipInfo.DetsIp, ScreenOSNetworkUtil.HostMask());
                                        if (cpVipIPObj == null)
                                        {
                                            cpVipIPObj = CreateCheckPointObjByIp(vipInfo.DetsIp, ScreenOSNetworkUtil.HostMask(), ObjectNameGenerator.VipTranslatedName(vipObj.Vip, vipInfo.DetsIp));
                                        }
                                        vipInfoInCpObjects.IpTranslated = cpVipIPObj;

                                        /* Get translated port object*/
                                        string serviceType = "";
                                        cpVipIPObj = GetCheckPointServiceObjByName(vipInfo.DestServiceName);
                                        if (cpVipIPObj == null)
                                        {
                                            /* This should not happen, service should exist already*/
                                            cpVipIPObj = GetCheckPointObjectOrCreateDummy(vipInfo.DestServiceName,
                                                                                CheckPointDummyObjectType.Service,
                                                                                ifc,
                                                                                "Error creating NAT rule, service " + vipInfo.DestServiceName + " does not exist in Check Point  objects",
                                                                                "Interface VIP object details: " + destObj + ".");
                                        }
                                        else
                                        {
                                            serviceType = cpVipIPObj.GetType().ToString().Substring(cpVipIPObj.GetType().ToString().IndexOf("_") + 1);
                                            serviceType = serviceType.Replace("Service", "").ToUpper();

                                            /* Get type of predefined service*/
                                            if (serviceType == "PREDIFINEDOBJECT")
                                            {
                                                List<string> ports = ScreenOSKnownServices.ConvertPredefinedServiceNameToPort(vipInfo.DestServiceName);
                                                if (ports.Any() == false)
                                                {
                                                    serviceType = "";
                                                }
                                                else if (ports.Count > 1)
                                                {
                                                    serviceType = "GROUP";
                                                }
                                                else
                                                {
                                                    serviceType = ports.First().Substring(0, ports.First().IndexOf("_"));
                                                }
                                            }
                                        }
                                        vipInfoInCpObjects.portTranslated = cpVipIPObj;

                                        /* Get orig port object*/
                                        cpVipIPObj = GetCheckPointServiceObjByPort(vipInfo.SrcPort, serviceType);
                                        if (cpVipIPObj == null)
                                        {
                                            /* Check if translated service is known and not a group*/
                                            if (string.IsNullOrEmpty(serviceType) || serviceType == "GROUP")
                                            {
                                                cpVipIPObj = GetCheckPointObjectOrCreateDummy("VIP_" + vipObj.Vip + "_" + vipInfo.SrcPort.ToString(),
                                                                                    CheckPointDummyObjectType.Service,
                                                                                    ifc,
                                                                                    "Error creating NAT rule, check if translated service does not exist or a group of services",
                                                                                    "Interface VIP object details: " + ifc.Text + ".");
                                            }
                                            else
                                            {
                                                cpVipIPObj = _cpObjects.GetObject(CreateCheckPointServiceByNameAndPort("VIP", serviceType + "_" + vipInfo.SrcPort.ToString()));
                                            }
                                        }
                                        vipInfoInCpObjects.portOrig = cpVipIPObj;

                                        /* Add to list*/
                                        vip2CheckpointObj[destObj].VipInfoInCpObjectsList.Add(vipInfoInCpObjects);
                                    }
                                    else
                                    {
                                        /* No relevant info in interface Vip command*/
                                        string errorTitle = string.Format("{0}, NAT rule will not be created", ifc.ConversionIncidentMessage);
                                        string errorDescription = string.Format("Interface VIP object details: {0}.", ifc.Text);
                                        _conversionIncidents.Add(new ConversionIncident(ifc.Id, errorTitle, errorDescription, ConversionIncidentType.ManualActionRequired));
                                    }
                                }
                            }
                            else
                            {
                                /* There is no interface VIP command for this policy, configuration error*/
                                natPolicy.ConversionIncidentMessage = "Vip interface object: " + destObj + " does not exist, configuration error";
                                natPolicy.ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                            }
                        }

                        /* Create Nat rules*/
                        CheckPointObject srcOrig = GetSrcObjectFromPolicyForNAT(simpleVipPolicy);
                        NatVipForCheckPoint natRulesToConvert = vip2CheckpointObj[destObj];
                        foreach (NatVipForCheckPoint.VipInfoInCpObjects vipInfoCpObj in natRulesToConvert.VipInfoInCpObjectsList)
                        {
                            CheckPoint_NAT_Rule natRule = new CheckPoint_NAT_Rule();
                            natRule.Enabled = simpleVipPolicy.IsEnabled;
                            natRule.Method = CheckPoint_NAT_Rule.NatMethod.Static;
                            natRule.Source = srcOrig;
                            natRule.Service = vipInfoCpObj.portOrig;
                            natRule.TranslatedService = vipInfoCpObj.portTranslated;
                            natRule.Destination = natRulesToConvert.OrigDestination;
                            natRule.TranslatedDestination = vipInfoCpObj.IpTranslated;
                            natRule.Tag = "VIP";
                            _cpNatRules.Add(natRule);

                        }
                    }

                    if (simpleVipPolicy.OrigPolicy.MixedNAT)
                    {
                        /* No relevant info in interface Vip command*/
                        string errorTitle = string.Format("Complex ScreenOS NAT policy is not supported, only VIP NAT will be considered");
                        string errorDescription = string.Format("Policy NAT object details: {0}.", simpleVipPolicy.OrigPolicy.Text);
                        _conversionIncidents.Add(new ConversionIncident(simpleVipPolicy.OrigPolicy.Id, errorTitle, errorDescription, ConversionIncidentType.Informative));
                    }

                    /* Create Policy*/
                    CreateRuleFromNATPolicy(simpleVipPolicy);
                }
            }
        }

        private void Add_Dip_Nat()
        {
            foreach (ScreenOSCommand_Policy natPolicy in ScreenOSPolicyCommands)
            {
                if (natPolicy.PolicyNatType == ScreenOSCommand_Policy.PolicyNatTypeEnum.Dip && !natPolicy.NotAnInterestingCommand)
                {
                    PolicyCommandSimplifier simpleDipPolicy = new PolicyCommandSimplifier(natPolicy);
                    List<CheckPointObject> cpDipOriginalObj;
                    List<CheckPointObject> cpDipTranslatedObj;
                    List<bool> isPATEnabled;
                    List<bool> isEnabled;
                    string comment ="";
                    
                    if (!Prepare_ObjectsForDipNat(simpleDipPolicy, out cpDipOriginalObj, out cpDipTranslatedObj, out isEnabled, out isPATEnabled, out comment))
                    {
                        continue;
                    }

                    CheckPointObject destOrig = GetDstObjectFromPolicyForNAT(simpleDipPolicy);
                    CheckPointObject serviceOrig = GetServiceObjectFromPolicyForNAT(simpleDipPolicy);

                    /* Create NAT rules*/
                    for (int index = 0; index < cpDipOriginalObj.Count; ++index)
                    {
                        CheckPoint_NAT_Rule natRule = new CheckPoint_NAT_Rule();
                        natRule.Enabled = simpleDipPolicy.IsEnabled;
                        natRule.Method = isPATEnabled[index] ? CheckPoint_NAT_Rule.NatMethod.Hide : CheckPoint_NAT_Rule.NatMethod.Static;
                        natRule.Service = serviceOrig;
                        natRule.Source = cpDipOriginalObj[index];
                        natRule.TranslatedSource = cpDipTranslatedObj[index];
                        natRule.Destination = destOrig;
                        natRule.Comments = comment;
                        natRule.Tag = "DIP";
                        _cpNatRules.Add(natRule);
                    }

                    /* Create Policy*/
                    CreateRuleFromNATPolicy(simpleDipPolicy);
                }
            }
        }

        private void Add_PolicyBasedDestNat()
        {
            foreach (ScreenOSCommand_Policy natPolicy in ScreenOSPolicyCommands)
            {
                if (natPolicy.PolicyNatType == ScreenOSCommand_Policy.PolicyNatTypeEnum.PolicyBaseDest && !natPolicy.NotAnInterestingCommand)
                {
                    PolicyCommandSimplifier simplePolicy = new PolicyCommandSimplifier(natPolicy);
                    CheckPointObject destIpTranslated = null;
                    CheckPointObject destPortTranslated = null;

                    if (!Prepare_ObjectsForPolicyBasedDestNat( simplePolicy, out  destIpTranslated,  out destPortTranslated))
                    {
                        continue;
                    }

                    /* Create NAT rule*/
                    CheckPointObject srcOrig = GetSrcObjectFromPolicyForNAT(simplePolicy);
                    CheckPointObject dstOrig = GetDstObjectFromPolicyForNAT(simplePolicy);
                    CheckPointObject serviceOrig = GetServiceObjectFromPolicyForNAT(simplePolicy);

                    CheckPoint_NAT_Rule natRule = new CheckPoint_NAT_Rule();
                    natRule.Enabled = simplePolicy.IsEnabled;
                    natRule.Method = CheckPoint_NAT_Rule.NatMethod.Static;
                    natRule.Service = serviceOrig;
                    if (destPortTranslated != null)
                    {
                        natRule.TranslatedService = IfTranslatedServiceIsGroupReturnDummy(destPortTranslated, simplePolicy);
                    }
                    natRule.Source = srcOrig;
                    natRule.Destination = dstOrig;
                    natRule.TranslatedDestination = destIpTranslated;
                    natRule.Tag = "PolicyBasedDestNat";
                    _cpNatRules.Add(natRule);

                    /* Create Policy*/
                    CreateRuleFromNATPolicy(simplePolicy);
                }
            }
        }

        private void Add_PolicyBasedSrcDestNat()
        {
            foreach (ScreenOSCommand_Policy natPolicy in ScreenOSPolicyCommands)
            {
                if (natPolicy.PolicyNatType == ScreenOSCommand_Policy.PolicyNatTypeEnum.PolicyBaseSrcDest && !natPolicy.NotAnInterestingCommand)
                {
                    PolicyCommandSimplifier simplePolicy = new PolicyCommandSimplifier(natPolicy);
                    CheckPointObject destIpTranslated = null;
                    CheckPointObject destPortTranslated = null;
                    List<CheckPointObject> cpDipOriginalObj;
                    List<CheckPointObject> cpDipTranslatedObj;
                    List<bool> isPATEnabled;
                    List<bool> isEnabled;
                    string comment = "";

                    /* Get policy based source objects(DIP)*/
                    if (!Prepare_ObjectsForDipNat(simplePolicy, out cpDipOriginalObj, out cpDipTranslatedObj, out isEnabled, out isPATEnabled, out comment))
                    {
                        continue;
                    }

                    /* Get policy based destination objects*/
                    if (!Prepare_ObjectsForPolicyBasedDestNat(simplePolicy, out destIpTranslated, out destPortTranslated))
                    {
                        continue;
                    }

                    CheckPointObject serviceOrig = GetServiceObjectFromPolicyForNAT(simplePolicy);
                    CheckPointObject dstOrig = GetDstObjectFromPolicyForNAT(simplePolicy);
                    CheckPointObject srcOrig = GetSrcObjectFromPolicyForNAT(simplePolicy);

                    if (isPATEnabled[0] && destPortTranslated != null)
                    {
                        string errorTitle = "ScreenOS policy based source & destination NAT policy command. Conflict has been detected in port translation. NAT rules will be created separately for source and destination";
                        string errorDescription = string.Format("Policy NAT object details: {0}.", natPolicy.Text);
                        _conversionIncidents.Add(new ConversionIncident(natPolicy.Id, errorTitle, errorDescription, ConversionIncidentType.Informative));
                    }

                    /* Create NAT rules*/
                    for (int index = 0; index < cpDipOriginalObj.Count; ++index)
                    {
                        /* If PAT enabled and dest translated port exit, Create two separated NAT rules for source and destination NAT*/
                        if (isPATEnabled[index] && destPortTranslated != null)
                        {
                            /* Add DIP NAT rule separately*/
                            CheckPoint_NAT_Rule natRuleSrc = new CheckPoint_NAT_Rule();
                            natRuleSrc.Enabled = isEnabled[index];
                            natRuleSrc.Method = isPATEnabled[index] ? CheckPoint_NAT_Rule.NatMethod.Hide : CheckPoint_NAT_Rule.NatMethod.Static;
                            natRuleSrc.Service = serviceOrig;
                            natRuleSrc.Source = cpDipOriginalObj[index];
                            natRuleSrc.TranslatedSource = cpDipTranslatedObj[index];
                            natRuleSrc.Destination = dstOrig;
                            natRuleSrc.Tag = "PolicyBasedSrcNAT";
                            natRuleSrc.Comments = comment;
                            _cpNatRules.Add(natRuleSrc);

                            /* Add policy based destination NAT rule separately, only once*/
                            if (index == 0)
                            {
                                CheckPoint_NAT_Rule natRuleDst = new CheckPoint_NAT_Rule();
                                natRuleDst.Enabled = isEnabled[index];
                                natRuleDst.Method = CheckPoint_NAT_Rule.NatMethod.Static;
                                natRuleDst.Service = serviceOrig;
                                if (destPortTranslated != null)
                                {
                                    natRuleDst.TranslatedService = IfTranslatedServiceIsGroupReturnDummy(destPortTranslated, simplePolicy);
                                }
                                natRuleDst.Source = srcOrig;
                                natRuleDst.Destination = dstOrig;
                                natRuleDst.TranslatedDestination = destIpTranslated;
                                natRuleDst.Tag = "PolicyBasedDestNAT";
                                natRuleDst.Comments = comment;
                                _cpNatRules.Add(natRuleDst);
                            }
                        }
                        else
                        {
                            /* Create one NAT rule combined from source and destination NAT*/
                            CheckPoint_NAT_Rule natRule = new CheckPoint_NAT_Rule();
                            natRule.Enabled = isEnabled[index];
                            natRule.Method = isPATEnabled[index] ? CheckPoint_NAT_Rule.NatMethod.Hide : CheckPoint_NAT_Rule.NatMethod.Static;
                            natRule.Service = serviceOrig;
                            if (destPortTranslated != null)
                            {
                                natRule.TranslatedService = IfTranslatedServiceIsGroupReturnDummy(destPortTranslated, simplePolicy);
                            }
                            natRule.Source = cpDipOriginalObj[index];
                            natRule.TranslatedSource = cpDipTranslatedObj[index];
                            natRule.Destination = dstOrig;
                            natRule.TranslatedDestination = destIpTranslated;
                            natRule.Tag = "PolicyBasedSrcDestNAT";
                            natRule.Comments = comment;
                            _cpNatRules.Add(natRule);
                        }
                    }

                    /* Create Policy*/
                    CreateRuleFromNATPolicy(simplePolicy);
                }
            }
        }

        private void Add_InterfaceBasedLegacyNat()
        {
            /* Check if all predefined zones are attached to Vrouter trust-vr*/
            int predefinedZonesConectToTrustVR = 0;
            foreach (string zone in ScreenOSCommand_Zone.PredefinedZones)
            {
                foreach (ScreenOSCommand_Zone zoneObj in ScreenOSZoneCommands)
                {
                    if (zoneObj.ZoneName == zone && zoneObj.Vrouter == "trust-vr")
                    {
                        predefinedZonesConectToTrustVR++;
                    }
                }
            }

            /* Terms for legacy NAT missing, exit function*/
            if (predefinedZonesConectToTrustVR != ScreenOSCommand_Zone.PredefinedZones.Length)
            {
                return;
            }

            CheckPoint_NetworkGroup zoneTrustNetGroup = (CheckPoint_NetworkGroup)_cpObjects.GetObject(ObjectNameGenerator.ZoneName("Trust"));
            if (zoneTrustNetGroup == null)
            {
                return;
            }

            /* Find all attached interface with NAT to Trust zone */
            List<CheckPointObject> interfacesWithNAT = new List<CheckPointObject>();
            foreach (string ifcGroup in zoneTrustNetGroup.Members)
            {
                CheckPointObject ifcGroupObj = _cpObjects.GetObject(ifcGroup);
                if(ifcGroupObj.Tag == "NAT")
                {
                    interfacesWithNAT.Add(ifcGroupObj);
                }
            }

            /* If no interface with NAT attached to Trust zone, exit function*/ 
            if (interfacesWithNAT.Count == 0)
            {
                return;
            }

            CheckPointObject srcObj = null;
            if (zoneTrustNetGroup.Members.Count == 1 && zoneTrustNetGroup.Members.Count == interfacesWithNAT.Count)
            {
                srcObj = interfacesWithNAT.First();
            }
            else if(zoneTrustNetGroup.Members.Count == interfacesWithNAT.Count)
            {
                srcObj = zoneTrustNetGroup;
            }
            else
            {
                srcObj = new CheckPoint_NetworkGroup();
                srcObj.Name = "GRP_SM_NAT_INT_TRUST";
                foreach (CheckPointObject ifcNAT in interfacesWithNAT)
                {
                    ((CheckPoint_NetworkGroup)srcObj).Members.Add(ifcNAT.Name);
                }
                AddCheckPointObject(srcObj);
            }

            /* For each interface in Untrust zone*/
            CheckPoint_NetworkGroup zoneUntrastNetGroup = (CheckPoint_NetworkGroup)_cpObjects.GetObject(ObjectNameGenerator.ZoneName("Untrust"));
            if (zoneUntrastNetGroup != null)
            {
                string ifcName = "";
                int interfaceWithHostobject = 0;

                foreach (string ifcGroup in zoneUntrastNetGroup.Members)
                {
                    ifcName = ifcGroup.Replace(ObjectNameGenerator.InterfaceName(""), "");
                    CheckPoint_Host ifcHost = (CheckPoint_Host)_cpObjects.GetObject(ObjectNameGenerator.HostInterface(ifcName));
                    if (ifcHost != null)
                    {
                        /* Add NAT rule for each interface in Utrust Zone*/
                        CheckPoint_NAT_Rule natRuleSrc = new CheckPoint_NAT_Rule();
                        natRuleSrc.Enabled = false;
                        natRuleSrc.Method = CheckPoint_NAT_Rule.NatMethod.Hide;
                        natRuleSrc.Service = _cpObjects.GetObject(CheckPointObject.Any);
                        natRuleSrc.Source = srcObj;
                        natRuleSrc.TranslatedSource = ifcHost;
                        natRuleSrc.Destination = zoneUntrastNetGroup;
                        natRuleSrc.Tag = "InterfaceBasedNAT";
                        natRuleSrc.Comments = "Legacy NAT, Trust to Untrust- Due to multiple interfaces in Untrust zone, NAT rule will be disabled";
                        _cpNatRules.Add(natRuleSrc);

                        interfaceWithHostobject++;
                    }
                }

                if (interfaceWithHostobject == 1)
                {
                    _cpNatRules.Last().Enabled = true;
                    _cpNatRules.Last().Comments = "Legacy NAT, Trust to Untrust";
                }
            }

            /* For each interface in DMZ zone*/
            CheckPoint_NetworkGroup zoneDMZNetGroup = (CheckPoint_NetworkGroup)_cpObjects.GetObject(ObjectNameGenerator.ZoneName("DMZ"));
            if (zoneDMZNetGroup != null)
            {
                string ifcName = "";
                int interfaceWithHostobject = 0;
                foreach (string ifcGroup in zoneDMZNetGroup.Members)
                {
                    ifcName = ifcGroup.Replace(ObjectNameGenerator.InterfaceName(""), "");
                    CheckPoint_Host ifcHost = (CheckPoint_Host)_cpObjects.GetObject(ObjectNameGenerator.HostInterface(ifcName));
                    if (ifcHost != null)
                    {
                        /* Add NAT rule for each interface in DMZ Zone*/
                        CheckPoint_NAT_Rule natRuleSrc = new CheckPoint_NAT_Rule();
                        natRuleSrc.Enabled = false;
                        natRuleSrc.Method = CheckPoint_NAT_Rule.NatMethod.Hide;
                        natRuleSrc.Service = _cpObjects.GetObject(CheckPointObject.Any);
                        natRuleSrc.Source = srcObj;
                        natRuleSrc.TranslatedSource = ifcHost;
                        natRuleSrc.Destination = zoneDMZNetGroup;
                        natRuleSrc.Tag = "InterfaceBasedNAT";
                        natRuleSrc.Comments = "Legacy NAT, Trust to DMZ - Due to multiple interfaces in DMZ zone, NAT rule will be disabled";
                        _cpNatRules.Add(natRuleSrc);

                        interfaceWithHostobject++;
                    }
                }

                if (interfaceWithHostobject == 1)
                {
                    _cpNatRules.Last().Enabled = true;
                    _cpNatRules.Last().Comments = "Legacy NAT, Trust to DMZ";
                }
            }
        }

        private bool Prepare_ObjectsForPolicyBasedDestNat(PolicyCommandSimplifier simplePolicy, out CheckPointObject destIpTranslated,out  CheckPointObject destPortTranslated)
        {
            destIpTranslated = null;
            destPortTranslated = null;
            ScreenOSCommand_Policy natPolicy = simplePolicy.OrigPolicy;

            if (natPolicy.DestNatIp.Any() == false)
            {
                string errorTitle = string.Format("ScreenOS NAT policy command bad format. NAT rule will not be created");
                string errorDescription = string.Format("Policy object details: {0}.", natPolicy.Text);
                _conversionIncidents.Add(new ConversionIncident(natPolicy.Id, errorTitle, errorDescription, ConversionIncidentType.ManualActionRequired));
                return false;
            }

            /* Get translated address object*/
            if (natPolicy.DestNatIp.Count == 2)
            {
                /* Range case*/
                destIpTranslated = GetCheckPointObjByIpRange(natPolicy.DestNatIp.First(),
                                                    natPolicy.DestNatIp.Last(),
                                                    ObjectNameGenerator.PolicyBasedNatTranslatedName(natPolicy.DestNatIp.First(), natPolicy.DestNatIp.Last()));
            }
            else
            {
                /* Host case */
                destIpTranslated = GetCheckPointObjByIp(natPolicy.DestNatIp.First(), ScreenOSNetworkUtil.HostMask());
                if (destIpTranslated == null)
                {
                    destIpTranslated = CreateCheckPointObjByIp(natPolicy.DestNatIp.First(),
                                                        ScreenOSNetworkUtil.HostMask(),
                                                        ObjectNameGenerator.PolicyBasedNatTranslatedName(natPolicy.DestNatIp.First()));
                }
            }

            /* Handle translated port if not zero*/
            if (natPolicy.DestNatPort != 0)
            {
                /* Get original port object*/
                CheckPointObject tempServiceObj = GetServiceObjectByNameFromPolicy(simplePolicy.Services.First(), simplePolicy);
                if (tempServiceObj != null)
                {
                    string serviceType = "";
                    serviceType = tempServiceObj.GetType().ToString().Substring(tempServiceObj.GetType().ToString().IndexOf("_") + 1);
                    serviceType = serviceType.Replace("Service", "").ToUpper();

                    /* Get type of predefined service*/
                    if (serviceType == "PREDIFINEDOBJECT")
                    {
                        List<string> ports = ScreenOSKnownServices.ConvertPredefinedServiceNameToPort(simplePolicy.Services.First());
                        if (ports.Any() == false)
                        {
                            serviceType = "";
                        }
                        else if (ports.Count > 1)
                        {
                            serviceType = "GROUP";
                        }
                        else
                        {
                            serviceType = ports.First().Substring(0, ports.First().IndexOf("_"));
                        }
                    }

                    /* Check if original service is known and not a group*/
                    if (string.IsNullOrEmpty(serviceType) || serviceType == "GROUP")
                    {
                        destPortTranslated = GetCheckPointObjectOrCreateDummy("PolicyBasedNAT_" + natPolicy.DestNatPort.ToString(),
                                                            CheckPointDummyObjectType.Service,
                                                            natPolicy,
                                                            "Error creating NAT rule, check if original service does not exist or a group of services",
                                                            "Policy object details: " + natPolicy.Text + ".");
                    }
                    else
                    {
                        /*CheckObjectNameValidity if exist if not create new service object*/
                        destPortTranslated = GetCheckPointServiceObjByPort(natPolicy.DestNatPort, serviceType);
                        if (destPortTranslated == null)
                        {
                            destPortTranslated = _cpObjects.GetObject(CreateCheckPointServiceByNameAndPort("TRANSLATED", serviceType + "_" + natPolicy.DestNatPort.ToString()));
                        }
                    }
                }
                else
                {
                    /* Unknown original service in NAT policy*/
                    string errorTitle = string.Format("ScreenOS NAT policy object contains unknown service object \"{0}\". Translated Port will be ignored", simplePolicy.Services.First());
                    string errorDescription = string.Format("Policy object details: {0}.", natPolicy.Text);
                    _conversionIncidents.Add(new ConversionIncident(natPolicy.Id, errorTitle, errorDescription, ConversionIncidentType.Informative));
                }
            }

            return true;
        }

        private bool Prepare_ObjectsForDipNat(PolicyCommandSimplifier simplePolicy, out List<CheckPointObject> cpDipOriginalObj, out List<CheckPointObject> cpDipTranslatedObj, out List<bool> isEnabled, out List<bool> isPATEnabled, out string comments)
        {
            cpDipOriginalObj = new List<CheckPointObject>();
            cpDipTranslatedObj = new List<CheckPointObject>();
            isEnabled = new List<bool>();
            isPATEnabled = new List<bool>();
            comments = "";

            ScreenOSCommand_Policy natPolicy = simplePolicy.OrigPolicy;
            int dipId = natPolicy.DipId;
            ScreenOSCommand_Interface ifc = null;

            if (dipId == 0)
            {
                if (!IsZoneAvailable(simplePolicy.ToZone, simplePolicy.OrigPolicy))
                {
                    return false;
                }

                string ifcName = "";
                CheckPoint_NetworkGroup zoneNetGroup = (CheckPoint_NetworkGroup)_cpObjects.GetObject(ObjectNameGenerator.ZoneName(simplePolicy.ToZone));
                if (zoneNetGroup == null)
                {
                    string errorTitle = string.Format("ScreenOS NAT policy object does not contain dip-id. Zone object \"{0}\" does not attach any interfaces to it. Please review for further possible modifications to objects before migration", simplePolicy.ToZone);
                    string errorDescription = string.Format("Policy DIP object details: {0}.", natPolicy.Text);
                    _conversionIncidents.Add(new ConversionIncident(natPolicy.Id, errorTitle, errorDescription, ConversionIncidentType.Informative));
                    return false;
                }

                /* Get original source checkpoint object from policy*/
                CheckPointObject cpDipOriginalObjTemp = GetSrcObjectFromPolicyForNAT(simplePolicy);

                /* For each interface attached to zone create a rule, if multiple put in disable*/
                int interfaceWithHostObject = 0;
                foreach (string ifcGroup in zoneNetGroup.Members)
                {
                    ifcName = ifcGroup.Replace(ObjectNameGenerator.InterfaceName(""), "");
                    CheckPoint_Host ifcHost = (CheckPoint_Host)_cpObjects.GetObject(ObjectNameGenerator.HostInterface(ifcName));
                    if (ifcHost != null)
                    {
                        cpDipTranslatedObj.Add(ifcHost);
                        cpDipOriginalObj.Add(cpDipOriginalObjTemp);
                        isEnabled.Add(false);
                        isPATEnabled.Add(true);
                        
                        interfaceWithHostObject++;
                    }
                }

                if (interfaceWithHostObject > 1)
                {           
                    string errorTitle = string.Format("ScreenOS NAT policy object does not contain dip-id. NAT rules will be created as much as the number of attached interfaces to destination zone with host IP. NAT rules will be in a disabled mode");
                    string errorDescription = string.Format("Policy DIP object details: {0}.", natPolicy.Text);
                    _conversionIncidents.Add(new ConversionIncident(natPolicy.Id, errorTitle, errorDescription, ConversionIncidentType.ManualActionRequired));
                    comments = errorTitle;
                }
                else
                {   /* If only one rule was created, set the enabled value by the policy configuration*/
                    comments = "ScreenOS NAT policy object does not contain dip-id. One NAT rule will be created according to attached interface to destination zone with host IP.";
                    isEnabled[isEnabled.IndexOf(isEnabled.Last())] = simplePolicy.IsEnabled;
                }      
            }
            /* Create Objects for Dip*/
            else if (GetDipObjByDipId(dipId, out ifc))
            {
                ScreenOsCommand_InterfceNatDIP dipObj = (ScreenOsCommand_InterfceNatDIP)ifc.NatObject;

                if (dipId != 0 && dipId != dipObj.DipId)
                {
                    string errorTitle = string.Format("ScreenOS DIP NAT rule using group dip-id {0}. Modifying the dip-id to dip-id {1} first member of group ", dipId, dipObj.DipId);
                    string errorDescription = string.Format("Policy DIP object details: {0}.", natPolicy.Text);
                    _conversionIncidents.Add(new ConversionIncident(natPolicy.Id, errorTitle, errorDescription, ConversionIncidentType.Informative));
                }

                if (ifc.ConversionIncidentType != ConversionIncidentType.None)
                {
                    string errorTitle = ifc.ConversionIncidentMessage;
                    string errorDescription = string.Format("Interface DIP object details: {0}.", ifc.Text);
                    _conversionIncidents.Add(new ConversionIncident(ifc.Id, errorTitle, errorDescription, ifc.ConversionIncidentType));
                }

                /* Get or create objects for NAT rule*/
                if (string.IsNullOrEmpty(dipObj.ShiftFromIp) == false)
                {
                    /* Shift from IP is enabled use ip range for original and translated*/
                    string lastOrigIpInRange = ScreenOSNetworkUtil.GetIPv4LastOfRangeByOtherRange(dipObj.IpStart, dipObj.IpEnd, dipObj.ShiftFromIp);

                    /* Original ip range*/
                    cpDipOriginalObj.Add(GetCheckPointObjByIpRange(dipObj.ShiftFromIp, lastOrigIpInRange, ObjectNameGenerator.DipOriginalName(dipObj.ShiftFromIp, "RANGE")));

                    /* Translated ip range*/
                    cpDipTranslatedObj.Add(GetCheckPointObjByIpRange(dipObj.IpStart, dipObj.IpEnd, ObjectNameGenerator.DipTranslatedName(dipObj.DipId, "RANGE")));

                    /* PAT is false in case of range*/
                    isPATEnabled.Add(false);
                }
                else
                {
                    /* Get original checkpoint object*/
                    cpDipOriginalObj.Add(GetSrcObjectFromPolicyForNAT(simplePolicy));

                    /* Get translated ip*/
                    CheckPointObject cpDipTranslatedObjTemp = GetCheckPointObjByIp(dipObj.IpStart, ScreenOSNetworkUtil.HostMask());
                    if (cpDipTranslatedObjTemp == null)
                    {
                        /* Create new checkpoint object*/
                        cpDipTranslatedObjTemp = CreateCheckPointObjByIp(dipObj.IpStart, ScreenOSNetworkUtil.HostMask(), ObjectNameGenerator.DipTranslatedName(dipObj.DipId, "HOST"));
                    }
                    cpDipTranslatedObj.Add(cpDipTranslatedObjTemp);

                    /* PAT*/
                    isPATEnabled.Add(dipObj.IsPATEnabled);

                    if (dipObj.IpStart != dipObj.IpEnd)
                    {
                        string errorTitle = string.Format("ScreenOS DIP object contains range of IPs. Modifying the range to only one IP by using the first IP of the range");
                        string errorDescription = string.Format("DIP object details: {0}.", ifc.Text);
                        _conversionIncidents.Add(new ConversionIncident(ifc.Id, errorTitle, errorDescription, ConversionIncidentType.Informative));
                    }
                }

                isEnabled.Add(simplePolicy.IsEnabled);
            }
            else
            {
                /* Interface command of DIP info not exist*/
                natPolicy.ConversionIncidentMessage = "ScreenOS configuration missing an interface object defining dip-id " + dipId + ". Please review for further possible modifications to objects before migration";
                natPolicy.ConversionIncidentType = ConversionIncidentType.ManualActionRequired;

                cpDipOriginalObj.Add(GetCheckPointObjectOrCreateDummy(dipId + "_orig",
                                        CheckPointDummyObjectType.Network,
                                        simplePolicy.OrigPolicy,
                                        "Error creating  NAT rule, from ScreenOS NAT rules of type DIP",
                                        "Missing information of dip-id " + dipId + " in ScreenOS configuration."));

                cpDipTranslatedObj.Add(GetCheckPointObjectOrCreateDummy(dipId + "_translated",
                                        CheckPointDummyObjectType.Network,
                                        simplePolicy.OrigPolicy,
                                        "Error creating NAT rule, from ScreenOS NAT rules of type DIP",
                                        "Missing information of dip-id " + dipId + " in ScreenOS configuration."));

                isPATEnabled.Add(false);
                isEnabled.Add(simplePolicy.IsEnabled);
                comments = "Missing information of dip-id " + dipId + " in ScreenOS configuration";
            }

            return true;
        }

        private void Add_NatPolicy2RegularPolicy()
        {
            foreach (CheckPoint_Rule cpRule in _convertedNatPolicy2Rules)
            {
                bool isFound = false;

                foreach (CheckPoint_Layer layer in _cpPackages[0].SubPolicies)
                {
                    if (layer.Name == cpRule.Layer)
                    {
                        layer.Rules.Insert(0, cpRule);
                        isFound = true;
                    }
                }

                /* Layer not found, create new layer*/
                if (!isFound)
                {   
                    /* Find first global in parent layer*/
                    int firstGlobal = 0;
                    foreach (CheckPoint_Rule layer in _cpPackages[0].ParentLayer.Rules)
                    {
                        if (layer.Tag == "global")
                        {
                            break; 
                        }
                        firstGlobal++;
                    }

                    List<string> tempArrayList = cpRule.Tag.Split(' ').ToList();

                    if (tempArrayList.Count() != 2)
                    {
                        continue;
                    }

                    CheckPointObject cpSrcObject = _cpObjects.GetObject(tempArrayList[0]);
                    if (cpSrcObject == null)
                    {
                        continue;
                    }

                    CheckPointObject cpDstObject = _cpObjects.GetObject(tempArrayList[1]);
                    if (cpDstObject == null)
                    {
                        continue;
                    }

                    /* Create the rule of new layer in ParentLayer*/
                    CheckPoint_Rule cpNewRule = new CheckPoint_Rule();
                    cpNewRule.Source.Add(cpSrcObject);
                    cpNewRule.Destination.Add(cpDstObject);
                    cpNewRule.Action = CheckPoint_Rule.ActionType.SubPolicy;
                    cpNewRule.SubPolicyName = ObjectNameGenerator.SubPolicyByZonesName(cpSrcObject.Name,cpDstObject.Name);
                    cpNewRule.Layer = _cpPackages[0].NameOfAccessLayer;
                    cpNewRule.Tag = "inter";
                    _cpPackages[0].ParentLayer.Rules.Insert(firstGlobal, cpNewRule);

                    /* Create layer to sub policies*/
                    CheckPoint_Layer cpLayer = new CheckPoint_Layer();
                    cpLayer.Name = cpRule.Layer;
                    cpLayer.Rules.Add(cpRule);
                    /* Copy global and clean up rules to new layer*/
                    for (int index = firstGlobal + 1; index < _cpPackages[0].ParentLayer.Rules.Count;++index)
                    {
                        cpLayer.Rules.Add(_cpPackages[0].ParentLayer.Rules[index].Clone());
                        cpLayer.Rules.Last().Layer = cpRule.Layer;

                    }
                    cpLayer.Rules.Last().Name = "Sub-Policy Cleanup rule";
                    _cpPackages[0].SubPolicies.Insert(firstGlobal,cpLayer);
                    validatePackage(_cpPackages[0]);
                }
            }
        }

        #endregion

        #region Public Methods

        public override void Initialize(VendorParser vendorParser, string vendorFilePath, string toolVersion, string targetFolder, string domainName)
        {
            _screenOSParser = (ScreenOSParser)vendorParser;
            if (_screenOSParser == null)
            {
                throw new InvalidDataException("Unexpected!!!");
            }

            base.Initialize(vendorParser, vendorFilePath, toolVersion, targetFolder, domainName);
        }

        public override void Convert(bool convertNat = false)
        {
            RaiseConversionProgress(20, "Converting obects ...");
            _cpObjects.Initialize();   // must be first!!!
            
            foreach (CheckPointObject cpObject in _cpObjects.GetPredefinedObjects())
            {
                _objectNameGenerator.AddAppearanceCount(cpObject.Name,true);
            }

            UploadPredefinedServices();

            Add_Zones();
            Add_AddressAndGroupAddress();
            Add_IpPool();
            Add_Services();
            Add_GroupServices();
            Add_InterfacesAndRoutes();
            Add_or_Modify_InterfaceNetworkGroups();
            Add_ZonesNetworkGroups();
            RaiseConversionProgress(30, "Converting rules ...");
            Convert_policies();

            if (!convertNat)
            {
                MarkNatRulesNotIntersting();
            }
            else
            {
                RaiseConversionProgress(40, "Converting NAT rules ...");
                Add_Mip_Nat();
                Add_Vip_Nat();
                Add_Dip_Nat();
                Add_PolicyBasedDestNat();
                Add_PolicyBasedSrcDestNat();
                Add_InterfaceBasedLegacyNat();
                RaiseConversionProgress(60, "Creating Firewall rulebase ...");
                Add_NatPolicy2RegularPolicy();
            }

            RaiseConversionProgress(70, "Validating converted objects ...");
            EnforceObjectNameValidity();

            RaiseConversionProgress(80, "Generating CLI scripts ...");
            CreateObjectsHtml();
            CreateObjectsScript();
            CreatePackagesScript();

            // This data container is important, and is used during rulebases html reports generation for incidents lookup!!!
            IEnumerable<IGrouping<int, ConversionIncident>> incidentsGroupedByLineNumber = _conversionIncidents.GroupBy(error => error.LineNumber);
            _conversionIncidentsByLineNumber = incidentsGroupedByLineNumber.ToDictionary(error => error.Key, error => error.Distinct().ToList());

            // Resolve the conversion categories/lines count to report to the user.
            ConversionIncidentCategoriesCount = _conversionIncidents.GroupBy(error => error.Title).Count();
            ConversionIncidentsCommandsCount = _conversionIncidents.GroupBy(error => error.LineNumber).Count();
			
            CreateSmartConnector();
        }

        public override int RulesInConvertedPackage()
        {
            return _cpPackages[0].TotalRules();
        }

        public override int RulesInConvertedOptimizedPackage()
        {
            return 0;
        }

        public override int RulesInNatLayer()
        {
            return _cpNatRules.Count;
        }

        public override void ExportConfigurationAsHtml()
        {
            using (var file = new StreamWriter(VendorHtmlFile))
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
                file.WriteLine("<h2>ScreenOS config file</h2>");

                file.WriteLine("<table style='margin-bottom: 20px; background: rgb(250,250,250);'>");
                file.WriteLine("   <tr><td style='font-size: 14px; text-decoration: underline;'>Colors Legend</td></tr>");
                file.WriteLine("   <tr><td style='font-size: 12px; color: Black;'>Parsed commands</td></tr>");
                file.WriteLine("   <tr><td style='font-size: 12px; color: Gray;'>Skipped commands</td></tr>");
                file.WriteLine("   <tr><td style='font-size: 12px; color: Fuchsia;'>Unknown commands</td></tr>");
                file.WriteLine("   <tr><td style='font-size: 12px; color: Red;'>Commands with conversion error</td></tr>");
                file.WriteLine("   <tr><td style='font-size: 12px; color: Blue;'>Commands with conversion notification</td></tr>");
                file.WriteLine("</table>");

                file.WriteLine("<div style='margin-bottom: 20px; font-size: 14px; color: Blue;'>");
                file.WriteLine("   <span style='vertical-align: middle; font-size: 14px;'>" + HtmlAlertImageTag);
                file.WriteLine("      <a> Valid Check Point object name consists of the following characters only - \"A-Za-z0-9_.-\". Any invalid character will be replaced with a \"_\" character.</a>");
                file.WriteLine("   </span>");
                file.WriteLine("</div>");

                if (_conversionIncidents.Count > 0)
                {
                    file.WriteLine("<div style='margin-bottom: 20px;'>");
                    file.WriteLine("   <span style='vertical-align: middle; font-size: 14px;'>" + HtmlAlertImageTag);
                    file.WriteLine("      <a href='#ConversionIncidents'>Found " + ConversionIncidentCategoriesCount + " conversion issues in " + ConversionIncidentsCommandsCount + " configuration lines</a>");
                    file.WriteLine("   </span>");
                    file.WriteLine("</div>");
                }

                file.WriteLine("<table class=\"report_table\">");

                foreach (ScreenOSCommand command in ScreenOSAllCommands)
                {
                    string lineStyle = "";
                    string indentation  = "";

                    if (!command.KnownCommand)
                    {
                        lineStyle = " class=\"unhandeled\" ";
                    }

                    if (command.NotAnInterestingCommand)
                    {
                        lineStyle = " class=\"notimportant\" ";
                    }

                    if (command.ConversionIncidentType == ConversionIncidentType.ManualActionRequired)
                    {
                        lineStyle = " class=\"converterr\" ";
                    }

                    if (command.ConversionIncidentType == ConversionIncidentType.Informative)
                    {
                        lineStyle = " class=\"convertinfo\" ";
                    }

                    string incidentFlag = "";
                    if (command.ConversionIncidentType != ConversionIncidentType.None)
                    {
                        ConversionIncidentType highestIncidentType;
                        incidentFlag = BuildConversionIncidentInfo(command.Id, out highestIncidentType);
                    }

                    file.WriteLine("<tr>");
                    file.WriteLine("  <td id=\"line_" + command.Id + "\" class=\"line_number\" style=\"text-align: right;\">" + incidentFlag + command.Id + "</td>" + "<td " + lineStyle + " >" + indentation + command.Text + "</td>");
                    file.WriteLine("</tr>");
                }

                file.WriteLine("</table>");

                if (_conversionIncidents.Count > 0)
                {
                    file.WriteLine("<hr/>");
                    file.WriteLine("<h2 id=\"ConversionIncidents\">Conversion Issues</h2>");

                    bool first = true;
                    string prevTitle = "";

                    foreach (ConversionIncident err in _conversionIncidents.OrderByDescending(item => item.IncidentType).ThenBy(item => item.Title).ThenBy(item => item.LineNumber).ToList())
                    {
                        if (first)
                        {
                            if (err.IncidentType == ConversionIncidentType.ManualActionRequired)
                            {
                                file.WriteLine("<h4 class=\"err_title\">" + err.Title + "</h4>");
                            }
                            else
                            {
                                file.WriteLine("<h4 class=\"info_title\">" + err.Title + "</h4>");
                            }

                            file.WriteLine("<table class=\"report_table\">");
                        }

                        if (!first && prevTitle != err.Title)
                        {
                            file.WriteLine("</table>");

                            if (err.IncidentType == ConversionIncidentType.ManualActionRequired)
                            {
                                file.WriteLine("<h4 class=\"err_title\">" + err.Title + "</h4>");
                            }
                            else
                            {
                                file.WriteLine("<h4 class=\"info_title\">" + err.Title + "</h4>");
                            }

                            file.WriteLine("<table class=\"report_table\">");
                        }

                        file.WriteLine("  <tr>");
                        file.WriteLine("    <td class=\"line_number\" style=\"text-align: right;\"> <a href=\"#line_" + err.LineNumber + "\">" + err.LineNumber + "</a></td>");
                        file.WriteLine("    <td>" + err.Description + "</td>");
                        file.WriteLine("  </tr>");

                        first = false;
                        prevTitle = err.Title;
                    }
                }

                file.WriteLine("</body>");
                file.WriteLine("</html>");
            }
        }

        public override void ExportPolicyPackagesAsHtml()
        {
            const string ruleIdPrefix = "rule_";

            foreach (CheckPoint_Package package in _cpPackages)
            {
                string filename = _targetFolder + "\\" + package.Name + ".html";

                using (var file = new StreamWriter(filename, false))
                {
                    var rulesWithConversionErrors = new Dictionary<string, CheckPoint_Rule>();
                    var rulesWithConversionInfos = new Dictionary<string, CheckPoint_Rule>();

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
                                    }
                                }
                            }
                        }

                        ruleNumber++;
                    }

                    file.WriteLine("</table>");

                    if (rulesWithConversionErrors.Count > 0 || rulesWithConversionInfos.Count > 0)
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

                    if (rulesWithConversionInfos.Count > 0)
                    {
                        int counter = 0;
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

        #endregion
    }
}
