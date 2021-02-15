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

using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using CommonUtils;

namespace NetScreenMigration
{
    public interface IScreenOSCommand
    {
        string Name();

        void Parse(ScreenOSCommand command);
    }

    /// <summary>
    /// Represents a basic ScreenOS SSG object.
    /// Parses the name and description fields for all objects.
    /// Each derived object auto-parses the appropriate configuration element for additional fields.
    /// </summary>
    public class ScreenOSCommand : IScreenOSCommand
    {
        private string _text = "";
        private string[] _words;

        public int Id { get; set; }
        public bool KnownCommand { get; set; }
        public bool NotAnInterestingCommand { get; set; }
        public ConversionIncidentType ConversionIncidentType { get; set; }
        public string ConversionIncidentMessage { get; set; }
        public string Comment { get; set; }
        public bool GotTreated { get; set; }
        public List<ScreenOSCommand> AdditionalRealatedObjects { get; set; }

        public string Text
        {
            get { return _text; }
            set
            {
                _text = value;

                string trimmedText = _text.Trim();
                char[] delimiterChars = { ' ', '\t' };

                // Replace multiple spaces with a single space
                trimmedText = Regex.Replace(trimmedText, @"\s+", " ");
                List<string> tempArrayList = trimmedText.Split(delimiterChars).ToList();

                // Gather strings with spaces between quotes
                for (int i = 0; i < tempArrayList.Count;++i)
                {
                    if (tempArrayList[i].First() == '\"' && tempArrayList[i].Last() != '\"')
                    {
                        do
                        {
                            tempArrayList[i] += " " + tempArrayList[i + 1];
                            tempArrayList.Remove(tempArrayList[i + 1]);
                        } while (tempArrayList[i].Last() != '\"' && i + 1 < tempArrayList.Count);
                    }
                }

                _words = tempArrayList.ToArray();
            }
        }

        public string ObjectWord
        {
            get
            {
                if (_words == null || !_words.Any())
                {
                    return "";
                }

                // If an object is a group, return group type also (address/service)
                if (_words.Length > 2)
                {
                    if (_words[1] == "group")
                    {
                        return _words[1] + " " + _words[2];
                    }

                    if (_words[1] == "dip" && _words[2] == "group")
                    {
                        return _words[1] + " " + _words[2];
                    }
                }

                if (_words.Length > 1)
                {
                    return _words[1];
                }

                return _words[0];
            }
        }

        public bool HasAdditionalRealatedObjects
        {
            get
            {
                if (AdditionalRealatedObjects != null && AdditionalRealatedObjects.Count > 0)
                {
                    return true;
                }

                return false;
            }
        }

        public ScreenOSCommand()
        {
            Comment = "";
            KnownCommand = false;
            NotAnInterestingCommand = false;
            GotTreated = false;
        }

        public virtual string Name() { return ""; }

        public virtual void Parse(ScreenOSCommand command)
        {
            if (command.GetParam(0) == "exit")
            {
                NotAnInterestingCommand = false;
                KnownCommand = true;
            }
            else if (command.GetParam(0) != "set")
            {
                NotAnInterestingCommand = true;
            }
        }
        
        public int GetNumOfParams()
        {
            if (_words == null)
            {
                return 0;
            }

            return _words.Length;
        }

        public string GetParam(int pos)
        {
            if (_words == null || _words.Length <= pos)
            {
                return "";
            }

            return _words[pos];
        }

        public List<string> GetParams(int pos)
        {
            var res = new List<string>();

            if (_words == null || !_words.Any())
            {
                return res;
            }

            for (int i = 0; i < _words.Length; i++)
            {
                if (i >= pos)
                {
                    res.Add(_words[i]);
                }
            }

            return res;
        }

        public List<string> GetParams(int startIndex, int count)
        {
            var res = new List<string>();

            if (_words == null || !_words.Any() || startIndex < 0)
            {
                return res;
            }

            int numOfParams = (startIndex + count > _words.Length) ? _words.Length : startIndex + count;

            for (int i = startIndex; i < numOfParams; i++)
            {
                res.Add(_words[i]);
            }

            return res;
        }

        public int GetParamPosition(string paramName)
        {
            if (_words == null || !_words.Any())
            {
                return -1;
            }

            int pos = 0;
            foreach (string word in _words)
            {
                if (word == paramName)
                {
                    return pos;
                }
                pos++;
            }

            return -1;
        }

        public static bool IsInQuotation(string str)
        {
            if (str.Length != 0 && str.First() == '\"' && str.Last() == '\"')
            {
                return true;
            }

            return false;
        }
    }

    public class ScreenOSCommand_Address: ScreenOSCommand
    {
        public enum AddressTypeEnum { NA, Host, Network, Domain };

        private string _zone = "";
        private string _objectName = "";
        private string _mask = "";
    
        public AddressTypeEnum AddressType { get; set; }
        public string IpAddress { get; set; }
        public string Domain { get; set; }

        public bool IsWildCardMask
        {
            get
            {
                if (string.IsNullOrEmpty(_mask) || NetworkUtils.IsValidNetmaskv4(_mask))
                {
                    return false;
                }

                if (NetworkUtils.IsWildCardNetmask(_mask))
                {
                    return true;
                }

                return false;
            }
        }

        public string Zone
        {
            get { return _zone.Trim('"'); }
            set { _zone = value; }
        }

        public string ObjectName
        {
            get { return _objectName.Trim('"'); }
            set { _objectName = value; }
        }

        public string Netmask
        {
            get
            {
                if (IsWildCardMask)
                {
                    return NetworkUtils.WildCardMask2Netmask(_mask);
                }

                return _mask;
            }

            set { _mask = value; }
        }

        public ScreenOSCommand_Address()
        {
            KnownCommand = true;
            IpAddress = "";
            Netmask = "";
            Domain = "";
            AddressType = AddressTypeEnum.NA;
        }

        public override string Name() { return "address"; }

        public override void Parse(ScreenOSCommand command)
        {
            base.Parse(command);
            
            // Check if base parse marked the command as interesting
            if (NotAnInterestingCommand)
            {
                return;
            }

            Zone = command.GetParam(2);
            ObjectName = command.GetParam(3);

            string commandParam = command.GetParam(5);
            if (NetworkUtils.IsValidNetmaskv4(commandParam) || NetworkUtils.IsWildCardNetmask(commandParam))
            {
                Netmask = commandParam;
                if (NetworkUtils.GetMaskLength(Netmask) == 32)
                {
                    AddressType = AddressTypeEnum.Host;
                    IpAddress = command.GetParam(4);
                }
                else
                {
                    AddressType = AddressTypeEnum.Network;
                    IpAddress = NetworkUtils.GetNetwork(command.GetParam(4), Netmask);
                }
            }
            else if (NetworkUtils.IsValidIpv4(commandParam))
            {
                // Complex wild card not supported, e.g 0.255.0.255
                AddressType = AddressTypeEnum.Network;
                IpAddress = "1.1.1.0";
                Netmask = "255.255.255.0";
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = string.Format("ScreenOS address object with complex wildcard mask {0} is not supported. Using subnet 1.1.1.0/255.255.255.0", commandParam);
            }
            else if(string.IsNullOrEmpty(commandParam) || IsInQuotation(commandParam))
            {
                Domain = command.GetParam(4);
                AddressType = AddressTypeEnum.Domain;
            }
            else
            {
                KnownCommand = false;
                ConversionIncidentMessage = "Unknown format of " + commandParam + " Network Mask";
            }

            // Check for comment
            commandParam = command.GetParam(command.GetNumOfParams() - 1);
            if (IsInQuotation(commandParam))
            {
                Comment = commandParam;
            }  
        }
    }

    public class ScreenOSCommand_GroupAddress : ScreenOSCommand
    {
        private string _zone = "";
        private string _groupName = "";
        private string _addressObjectName = "";

        public string Zone
        {
            get { return _zone.Trim('"'); }
            set { _zone = value; }
        }

        public string GroupName
        {
            get { return _groupName.Trim('"'); }
            set { _groupName = value; }
        }

        public string AddressObjectName
        {
            get { return _addressObjectName.Trim('"'); }
            set { _addressObjectName = value; }
        }

        public ScreenOSCommand_GroupAddress()
        {
            KnownCommand = true;
        }

        public override string Name() { return "group address"; }

        public override void Parse(ScreenOSCommand command)
        {
            base.Parse(command);
            
            // Check if base parse marked the command as interesting
            if (NotAnInterestingCommand)
            {
                return;
            }

            Zone = command.GetParam(3);
            GroupName = command.GetParam(4);

            if (command.GetNumOfParams() > 5)
            {
                switch (command.GetParam(5))
                {
                    case "add":
                        AddressObjectName = command.GetParam(6);
                        break;

                    case "comment":
                        Comment = command.GetParam(6);
                        break;

                    default:
                        NotAnInterestingCommand = true;
                        break;
                }
            }
        }
    }

    public class ScreenOSCommand_Service : ScreenOSCommand
    {
        public enum TimeOutUnitsEnum { Minutes, TenSeconds };

        private readonly int _maxTimeout = 2160;
        private string _serviceName = "";
       
        public int TimeOut { get; set; }
        public TimeOutUnitsEnum TimeOutUnits { get; set; }
        public bool IsSessionCacheEnabled { get; set; }
        public ServiceProtocolObject ServiceProtocol;
        public bool OfPolicyContext { get; set; }

        public string ServiceName
        {
            get { return _serviceName.Trim('"'); }
            set { _serviceName = value; }
        }

        public int Never
        {
            get { return _maxTimeout; }
        }

        public ScreenOSCommand_Service()
        {
            KnownCommand = true;
            TimeOut = 0;
            TimeOutUnits = TimeOutUnitsEnum.Minutes;
            IsSessionCacheEnabled = false;
            OfPolicyContext = false;
            ServiceProtocol = null;
        }

        public override string Name() { return "service"; }

        public override void Parse(ScreenOSCommand command)
        {
            base.Parse(command);
            
            // Check if base parse marked the command as interesting
            if (NotAnInterestingCommand)
            {
                return;
            }

            ServiceName = command.GetParam(2);

            int index = 3;
            string commandString = command.GetParam(index);
            if (string.IsNullOrEmpty(commandString))
            {
                OfPolicyContext = true;
                return;
            }

            if (commandString == "protocol" || commandString == "+")
            {
                commandString = command.GetParam(++index);
                switch (commandString)
                {
                    case "udp":
                        ServiceProtocol = new ServiceProtocolObject_Udp();
                        break;

                    case "tcp":
                        ServiceProtocol = new ServiceProtocolObject_Tcp();
                        break;

                    case "icmp":
                        ServiceProtocol = new ServiceProtocolObject_Icmp();
                        break;

                    case "ms-rpc":
                        ServiceProtocol = new ServiceProtocolObject_MsRPC();
                        break;

                    case "sun-rpc":
                        ServiceProtocol = new ServiceProtocolObject_SunRPC();
                        break;

                    default:
                        // Check if it is an IP protocol
                        int n = -1;
                        if (int.TryParse(commandString, out n))
                        {
                            ServiceProtocol = new ServiceProtocolObject_Ip();
                        }
                        else
                        {
                            // Not an IP protocol
                            NotAnInterestingCommand = true;
                            ServiceProtocol = new ServiceProtocolObject();
                            return;
                        }
                        break;
                }
                index = ServiceProtocol.Parse(command, index);
                commandString = command.GetParam(index);
            }

            if (commandString == "session-cache")
            {
                ConversionIncidentMessage = commandString ;
                IsSessionCacheEnabled = true;
                commandString = command.GetParam(++index);
                
            }

            if (commandString == "timeout")
            {
                ConversionIncidentMessage = commandString;
                commandString = command.GetParam(++index);
                if (commandString == "unit")
                {
                    switch (command.GetParam(++index))
                    {
                        case "10sec":
                            TimeOutUnits = TimeOutUnitsEnum.TenSeconds;
                            break;
                    }
                }
                else if (commandString == "never")
                {
                    TimeOut = _maxTimeout;
                }
                else
                {
                    int t = 0;
                    if (int.TryParse(commandString, out t))
                    {
                        TimeOut = t;
                    }
                    else
                    {
                        NotAnInterestingCommand = true;
                    }
                }
            }

            if (!string.IsNullOrEmpty(ConversionIncidentMessage))
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "ScreenOS service object option \"" + ConversionIncidentMessage + "\" is not supported. Ignoring this part of object";
            }

            if (ServiceProtocol != null && !string.IsNullOrEmpty(ServiceProtocol.ConversionIncidentMessage))
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage += !string.IsNullOrEmpty(ConversionIncidentMessage) ?
                                            "\n" + ServiceProtocol.ConversionIncidentMessage :
                                            ServiceProtocol.ConversionIncidentMessage;
            }
        }
    }

    public class ScreenOSCommand_GroupService : ScreenOSCommand
    {
        private string _groupName = "";
        private string _serviceObjectName = "";

        public string GroupName
        {
            get { return _groupName.Trim('"'); }
            set { _groupName = value; }
        }

        public string ServiceObjectName
        {
            get { return _serviceObjectName.Trim('"'); }
            set { _serviceObjectName = value; }
        }
 
        public ScreenOSCommand_GroupService()
        {
            KnownCommand = true;
        }

        public override string Name() { return "group service"; }

        public override void Parse(ScreenOSCommand command)
        {
            base.Parse(command);

            // Check if base parse marked the command as interesting
            if (NotAnInterestingCommand)
            {
                return;
            }

            GroupName = command.GetParam(3);

            if (command.GetNumOfParams() > 4)
            {
                switch (command.GetParam(4))
                {
                    case "add":
                        ServiceObjectName = command.GetParam(5);
                        break;

                    case "comment":
                        Comment = command.GetParam(5);
                        break;

                    default:
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = "Unknown format of " + Name() + " object";
                        break;
                }
            }
        }
    }

    public class ScreenOSCommand_IPpool : ScreenOSCommand
    {
        private string _objectName = "";

        public string IpAddressFirst { get; set; }
        public string IpAddressLast { get; set; }

        public string ObjectName
        {
            get { return _objectName.Trim('"'); }
            set { _objectName = value; }
        }

        public ScreenOSCommand_IPpool()
        {
            IpAddressFirst = "";
            IpAddressLast = "";
            KnownCommand = true;
        }

        public override string Name() { return "ippool"; }

        public override void Parse(ScreenOSCommand command)
        {
            base.Parse(command);

            // Check if base parse marked the command as interesting
            if (NotAnInterestingCommand)
            {
                return;
            }

            ObjectName = command.GetParam(2);
            IpAddressFirst = command.GetParam(3);
            IpAddressLast = command.GetParam(4);
        
            if (!NetworkUtils.IsValidIpv4(IpAddressFirst) ||
                !NetworkUtils.IsValidIpv4(IpAddressLast) ||
                NetworkUtils.Ip2Number(IpAddressLast) < NetworkUtils.Ip2Number(IpAddressFirst))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Invalid IP or Range between IPs";
            }
        }
    }

    public class ScreenOSCommand_Zone : ScreenOSCommand
    {
        private string _zoneName = "";

        public static string[] PredefinedZones = { "Trust", "Untrust", "DMZ" };
        public static string[] SpecialPredefinedZones = { "MGT" , "Null" , "Untrust-Tun", "V1-Null", "V1-Trust", "V1-Untrust" , "V1-DMZ" };
        public static string[] UnsupportedPredefinedZones = { "HA", "VLAN"};
        public static string Global = "Global";

        public bool IsPredefinedZones { get; set; }
        public int ZoneID { get; set; }
        public string Vrouter { get; set; }
        public bool OfPolicyContext { get; set; }
        public bool isBlocked { get; set; }

        public string ZoneName
        {
            get { return _zoneName.Trim('"'); }
            set { _zoneName = value; }
        }

        public ScreenOSCommand_Zone()
        {
            KnownCommand = true;
            Vrouter = "";
            ZoneID = -1;
            OfPolicyContext = false;
            isBlocked = false;
            IsPredefinedZones = false;
        }

        public override string Name() { return "zone"; }

        public override void Parse(ScreenOSCommand command)
        {
            base.Parse(command);

            // Check if base parse marked the command as interesting
            if (NotAnInterestingCommand)
            {
                return;
            }

            string commandParam = command.GetParam(2);
            if (IsInQuotation(commandParam))
            {
                if(PredefinedZones.Contains(commandParam.Trim('"')))
                {
                    IsPredefinedZones = true;
                }
                else if (UnsupportedPredefinedZones.Contains(commandParam.Trim('"')))
                {
                    NotAnInterestingCommand = true;
                    return;
                }

                ZoneName = commandParam;
                commandParam = command.GetParam(3);
                if (commandParam == "vrouter")
                {
                    Vrouter = command.GetParam(4).Trim('"');
                }
                else if (commandParam == "block")
                {
                    isBlocked = true;
                    OfPolicyContext = true;
                }
                else
                {
                    NotAnInterestingCommand = true;
                }
            }
            else if (commandParam == "id")
            {   
                // New definition of zone
                int zoneId = 0;
                if (int.TryParse(command.GetParam(3), out zoneId))
                {
                    ZoneID = zoneId;
                    commandParam = command.GetParam(4);
                    if (IsInQuotation(commandParam))
                    {
                        ZoneName = commandParam;
                    }
                    else
                    {
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = "Zone name should be between quotations";
                    }

                    // Whenever the sixth param exists - command become irrelevant
                    if (!string.IsNullOrEmpty(command.GetParam(5)))
                    {
                        NotAnInterestingCommand = true;
                    }
                }
                else
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = "Id should be a number";
                }
            }
            else
            {
                NotAnInterestingCommand = true;
            }
        }
    }

    public class ScreenOSCommand_Interface : ScreenOSCommand
    {
        public class Subnet
        {
            public string Network { get; private set; }
            public string Netmask { get; private set; }
            public ScreenOSCommand RouteOrig { get; private set; }

            public Subnet(string sIp, string sMask, ScreenOSCommand sRouteOrig)
            {
                Network = NetworkUtils.GetNetwork(sIp, sMask);
                Netmask = sMask;
                RouteOrig = sRouteOrig;
            }
        }

        public enum InterfaceObjectTypeEnum { NA, Ip, Zone, Nat, Dip, Mip, Vip };

        private string _zone = "";

        public string InterfaceName { get; set; } 
        public string IP { get; set; }
        public string Mask { get; set; }
        public bool IsSecondery { get; set; }
        public InterfaceObjectTypeEnum InterfaceObjectType { get; set; }
        public List<Subnet> Topology = new List<Subnet>();
        public bool LeadsToInternet { get; set; }
        public ScreenOSCommand NatObject { get; set; }

        public string InterfaceObjName
        {
            get { return InterfaceName.Trim('"'); }
        }

        public string Zone
        {
            get { return _zone.Trim('"'); }
            set { _zone = value; }
        }

        public ScreenOSCommand_Interface()
        {
            KnownCommand = true;
            InterfaceName = "";
            IP = "";
            Mask = "";
            Zone = "";
            IsSecondery = false;
            InterfaceObjectType = InterfaceObjectTypeEnum.NA;
            LeadsToInternet = false;
            NatObject = null;
        }

        public override string Name() { return "interface"; }

        public override void Parse(ScreenOSCommand command)
        {
            base.Parse(command);

            // Check if base parse marked the command as interesting
            if (NotAnInterestingCommand)
            {
                return;
            }

            int index = 3;
            // Only interfaces with ip or zone are relevant
            switch (command.GetParam(index))
            {
                case "ip":
                    InterfaceObjectType = InterfaceObjectTypeEnum.Ip;
                    break;

                case "zone":
                    InterfaceObjectType = InterfaceObjectTypeEnum.Zone;
                    index++;
                    break;

                case "tag":
                    InterfaceObjectType = InterfaceObjectTypeEnum.Zone;
                    index+=3;
                    break;

                case "nat":
                    InterfaceObjectType = InterfaceObjectTypeEnum.Nat;
                    break;

                case "dip":
                case "ext":
                    InterfaceObjectType = InterfaceObjectTypeEnum.Dip;
                    NatObject = new ScreenOsCommand_InterfceNatDIP();
                    NatObject.Parse(command);
                    break;

                case "mip":
                    InterfaceObjectType = InterfaceObjectTypeEnum.Mip;
                    NatObject = new ScreenOsCommand_InterfceNatMIP();
                    NatObject.Parse(command);
                    break;

                case "vip":
                    InterfaceObjectType = InterfaceObjectTypeEnum.Vip;
                    NatObject = new ScreenOsCommand_InterfceNatVIP();
                    NatObject.Parse(command);
                    break;

                default:
                    NotAnInterestingCommand = true;
                    return;
            }

            InterfaceName = command.GetParam(2);

            if (InterfaceObjectType == InterfaceObjectTypeEnum.Ip)
            {
                string[] commandParam = command.GetParam(4).Split('/');
                if (commandParam.Length == 2)
                {
                    IP = commandParam[0];
                    Mask = NetworkUtils.MaskLength2Netmask(int.Parse(commandParam[1]));
                }
                else if (commandParam.Length == 1)
                {
                    if (NetworkUtils.IsValidIpv4(commandParam[0]))
                    {
                        IP = commandParam[0];
                        Mask = command.GetParam(5);
                        IsSecondery = true;
                    }
                    else
                    {
                        NotAnInterestingCommand = true;
                    }
                }
                else
                {
                    NotAnInterestingCommand = true;
                }
            }
            else if (InterfaceObjectType == InterfaceObjectTypeEnum.Zone)
            {
                Zone = command.GetParam(index);
            }

            if (NatObject != null)
            {
                // Copy conversion incident from NAT object
                ConversionIncidentType = NatObject.ConversionIncidentType;
                ConversionIncidentMessage += NatObject.ConversionIncidentMessage;
                NotAnInterestingCommand = NatObject.NotAnInterestingCommand;
            }
        }

        public bool CheckIfInterfaceIsGateway(string gateway)
        {
            if (NotAnInterestingCommand)
            {
                return false;
            }

            if (InterfaceObjectType == InterfaceObjectTypeEnum.Ip &&
                NetworkUtils.GetNetwork(IP,Mask) == NetworkUtils.GetNetwork(gateway, Mask))
            {
                return true;  
            }

            // Check inside children
            if (AdditionalRealatedObjects == null)
            {
                return false;
            }

            foreach (ScreenOSCommand_Interface interChiled in AdditionalRealatedObjects)
            {
                if (interChiled.CheckIfInterfaceIsGateway(gateway))
                {
                    return true;
                }
            }

            return false;
        }
    }

    public class ScreenOSCommand_Route : ScreenOSCommand
    {
        public string Network { get; set; }
        public string Mask { get; set; }
        public string Interface { get; set; }
        public string Gateway { get; set; }
        public string Description { get; set; }
        public int    Metric { get; set; }
        public bool   IsPermanent { get; set; }

        public bool DefaultRoute
        {
            get { return NetworkUtils.GetMaskLength(Mask) == 0; }
        }

        public ScreenOSCommand_Route()
        {
            KnownCommand = true;
            Network = "";
            Mask = "";
            Interface = "";
            Gateway = "";
            Description = "";
            Metric = -1;
            IsPermanent = false;
        }

        public override string Name() { return "route"; }

        public override void Parse(ScreenOSCommand command)
        {
            base.Parse(command);

            // Check if base parse marked the command as interesting
            if (NotAnInterestingCommand)
            {
                return;
            }

            // Get Ip and Mask
            string[] commandParam = command.GetParam(2).Split('/');
            if (commandParam.Length == 2)
            {
                Network = commandParam[0];
                Mask = NetworkUtils.MaskLength2Netmask(int.Parse(commandParam[1]));

                if (!NetworkUtils.IsValidIpv4(Network))
                {
                    ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                    ConversionIncidentMessage = "ScreenOS route object network or mask is invalid. Ignoring this command";
                    return;
                }
            }
            else
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "ScreenOS route object network and mask should represented as A.B.C.D/Mask-Length. Ignoring this command";
                return;
            }

            int i = 3;
            while (i < command.GetNumOfParams())
            {
                switch (command.GetParam(i))
                {
                    case "interface":
                        Interface = command.GetParam(++i);
                        break;

                    case "gateway":
                        Gateway = command.GetParam(++i);
                        break;

                    case "description":
                        Description = command.GetParam(++i);
                        break;

                    default:
                        break;
                }
                i++;
            }

            if (string.IsNullOrEmpty(Interface) && string.IsNullOrEmpty(Gateway))
            {
                NotAnInterestingCommand = true;
            }
        }
    }

    public class ScreenOSCommand_Policy : ScreenOSCommand
    {
        public enum ActoinEnum { Na, Permit, Reject, Deny};
        public enum PolicyNatTypeEnum { Na, Policy, Vip, Mip, Dip, PolicyBaseDest, PolicyBaseSrcDest };

        public int PolicyId { get; set; }
        public string PolicyName { get; set; }
        public string SrcZone { get; set; }
        public string DestZone { get; set; }
        public string SrcObject { get; set; }
        public string DestObject { get; set; }
        public string ServiceName { get; set; }
        public ActoinEnum Action { get; set; }
        public string ActionStr { get; set; }
        public bool IsLogEnabled { get; set; }
        public bool IsDisabled { get; set; }
        public bool IsGlobal { get; set; }
        public bool IsDefaultPermitAll { get; set; }
        public PolicyNatTypeEnum PolicyNatType { get; set; }
        public int DipId { get; set; }
        public List<string> DestNatIp { get; set; }
        public int DestNatPort;
        public bool MixedNAT { get; set; }

        public ScreenOSCommand_Policy()
        {
            PolicyId = 0;
            PolicyName = "";
            SrcZone = "";
            DestZone = "";
            SrcObject = "";
            DestObject = "";
            ServiceName = "";
            Action = ActoinEnum.Na;
            IsLogEnabled = false;
            IsDisabled = false;
            IsGlobal = false;
            IsDefaultPermitAll = false;
            PolicyNatType = PolicyNatTypeEnum.Policy;
            DipId = 0;
            DestNatIp = null;
            DestNatPort = 0;
            KnownCommand = true;
            MixedNAT = false;
        }

        public override string Name() { return "policy"; }

        public override void Parse(ScreenOSCommand command)
        {
            base.Parse(command);

            // Check if base parse marked the command as interesting
            if (NotAnInterestingCommand)
            {
                return;
            }

            string commandString = "";
            int i = 2;
            int nameExtension = 0;
            int globalExtension = 0;

            do
            {
                commandString = command.GetParam(i);
                switch (commandString)
                {
                    case "global":
                        IsGlobal = true;
                        globalExtension = 1;
                        break;

                    case "id":
                        PolicyId = int.Parse(command.GetParam(++i));
                        break;

                    case "name":
                        PolicyName = command.GetParam(++i);
                        nameExtension = 2;
                        break;

                    case "from":
                        SrcZone = command.GetParam(++i);
                        break;

                    case "to":
                        DestZone = command.GetParam(++i);
                        break;

                    case "disable":
                        IsDisabled = true;
                        return;

                    case "application":
                        NotAnInterestingCommand = true;
                        return;

                    case "default-permit-all":
                        IsDefaultPermitAll = true;
                        return;

                    default:
                        // policy with only id, informs the start of children
                        if (!(string.IsNullOrEmpty(commandString) && i == 4 && PolicyId != 0))
                        {
                            KnownCommand = false;
                            ConversionIncidentMessage = "Unknown format of " + Name() + " object. Ignoring this command";
                        }

                        return;
                }

                ++i;
            }
            while (i < (7 + nameExtension + globalExtension) && !string.IsNullOrEmpty(commandString));

            SrcObject = command.GetParam(i++);
            DestObject = command.GetParam(i++);
            ServiceName = command.GetParam(i++);

            // Check if VIP or MIP Nat Policy
            PolicyNatType = GetDestNatType(DestObject);

            // Check if policy based destination, source or either Nat
            commandString = command.GetParam(i++);
            if (commandString == "nat")
            {
                PolicyNatTypeEnum natType = ParseNatPart(command, ref i);
                if (PolicyNatType != PolicyNatTypeEnum.Policy)
                {
                    MixedNAT = true;
                }
                else
                {
                    PolicyNatType = natType;
                }
                commandString = command.GetParam(i++);
            }

            // Action
            switch (commandString)
            {
                case "permit":
                    Action = ActoinEnum.Permit;
                    break;

                case "reject":
                    Action = ActoinEnum.Reject;
                    break;

                case "deny":
                    Action = ActoinEnum.Deny;
                    break;

                case "tunnel":
                    Action = ActoinEnum.Na;
                    PolicyNatType = PolicyNatTypeEnum.Na;
                    NotAnInterestingCommand = true;
                    break;

                default:
                    Action = ActoinEnum.Na;
                    ConversionIncidentType = ConversionIncidentType.Informative;
                    ConversionIncidentMessage = ActionStr + " ";
                    break;
            }

            if (NotAnInterestingCommand)
            {
                return;
            }

            do
            {
                commandString = command.GetParam(i++);
                switch (commandString)
                {
                    case "log":
                        IsLogEnabled = true;
                        break;

                    case "":
                        break;

                    default:
                        ConversionIncidentType = ConversionIncidentType.Informative;
                        ConversionIncidentMessage += commandString + " ";
                        break;
                }
            } while (!string.IsNullOrEmpty(commandString));

            if (ConversionIncidentType != ConversionIncidentType.None)
            {
                ConversionIncidentMessage = "ScreenOS policy object option \"" + ConversionIncidentMessage + "\" is not supported. Ignoring this part of object";
            }
        }

        public static PolicyNatTypeEnum GetDestNatType(string destObjName)
        {   
            if (destObjName.Trim('"') == "Any" || destObjName.Trim('"').Length < 4)
            {
                return PolicyNatTypeEnum.Policy;
            }

            string strPrefix = destObjName.Trim('"').Substring(0, 4);
            if (strPrefix == "MIP(")
            {
                return PolicyNatTypeEnum.Mip;
            }

            if (strPrefix == "VIP(")
            {
                return PolicyNatTypeEnum.Vip;
            }

            return PolicyNatTypeEnum.Policy;
        }

        private PolicyNatTypeEnum ParseNatPart(ScreenOSCommand command, ref int baseIndex)
        {
            var policyNatType = PolicyNatTypeEnum.Na;
            string commandString = command.GetParam(baseIndex);

            // Source policy based nat
            if (commandString == "src")
            {
                policyNatType = PolicyNatTypeEnum.Dip;
                commandString = command.GetParam(++baseIndex);
                if (commandString == "dip-id")
                {
                    commandString = command.GetParam(++baseIndex);
                    DipId = int.Parse(commandString);
                    commandString = command.GetParam(++baseIndex);
                }
            }

            // Destination policy based nat
            if (commandString == "dst")
            {
                if (policyNatType == PolicyNatTypeEnum.Dip)
                {
                    policyNatType = PolicyNatTypeEnum.PolicyBaseSrcDest;
                }
                else
                {
                    policyNatType = PolicyNatTypeEnum.PolicyBaseDest;
                }

                baseIndex++;
                commandString = command.GetParam(++baseIndex);

                DestNatIp = new List<string>();
                // Get first IP
                DestNatIp.Add(commandString);

                commandString = command.GetParam(++baseIndex);
                if (NetworkUtils.IsValidIpv4(commandString))
                {
                    DestNatIp.Add(commandString);
                    commandString = command.GetParam(++baseIndex);
                }

                if (commandString == "port")
                {
                    commandString = command.GetParam(++baseIndex);
                    DestNatPort = int.Parse(commandString);
                    commandString = command.GetParam(++baseIndex);
                }
            }

            return policyNatType;
        }
    }

    public class ScreenOsCommand_InterfceNatDIP: ScreenOSCommand
    {
        private readonly int _baseIndex = 3;
        private bool _isPATEnabled;

        public int DipId { get; set; }
        public string IpStart { get; set; }
        public string IpEnd { get; set; }
        public string ShiftFromIp { get; set; }

        public bool IsPATEnabled
        {
            get
            {
                if (!string.IsNullOrEmpty(ShiftFromIp))
                {
                    return false;
                }
                return _isPATEnabled;
            }
            set
            {
                _isPATEnabled = value;
            }
        }

        public ScreenOsCommand_InterfceNatDIP()
        {
            KnownCommand = true;
            DipId = 0;
            IpStart = "";
            IpEnd = "";
            IsPATEnabled = true;
            ShiftFromIp = "";
        }

        public override string Name() { return "dip"; }

        public override void Parse(ScreenOSCommand command)
        {
            int paramIndex = command.GetParamPosition("dip");
            
            if (paramIndex < _baseIndex)
            {
                NotAnInterestingCommand = true;
                return;
            }
                
            if (paramIndex != _baseIndex)
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                List<string> notSupportedParams = command.GetParams(3, paramIndex - 3);
                ConversionIncidentMessage = string.Join(" ", notSupportedParams.ToArray()) + ", " ;
            }

            // Get Dip Id
            string commandParam = command.GetParam(++paramIndex);
            int tempInt = 0;
            if (int.TryParse(commandParam, out tempInt))
            {
                DipId = tempInt;
            }
            else if (commandParam == "interface-ip")
            {
                NotAnInterestingCommand = true;
                return;
            }

            // Get IP
            commandParam = command.GetParam(++paramIndex);

            if (commandParam == "shift-from")
            {
                ShiftFromIp = command.GetParam(++paramIndex);
                ++paramIndex;
                commandParam = command.GetParam(++paramIndex);
            }
            IpStart = commandParam;
            IpEnd = command.GetParam(++paramIndex);

            // Get extensions
            do
            {
                commandParam = command.GetParam(++paramIndex);
                if (string.IsNullOrEmpty(commandParam) == false)
                {
                    if (commandParam == "fix-port")
                    {
                        IsPATEnabled = false;
                    }
                    else
                    {
                        ConversionIncidentType = ConversionIncidentType.Informative;
                        ConversionIncidentMessage += commandParam + " ";
                    }
                }
            } while (string.IsNullOrEmpty(commandParam) == false);

            if (ConversionIncidentType != ConversionIncidentType.None)
            {
                ConversionIncidentMessage = "ScreenOS interface object with DIP instruction, option \"" + ConversionIncidentMessage + "\" is not supported. Ignoring this part of object";
            }
        }
    }

    public class ScreenOsCommand_GroupNatDIP : ScreenOSCommand
    {
        private readonly int _baseIndex = 3;

        public int GroupDipId { get; set; }
        public int DipMember { get; set; }

        public ScreenOsCommand_GroupNatDIP()
        {
            KnownCommand = true;
            GroupDipId = 0;
            DipMember = 0;
        }

        public override string Name() { return "dip group"; }

        public override void Parse(ScreenOSCommand command)
        {
           int paramIndex = _baseIndex;

            // Get group Dip Id
            string commandParam = command.GetParam(paramIndex);
            int tempInt = 0;
            if (int.TryParse(commandParam, out tempInt))
            {
                GroupDipId = tempInt;
            }
            else 
            {
                NotAnInterestingCommand = true;
                return;
            }

            // Get Dip Member if exists
            commandParam = command.GetParam(++paramIndex);
            if (string.IsNullOrEmpty(commandParam))
            {
                return;
            }

            if (commandParam == "member")
            {
                DipMember = int.Parse(command.GetParam(++paramIndex));
            }

            // Get extensions
            if (string.IsNullOrEmpty(command.GetParam(++paramIndex)) == false)
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "ScreenOS DIP object option \"" + string.Join(" ", command.GetParams(paramIndex, command.GetNumOfParams()).ToArray()) + " is not supported. Ignoring this part of object";
            }
        }
    }

    public class ScreenOsCommand_InterfceNatMIP : ScreenOSCommand
    {
        private readonly int _baseIndex = 3;

        public string Mip { get; set; }
        public string Ip { get; set; }
        public string Mask { get; set; }
        public string VrName { get; set; }

        public ScreenOsCommand_InterfceNatMIP()
        {
            KnownCommand = true;
            Mip = "";
            Ip = "";
            Mask = "";
            VrName = "";
        }

        public override string Name() { return "mip"; }

        public override void Parse(ScreenOSCommand command)
        {
            int paramIndex = command.GetParamPosition("mip");

            if (paramIndex < _baseIndex)
            {
                NotAnInterestingCommand = true;
                return;
            }

            // Get Mip
            string commandParam = command.GetParam(++paramIndex);
            if (NetworkUtils.IsValidIpv4(commandParam))
            {
                Mip = commandParam;
            }
            else
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "ScreenOS interface object with MIP instruction, option " + commandParam + " is not supported. Ignoring command";
                return;
            }

            // Get IP
            paramIndex += 2;
            commandParam = command.GetParam(paramIndex);
            if (NetworkUtils.IsValidIpv4(commandParam))
            {
                Ip = commandParam;
            }
            else
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "ScreenOS interface object with MIP instruction, option " + commandParam + " is not supported. Ignoring command";
                return;
            }

            // Get Mask
            paramIndex += 2;
            commandParam = command.GetParam(paramIndex);
            if (NetworkUtils.IsValidNetmaskv4(commandParam))
            {
                Mask = commandParam;
            }
            else
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage  = "ScreenOS interface object with MIP instruction, option " + commandParam + " is not supported. Ignoring command";
                return;
            }

            // VR
            commandParam = command.GetParam(++paramIndex);
            if (commandParam == "vr")
            {
                VrName = command.GetParam(++paramIndex);
            }

            if (!string.IsNullOrEmpty(command.GetParam(++paramIndex)))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "ScreenOS interface object with MIP instruction, option " + string.Join(" ", command.GetParams(paramIndex, command.GetNumOfParams()).ToArray()) + " is not supported. Ignoring this command";
            }
        }
    }

    public class ScreenOsCommand_InterfceNatVIP : ScreenOSCommand
    {
        public class VipInfo
        {
            private string _destServiceName;

            public int SrcPort { get; set; }
            public string DetsIp { get; set; }

            public string DestServiceName
            {
                get { return _destServiceName; }
                set { _destServiceName = value.Trim('"'); }
            }

            public VipInfo()
            {
                _destServiceName = "";
                SrcPort = 0;
                DestServiceName = "";
                DetsIp = "";
            }
        }

        private readonly int _baseIndex = 3;

        public string Vip { get; set; }
        public bool ShuoldUseInterfcaeIp { get; set; }
        public VipInfo VipData { get; set; }    

        public ScreenOsCommand_InterfceNatVIP()
        {
            KnownCommand = true;
            Vip = "";
            ShuoldUseInterfcaeIp = false;
            VipData = null;
        }

        public override string Name() { return "vip"; }

        public override void Parse(ScreenOSCommand command)
        {
            int paramIndex = command.GetParamPosition("vip");

            if (paramIndex < _baseIndex)
            {
                NotAnInterestingCommand = true;
                return;
            }

            // Get vip
            string commandParam = command.GetParam(++paramIndex);
            if (commandParam == "interface-ip")
            {
                ShuoldUseInterfcaeIp = true;
            }
            else
            {
                Vip = commandParam;
            }

            commandParam = command.GetParam(++paramIndex);
            if (commandParam == "+")
            {
                commandParam = command.GetParam(++paramIndex);
            }

            if (commandParam == "port-range")
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage += "ScreenOS interface object with VIP instruction, option \"port-range\" is not supported";
                return;
            }

            int tempInt = 0;
            if (int.TryParse(commandParam, out tempInt) == false)
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "ScreenOS interface object with VIP instruction, option \"" + commandParam + "\" is not supported";
                return;
            }

            VipData = new VipInfo();
            VipData.SrcPort = tempInt;
            VipData.DestServiceName = command.GetParam(++paramIndex);
            VipData.DetsIp = command.GetParam(++paramIndex);

            if (!string.IsNullOrEmpty(command.GetParam(++paramIndex)))
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage += "ScreenOS interface object with VIP instruction, option \"" + string.Join(" ", command.GetParams(paramIndex, command.GetNumOfParams()).ToArray()) + "\" is not supported. Ignoring this part of object";
            }
        }
    }
}
