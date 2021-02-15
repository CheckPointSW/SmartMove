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
using System.Text.RegularExpressions;
using CommonUtils;

namespace CiscoMigration
{
    public enum ProtocolType { NA, Ip, Icmp, Udp, Tcp, KnownOtherIpProtocol, ReferenceObject };
    public enum TcpUdpPortOperatorType { NA, All, Lt, Gt, Eq, Neq, Range, ReferenceObject };
    public enum ServiceDirection { Source, Destination };

    public interface ICiscoCommand
    {
        string Name();
        void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases);
    }

    /// <summary>
    /// Represents a basic Cisco command.
    /// Each derived command auto-parses the appropriate configuration line text according to its "name" (via reflection mechanism).
    /// Some commands may have child commands (network group commad has child network object commands).
    /// The "Id" property is the configuration line number.
    /// The "ParentId" property is the parent configuration line number.
    /// The "CiscoId" property is the user defined name of the command.
    /// </summary>
    public class CiscoCommand : ICiscoCommand
    {
        public const string InterfacePrefix = "Interface_";
        public const string Any = "any";

        private string _text = "";
        private string[] _words;

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

                _words = trimmedText.Split(delimiterChars);
            }
        }

        public int IndentationLevel
        {
            get
            {
                if (Text.Length == 0)
                {
                    return 0;
                }

                int pos = 0;
                while (Text.Substring(pos, 1) == " ")
                {
                    pos++;
                }
                return pos;
            }
        }

        public string FirstWord
        {
            get
            {
                if (_words != null && _words.Any())
                {
                    // This is a special handling!!!
                    // There are several commands that have the first word "ip"...
                    if (_words[0] == "ip")
                    {
                        if (_words.Count() > 1 && _words[1] == "address")
                        {
                            return _words[0] + " " + _words[1];
                        }
                        if (_words.Count() > 3 && _words[1] == "verify" && _words[2] == "reverse-path" && _words[3] == "interface")
                        {
                            return _words[0] + " " + _words[1] + " " + _words[2] + " " + _words[3];
                        }
                    }
                    else
                    {
                        return _words[0];
                    }
                }

                return "";
            }
        }

        public int Id { get; set; }
        public int? ParentId { get; set; }
        public string CiscoId { get; set; }
        public string Description { get; set; }
        public string Tag { get; set; }
        public string DataForNextElement { get; set; }
        public bool KnownCommand { get; set; }
        public bool NotAnInterestingCommand { get; set; }
        public ConversionIncidentType ConversionIncidentType { get; set; }
        public string ConversionIncidentMessage { get; set; }
        public List<CiscoCommand> Children { get; set; }

        public CiscoCommand()
        {
            CiscoId = "";
            Description = "";
            DataForNextElement = "";
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

        public List<CiscoCommand> Flatten()
        {
            var res = new List<CiscoCommand>();
            res.Add(this);

            if (Children != null)
            {
                foreach (CiscoCommand child in Children)
                {
                    foreach (CiscoCommand flattenchild in child.Flatten())
                    {
                        res.Add(flattenchild);
                    }
                }
            }

            return res;
        }

        public virtual string Name() { return ""; }

        public virtual void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            if (command.Children != null)
            {
                foreach (CiscoCommand child in command.Children)
                {
                    if (child.Name() == "description")
                    {
                        Description = child.Description;
                    }
                }
            }

            ConversionIncidentType = ConversionIncidentType.None;
            ConversionIncidentMessage = "";
        }
    }

    public class Cisco_Description : CiscoCommand
    {
        public Cisco_Description()
        {
            NotAnInterestingCommand = true;
        }

        public override string Name() { return "description"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            if (!string.IsNullOrEmpty(command.Text))
            {
                Description = command.Text.Trim().Substring(Name().Length + 1);
            }

        }
    }

    public class Cisco_ASA : CiscoCommand
    {
        public string Version { get; set; }

        public override string Name() { return "ASA"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            const string version = "version";
            if (!string.IsNullOrEmpty(command.Text) && command.GetParam(1).ToLower() == version)
            {
                Version = command.Text.Trim().Substring(Name().Length + version.Length + 2);
            }
            else
            {
                Version = "";
            }
        }
    }

    public class Cisco_Alias : CiscoCommand
    {
        public override string Name() { return "name"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            string real = command.GetParam(1);
            string alias = command.GetParam(2);

            if (!string.IsNullOrEmpty(alias) && !string.IsNullOrEmpty(real) && !aliases.ContainsKey(alias))
            {
                aliases.Add(alias, real);
            }
        }
    }

    public class Cisco_SSH : CiscoCommand
    {
        public string IpAddress { get; set; }
        public string Netmask { get; set; }
        public string Interface { get; set; }

        public override string Name() { return "ssh"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            IpAddress = "";
            Netmask = "";
            Interface = "";

            string commandParam = command.GetParam(1);
            if (NetworkUtils.IsValidIp(commandParam))
            {
                IpAddress = commandParam;
            }
            else
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "IPv4 address was expected, but '" + commandParam + "' was found.";
                return;
            }

            commandParam = command.GetParam(2);
            if (NetworkUtils.IsValidNetmaskv4(commandParam))
            {
                Netmask = commandParam;
            }
            else
            {
                IpAddress = "";
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "IPv4 netmask was expected, but " + commandParam + " was found.";
                return;
            }

            Interface = command.GetParam(3);
        }
    }

    public class Cisco_Hostname : CiscoCommand
    {
        public string HostName { get; set; }

        public override string Name() { return "hostname"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            HostName = command.GetParam(1);
        }
    }

    public class Cisco_Object : CiscoCommand
    {
        public enum ObjectTypes { NA, Fqdn, Host, Network, Range, TcpService, UdpService, IcmpService, KnownOtherService };

        public ObjectTypes ObjectType { get; set; }
        public string Fqdn { get; set; }
        public string HostAddress { get; set; }
        public string Network { get; set; }
        public string Netmask { get; set; }
        public string MaskPrefix { get; set; }
        public string RangeFrom { get; set; }
        public string RangeTo { get; set; }
        public bool IsDestination { get; set; }
        public string ServiceProtocol { get; set; }
        public string ServiceOperator { set; get; }
        public string ServicePort { get; set; }

        public override string Name() { return "object"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            CiscoId = command.GetParam(2);
            ObjectType = ObjectTypes.NA;

            switch (command.GetParam(1))
            {
                case "network":
                    ParseNetworks();
                    break;

                case "service":
                    ParseServices();
                    break;

                default:
                    ConversionIncidentType = ConversionIncidentType.Informative;
                    ConversionIncidentMessage = "Unrecognized object type (" + command.GetParam(1) + ")";
                    break;
            }
        }

        private void ParseNetworks()
        {
            if (Children == null)
            {
                return;
            }

            int found = 0;

            foreach (CiscoCommand child in Children)
            {
                switch (child.Name())
                {
                    case "fqdn":
                        ObjectType = ObjectTypes.Fqdn;
                        Fqdn = ((Cisco_Fqdn)child).Fqdn;
                        found++;
                        break;

                    case "host":
                        ObjectType = ObjectTypes.Host;
                        HostAddress = ((Cisco_Host)child).HostAddress;
                        found++;
                        break;

                    case "subnet":
                        ObjectType = ObjectTypes.Network;
                        Network = ((Cisco_Subnet)child).Network;
                        Netmask = ((Cisco_Subnet)child).Netmask;
                        MaskPrefix = ((Cisco_Subnet)child).MaskPrefix;
                        found++;
                        break;

                    case "range":
                        ObjectType = ObjectTypes.Range;
                        RangeFrom = ((Cisco_Range)child).RangeFrom;
                        RangeTo = ((Cisco_Range)child).RangeTo;
                        found++;
                        break;
                }

                if (found == 1)
                {
                    if (child.ConversionIncidentType != ConversionIncidentType.None)
                    {
                        ConversionIncidentType = child.ConversionIncidentType;
                        ConversionIncidentMessage = child.ConversionIncidentMessage;
                    }
                }
            }

            if (found > 1)
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "An Object (network) can only hold one fqdn, host, range or subnet";
                Console.WriteLine(ConversionIncidentMessage);
            }
        }

        private void ParseServices()
        {
            if (Children == null)
            {
                return;
            }

            int found = 0;

            foreach (CiscoCommand child in Children)
            {
                if (child.Name() == "service")
                {
                    found++;

                    var service = (Cisco_Service)child;
                    ServiceProtocol = service.Protocol;
                    ServiceOperator = service.Operator;
                    ServicePort = service.Port;
                    IsDestination = service.IsDestination;

                    if (service.ConversionIncidentType != ConversionIncidentType.None)
                    {
                        ConversionIncidentType = service.ConversionIncidentType;
                        ConversionIncidentMessage = service.ConversionIncidentMessage;
                    }

                    switch (ServiceProtocol)
                    {
                        case "ip":
                            // Predefined "any" object. No special handling...
                            break;

                        case "icmp":
                            ObjectType = ObjectTypes.IcmpService;
                            break;

                        case "tcp":
                            ObjectType = ObjectTypes.TcpService;
                            break;

                        case "udp":
                            ObjectType = ObjectTypes.UdpService;
                            break;

                        default:
                            // No need to check also for CiscoKnownServices.IsKnownServiceNumber here, 
                            // because it is already done in Cisco_Service class!!!
                            if (CiscoKnownServices.IsKnownService(ServiceProtocol))
                            {
                                ObjectType = ObjectTypes.KnownOtherService;
                            }
                            else
                            {
                                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                                ConversionIncidentMessage = "Unrecognized service protocol (" + ServiceProtocol + ")";
                                Console.WriteLine(ConversionIncidentMessage);
                            }
                            break;
                    }
                }
            }

            if (found > 1)
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "An Object (service) can only hold one service";
                Console.WriteLine(ConversionIncidentMessage);
            }
        }
    }

    public class Cisco_Fqdn : CiscoCommand
    {
        public string Fqdn { get; set; }

        public override string Name() { return "fqdn"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            Fqdn = (command.GetParam(1) == "v4") ? command.GetParam(2) : command.GetParam(1);
        }
    }

    public class Cisco_Host : CiscoCommand
    {
        public string HostAddress { get; set; }

        public override string Name() { return "host"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            HostAddress = command.GetParam(1);
            if (!NetworkUtils.IsValidIp(HostAddress))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Invalid host IP address (" + HostAddress + "). Using IP 1.1.1.1.";
                Console.WriteLine(ConversionIncidentMessage);

                HostAddress = "1.1.1.1";
            }
        }
    }

    public class Cisco_Subnet : CiscoCommand
    {
        public string Network { get; set; }
        public string Netmask { get; set; }
        public string MaskPrefix { get; set; }

        public override string Name() { return "subnet"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            Network = command.GetParam(1);
            Netmask = command.GetParam(2);
            string sNetwork;
            string sMaskLength;
            if (NetworkUtils.TryParseNetwortWithPrefix(Network, out sNetwork, out sMaskLength))
            {
                Network = sNetwork;
                MaskPrefix = sMaskLength;
            }
            else if (!NetworkUtils.IsValidIpv4(Network) || !NetworkUtils.IsValidNetmaskv4(Netmask))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Invalid IP subnet (" + Network + "/" + Netmask + "). Using IP subnet 1.1.1.0/255.255.255.0.";
                Console.WriteLine(ConversionIncidentMessage);

                Network = "1.1.1.0";
                Netmask = "255.255.255.0";
            }
        }
    }

    public class Cisco_Range : CiscoCommand
    {
        public string RangeFrom { get; set; }
        public string RangeTo { get; set; }

        public override string Name() { return "range"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            RangeFrom = command.GetParam(1);
            if (!NetworkUtils.IsValidIp(RangeFrom))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Invalid range starting IP address (" + RangeFrom + "). Using IP 0.0.0.0.";
                Console.WriteLine(ConversionIncidentMessage);

                RangeFrom = "0.0.0.0";
            }

            RangeTo = command.GetParam(2);
            if (!NetworkUtils.IsValidIp(RangeTo))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Invalid range ending IP address (" + RangeTo + "). Using IP 255.255.255.255.";
                Console.WriteLine(ConversionIncidentMessage);

                RangeTo = "255.255.255.255";
            }
        }
    }

    public class Cisco_Service : CiscoCommand
    {
        public string Protocol { get; set; }
        public bool IsDestination { get; set; }
        public string Port { get; set; }
        public string Operator { get; set; }

        public override string Name() { return "service"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            // Parsing Options:
            //-----------------
            // 1. service protocol_name_or_number
            // 2. service {icmp | icmp6} [icmp-type]
            // 3. service {tcp | udp} [source operator port] [destination operator port]
            //-----------------

            Protocol = command.GetParam(1);

            IsDestination = false;
            Port = "";
            Operator = "";

            switch (Protocol)
            {
                case "ip":
                    IsDestination = true;
                    break;

                case "icmp":
                case "icmp6":
                    IsDestination = true;
                    Protocol = "icmp";
                    Operator = "eq";
                    Port = CiscoKnownServices.ConvertIcmpServiceToType(command.GetParam(2));
                    break;

                case "tcp":
                case "udp":
                    IsDestination = (command.GetParam(2) == "destination");
                    Operator = command.GetParam(3);
                    Port = CiscoKnownServices.ConvertServiceToPort(command.GetParam(4));

                    int nextParamId = 5;   // we need this because of 'range' operator

                    if (Operator == "range")
                    {
                        Operator = "eq";
                        Port = Port + "-" + CiscoKnownServices.ConvertServiceToPort(command.GetParam(5));
                        nextParamId = 6;   // !!!
                    }

                    if (!IsDestination && command.GetParam(nextParamId) == "destination")
                    {
                        // "service tcp source eq ssh destination eq ssh" ---> wrong!!! ---> ignore source!!!
                        ConversionIncidentType = ConversionIncidentType.Informative;
                        ConversionIncidentMessage = "Cannot convert a service defined as both source service and destination service. Ignoring source service.";
                        Console.WriteLine(ConversionIncidentMessage);

                        IsDestination = true;
                        Operator = command.GetParam(nextParamId + 1);
                        Port = CiscoKnownServices.ConvertServiceToPort(command.GetParam(nextParamId + 2));

                        if (Operator == "range")
                        {
                            Operator = "eq";
                            Port = Port + "-" + CiscoKnownServices.ConvertServiceToPort(command.GetParam(nextParamId + 3));
                        }
                    }

                    if (string.IsNullOrEmpty(Operator) || string.IsNullOrEmpty(Port))
                    {
                        // Use ALL tcp/udp ports if nothing specified!!!
                        IsDestination = true;
                        Operator = "all";
                        Port = "1-65535";
                    }
                    break;

                default:
                    IsDestination = true;

                    string serviceName;
                    if (CiscoKnownServices.IsKnownService(Protocol))
                    {
                        Port = CiscoKnownServices.ConvertServiceToPort(Protocol);
                    }
                    else if (CiscoKnownServices.IsKnownServiceNumber(Protocol, out serviceName))   // protocol number is used!!!
                    {
                        Port = Protocol;
                        Protocol = serviceName;
                    }
                    else
                    {
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = "Unrecognized service protocol (" + Protocol + ")";
                        Console.WriteLine(ConversionIncidentMessage);
                    }
                    break;
            }
        }
    }

    public class Cisco_NetworkObject : CiscoCommand
    {
        public string IpAddress { get; set; }
        public string Netmask { get; set; }
        public string MaskPrefix { get; set; }
        public string ReferencedObject { get; set; }

        public override string Name() { return "network-object"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            IpAddress = "";
            Netmask = "";
            ReferencedObject = "";

            switch (command.GetParam(1))
            {
                case "object":
                    ReferencedObject = command.GetParam(2);
                    break;

                case "host":
                    string ipAddressOrObjectName = command.GetParam(2);
                    if (ciscoIds.ContainsKey(ipAddressOrObjectName))
                    {
                        ReferencedObject = ipAddressOrObjectName;
                    }
                    else
                    {
                        IpAddress = aliases.ContainsKey(ipAddressOrObjectName) ? aliases[ipAddressOrObjectName] : ipAddressOrObjectName;
                        if (!NetworkUtils.IsValidIp(IpAddress))
                        {
                            ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                            ConversionIncidentMessage = "Invalid IP address (" + IpAddress + "). Using IP 1.1.1.1.";
                            Console.WriteLine(ConversionIncidentMessage);

                            IpAddress = "1.1.1.1";
                        }

                        Netmask = "255.255.255.255";
                    }
                    break;

                default:
                    // subnet
                    IpAddress = command.GetParam(1);
                    if (aliases.ContainsKey((IpAddress)))
                    {
                        IpAddress = aliases[IpAddress];
                    }
                    Netmask = command.GetParam(2);

                    string sIp;
                    string sMaskLenth;
                    if (NetworkUtils.TryParseNetwortWithPrefix(IpAddress, out sIp, out sMaskLenth))
                    {
                        IpAddress = sIp;
                        MaskPrefix = sMaskLenth;
                    }
                    else if (!NetworkUtils.IsValidIpv4(IpAddress) || !NetworkUtils.IsValidNetmaskv4(Netmask))
                    {
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = "Invalid IP subnet (" + IpAddress + "/" + Netmask + "). Using IP subnet 1.1.1.0/255.255.255.0.";
                        Console.WriteLine(ConversionIncidentMessage);

                        IpAddress = "1.1.1.0";
                        Netmask = "255.255.255.0";
                    }
                    break;
            }
        }
    }

    public class Cisco_ProtocolObject : CiscoCommand
    {
        public string ProtocolName { get; set; }

        public override string Name() { return "protocol-object"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            ProtocolName = command.GetParam(1);
        }
    }

    public class Cisco_PortObject : CiscoCommand
    {
        public string Port { get; set; }

        public override string Name() { return "port-object"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            Port = "";

            string portOperator = command.GetParam(1);

            switch (portOperator)
            {
                case "eq":
                    Port = CiscoKnownServices.ConvertServiceToPort(command.GetParam(2));
                    break;

                case "range":
                    Port = CiscoKnownServices.ConvertServiceToPort(command.GetParam(2)) + "-" + CiscoKnownServices.ConvertServiceToPort(command.GetParam(3));
                    break;
            }
        }
    }

    public class Cisco_ServiceObject : CiscoCommand
    {
        public string Protocol { get; set; }
        public bool IsDestination { get; set; }
        public string Port { get; set; }
        public string Operator { get; set; }
        public string RefObjectName { get; set; }

        public override string Name() { return "service-object"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            // Parsing Options:
            //-----------------
            // 1. service-object object object_name
            // 2. service-object protocol_name_or_number
            // 3. service-object {icmp | icmp6} [icmp-type]
            // 4. service-object {tcp | udp | tcp-udp} [source operator port] [destination operator port]
            //-----------------

            Protocol = command.GetParam(1);

            IsDestination = false;
            Port = "";
            Operator = "";
            RefObjectName = "";

            switch (Protocol)
            {
                case "object":
                    RefObjectName = command.GetParam(2);
                    Protocol = "";
                    break;

                case "ip":
                    IsDestination = true;
                    break;

                case "icmp":
                case "icmp6":
                    IsDestination = true;
                    Protocol = "icmp";
                    Operator = "eq";
                    Port = CiscoKnownServices.ConvertIcmpServiceToType(command.GetParam(2));
                    break;

                case "tcp":
                case "udp":
                case "tcp-udp":
                    IsDestination = (command.GetParam(2) == "destination");
                    Operator = command.GetParam(3);
                    Port = CiscoKnownServices.ConvertServiceToPort(command.GetParam(4));

                    int nextParamId = 5;   // we need this because of 'range' operator

                    if (Operator == "range")
                    {
                        Operator = "eq";
                        Port = Port + "-" + CiscoKnownServices.ConvertServiceToPort(command.GetParam(5));
                        nextParamId = 6;   // !!!
                    }

                    if (!IsDestination && command.GetParam(nextParamId) == "destination")
                    {
                        // "service-object tcp source eq ssh destination eq ssh" ---> wrong!!! ---> ignore source!!!
                        ConversionIncidentType = ConversionIncidentType.Informative;
                        ConversionIncidentMessage = "Cannot convert a service defined as both source service and destination service. Ignoring source service.";
                        Console.WriteLine(ConversionIncidentMessage);

                        IsDestination = true;
                        Operator = command.GetParam(nextParamId + 1);
                        Port = CiscoKnownServices.ConvertServiceToPort(command.GetParam(nextParamId + 2));

                        if (Operator == "range")
                        {
                            Operator = "eq";
                            Port = Port + "-" + CiscoKnownServices.ConvertServiceToPort(command.GetParam(nextParamId + 3));
                        }
                    }

                    if (string.IsNullOrEmpty(Operator) || string.IsNullOrEmpty(Port))
                    {
                        // Use ALL tcp/udp ports if nothing specified!!!
                        IsDestination = true;
                        Operator = "all";
                        Port = "1-65535";
                    }
                    break;

                default:
                    IsDestination = true;

                    string serviceName;
                    if (CiscoKnownServices.IsKnownService(Protocol))
                    {
                        Port = CiscoKnownServices.ConvertServiceToPort(Protocol);
                    }
                    else if (CiscoKnownServices.IsKnownServiceNumber(Protocol, out serviceName))   // protocol number is used!!!
                    {
                        Port = Protocol;
                        Protocol = serviceName;
                    }
                    else
                    {
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = "Unrecognized service protocol (" + Protocol + ")";
                        Console.WriteLine(ConversionIncidentMessage);
                    }
                    break;
            }
        }
    }

    public class Cisco_IcmpObject : CiscoCommand
    {
        public string IcmpType { get; set; }

        public override string Name() { return "icmp-object"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            IcmpType = command.GetParam(1);
        }
    }

    public class Cisco_ReferenceGroupObject : CiscoCommand
    {
        public string ReferenceId { get; set; }

        public override string Name() { return "group-object"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            ReferenceId = command.GetParam(1);
        }
    }

    public class Cisco_GroupObject : CiscoCommand
    {
        public enum Group_Type { NA, Service, Protocol, Icmp, Network };

        private Dictionary<string, CiscoCommand> _ciscoIds;

        public Group_Type GroupType { get; set; }
        public string ServiceProtocol { get; set; }

        public List<string> Protocols = new List<string>();
        public List<string> IcmpTypes = new List<string>();
        public List<string> MembersGroupNames = new List<string>();
        public List<CiscoCommand> MemberObjects = new List<CiscoCommand>();

        public override string Name() { return "object-group"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            _ciscoIds = ciscoIds;

            CiscoId = command.GetParam(2);
            ServiceProtocol = "";

            switch (command.GetParam(1))
            {
                case "service":
                    GroupType = Group_Type.Service;
                    break;

                case "protocol":
                    GroupType = Group_Type.Protocol;
                    break;

                case "icmp-type":
                    GroupType = Group_Type.Icmp;
                    break;

                case "network":
                    GroupType = Group_Type.Network;
                    break;

                default:
                    GroupType = Group_Type.NA;
                    ConversionIncidentType = ConversionIncidentType.Informative;
                    ConversionIncidentMessage = "Unrecognized group type (" + command.GetParam(1) + ")";
                    return;
            }

            if (GroupType == Group_Type.Service)
            {
                ServiceProtocol = command.GetParam(3);
            }

            if (command.Children == null)
            {
                return;
            }

            foreach (CiscoCommand child in command.Children)
            {
                bool hasValidChild = true;

                switch (child.Name())
                {
                    case "protocol-object":
                        Protocols.Add(((Cisco_ProtocolObject)child).ProtocolName);
                        break;

                    case "port-object":
                        MemberObjects.Add((Cisco_PortObject)child);
                        break;

                    case "icmp-object":
                        IcmpTypes.Add(((Cisco_IcmpObject)child).IcmpType);
                        break;

                    case "group-object":
                        MembersGroupNames.Add(((Cisco_ReferenceGroupObject)child).ReferenceId);
                        break;

                    case "network-object":
                        MemberObjects.Add((Cisco_NetworkObject)child);
                        break;

                    case "service-object":
                        MemberObjects.Add((Cisco_ServiceObject)child);
                        break;

                    default:
                        hasValidChild = false;
                        break;
                }

                if (hasValidChild)
                {
                    if (child.ConversionIncidentType != ConversionIncidentType.None)
                    {
                        ConversionIncidentType = child.ConversionIncidentType;
                        ConversionIncidentMessage = child.ConversionIncidentMessage;
                    }
                }
            }
        }

        public List<Cisco_ServiceObject> GetChildServices()
        {
            var services = new List<Cisco_ServiceObject>();

            if (Children != null)
            {
                foreach (CiscoCommand child in Children)
                {
                    if (child.Name() == "service-object")
                    {
                        services.Add((Cisco_ServiceObject)child);
                    }
                    else if (child.Name() == "group-object")
                    {
                        if (_ciscoIds.ContainsKey(((Cisco_ReferenceGroupObject)child).ReferenceId))
                        {
                            var referencedGroupObject = (Cisco_GroupObject)_ciscoIds[((Cisco_ReferenceGroupObject)child).ReferenceId];
                            var referencedGroupServices = referencedGroupObject.GetChildServices();

                            foreach (Cisco_ServiceObject referencedService in referencedGroupServices)
                            {
                                if (!services.Contains(referencedService))
                                {
                                    services.Add(referencedService);
                                }
                            }
                        }
                    }
                }
            }

            return services;
        }

        public List<Cisco_PortObject> GetChildPorts()
        {
            var ports = new List<Cisco_PortObject>();

            if (Children != null)
            {
                foreach (CiscoCommand child in Children)
                {
                    if (child.Name() == "port-object")
                    {
                        ports.Add((Cisco_PortObject)child);
                    }
                    else if (child.Name() == "group-object")
                    {
                        if (_ciscoIds.ContainsKey(((Cisco_ReferenceGroupObject)child).ReferenceId))
                        {
                            var referencedGroupObject = (Cisco_GroupObject)_ciscoIds[((Cisco_ReferenceGroupObject)child).ReferenceId];
                            var referencedGroupPorts = referencedGroupObject.GetChildPorts();

                            foreach (Cisco_PortObject referencedPort in referencedGroupPorts)
                            {
                                if (!ports.Contains(referencedPort))
                                {
                                    ports.Add(referencedPort);
                                }
                            }
                        }
                    }
                }
            }

            return ports;
        }
    }

    public class Cisco_SecurityLevel : CiscoCommand
    {
        public string Value { get; set; }

        public override string Name() { return "security-level"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            Value = command.GetParam(1);
        }
    }

    public class Cisco_NameIf : CiscoCommand
    {
        public string Value { get; set; }

        public override string Name() { return "nameif"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            Value = InterfacePrefix + command.GetParam(1);
        }
    }

    public class Cisco_VLan : CiscoCommand
    {
        public string Value { get; set; }

        public override string Name() { return "vlan"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            Value = command.GetParam(1);
        }
    }

    public class Cisco_IP : CiscoCommand
    {
        public string IpAddress { get; set; }
        public string Netmask { get; set; }

        public override string Name() { return "ip address"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            IpAddress = "";
            Netmask = "";

            if (command.GetParam(1) == "address")
            {
                IpAddress = command.GetParam(2);
                Netmask = command.GetParam(3);
            }
        }
    }

    public class Cisco_Shutdown : CiscoCommand
    {
        public bool IsShutdown { get; set; }

        public override string Name() { return "shutdown"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            IsShutdown = (command.GetParam(0) == "shutdown");
        }
    }

    public class Cisco_ManagementOnly : CiscoCommand
    {
        public bool IsManagementOnly { get; set; }

        public override string Name() { return "management-only"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);
            IsManagementOnly = (command.GetParam(0) == "management-only");
        }
    }

    public class Cisco_TimeRange : CiscoCommand
    {
        public enum Weekdays { Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday };

        private string _timeRangeName;

        private string _startDateTime;
        private string _endDateTime;

        private List<string> _periodicsList;

        public string TimeRangeName
        {
            get { return _timeRangeName; }
        }

        public string StartDateTime
        {
            get { return _startDateTime; }
        }

        public string EndDateTime
        {
            get { return _endDateTime; }
        }

        public List<string> PeriodicsList
        {
            get { return _periodicsList; }
        }

        public override string Name() { return "time-range"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            _periodicsList = new List<string>();

            _timeRangeName = this.GetParam(1);

            foreach (CiscoCommand child in Children)
            {
                if (child.FirstWord.Equals("absolute"))
                {
                    int startIndex = child.Text.IndexOf("start");
                    int endIndex = child.Text.IndexOf("end");
                    if (startIndex > -1 && endIndex > -1)
                    {
                        _startDateTime = child.Text.Substring("absolute".Length + "start".Length + 2, endIndex - startIndex - "start".Length).Trim();
                        _endDateTime = child.Text.Substring(endIndex + "end".Length).Trim();
                    }
                    else if (startIndex > -1 && endIndex == -1)
                    {
                        _startDateTime = child.Text.Substring("absolute".Length + "start".Length + 2).Trim();
                    }
                    else if (startIndex == -1 && endIndex > -1)
                    {
                        _endDateTime = child.Text.Substring("absolute".Length + "end".Length + 2).Trim();
                    }
                }

                if (child.FirstWord.Equals("periodic"))
                {
                    string period = child.Text.Substring("periodic".Length + 1).Trim();

                    string[] daysTimes = period.Trim().Split(new string[] { "to" }, StringSplitOptions.RemoveEmptyEntries);

                    string[] daysTimes_1 = daysTimes[0].Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                    string[] daysTimes_2 = daysTimes[1].Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);

                    if (daysTimes_1.Length == 2 && daysTimes_2.Length == 2)
                    {
                        int startWdIndex = (int)Enum.Parse(typeof(Weekdays), daysTimes_1[0]);
                        int endWdIndex = (int)Enum.Parse(typeof(Weekdays), daysTimes_2[0]);

                        if (startWdIndex < endWdIndex)
                        {
                            _periodicsList.Add((Weekdays)startWdIndex + " " + daysTimes_1[1] + " to 23:59");

                            for (int i = startWdIndex + 1; i <= endWdIndex - 1; i++)
                            {
                                _periodicsList.Add((Weekdays)i + " 0:00 to 23:59");
                            }

                            _periodicsList.Add((Weekdays)endWdIndex + " 0:00 to " + daysTimes_2[1]);
                        }
                        else
                        {
                            int firstWdIndex = (int)Enum.GetValues(typeof(Weekdays)).Cast<Weekdays>().First();
                            int lastWdIndex = (int)Enum.GetValues(typeof(Weekdays)).Cast<Weekdays>().Last();

                            _periodicsList.Add((Weekdays)startWdIndex + " " + daysTimes_1[1] + " to 23:59");

                            for (int i = startWdIndex + 1; i <= lastWdIndex; i++)
                            {
                                _periodicsList.Add((Weekdays)i + " 0:00 to 23:59");
                            }

                            for (int i = firstWdIndex; i <= endWdIndex - 1; i++)
                            {
                                _periodicsList.Add((Weekdays)i + " 0:00 to 23:59");
                            }

                            _periodicsList.Add((Weekdays)endWdIndex + " 0:00 to " + daysTimes_2[1]);
                        }
                    }
                    else
                    {
                        _periodicsList.Add(period);
                    }
                }
            }
        }
    }

    public class Cisco_Interface : CiscoCommand
    {
        public string InterfaceName { get; set; }
        public int SecurityLevel { get; set; }
        public string VLan { get; set; }
        public string IpAddress { get; set; }
        public string Netmask { get; set; }
        public bool Shutdown { get; set; }
        public bool ManagementOnly { get; set; }
        public bool LeadsToInternet { get; set; }

        public class Subnet
        {
            public string Network { get; private set; }
            public string Netmask { get; private set; }

            public Subnet(string sIp, string sMask)
            {
                Network = sIp;
                Netmask = sMask;
            }
        }

        public List<Subnet> Topology = new List<Subnet>();

        public override string Name() { return "interface"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            InterfaceName = command.GetParam(1);
            SecurityLevel = 0;
            VLan = "";
            IpAddress = "";
            Netmask = "";
            Shutdown = false;
            ManagementOnly = false;
            LeadsToInternet = false;

            if (command.Children == null)
            {
                return;
            }

            foreach (CiscoCommand child in command.Children)
            {
                switch (child.Name())
                {
                    case "security-level":
                        int securityLevel;
                        if (int.TryParse(((Cisco_SecurityLevel)child).Value, out securityLevel))
                        {
                            SecurityLevel = securityLevel;
                        }
                        break;

                    case "nameif":
                        CiscoId = ((Cisco_NameIf)child).Value;
                        break;

                    case "vlan":
                        VLan = ((Cisco_VLan)child).Value;
                        break;

                    case "shutdown":
                        Shutdown = ((Cisco_Shutdown)child).IsShutdown;
                        break;

                    case "management-only":
                        ManagementOnly = ((Cisco_ManagementOnly)child).IsManagementOnly;
                        break;

                    case "ip address":
                        IpAddress = ((Cisco_IP)child).IpAddress;
                        Netmask = ((Cisco_IP)child).Netmask;

                        if (NetworkUtils.IsValidIpv4(IpAddress) && NetworkUtils.IsValidNetmaskv4(Netmask))
                        {
                            Topology.Add(new Subnet(NetworkUtils.GetNetwork(IpAddress, Netmask), Netmask));
                        }
                        else
                        {
                            ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                            ConversionIncidentMessage = "Invalid IP subnet (" + IpAddress + "/" + Netmask + ").";
                            Console.WriteLine(ConversionIncidentMessage);
                        }
                        break;
                }
            }
        }

        public bool HasValidIpAddress()
        {
            return NetworkUtils.IsValidIp(IpAddress) && NetworkUtils.IsValidNetmaskv4(Netmask);
        }
    }

    public class Cisco_Route : CiscoCommand
    {
        public string InterfaceName { get; set; }
        public bool DefaultRoute { get; set; }
        public string DestinationIp { get; set; }
        public string DestinationNetmask { get; set; }
        public string Gateway { get; set; }

        public override string Name() { return "route"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            DefaultRoute = false;
            InterfaceName = command.GetParam(1);
            DestinationIp = command.GetParam(2);
            DestinationNetmask = command.GetParam(3);
            Gateway = command.GetParam(4);

            bool destinationIpResolved = false;

            if (ciscoIds.ContainsKey(DestinationIp))
            {
                var refObj = (Cisco_Object)ciscoIds[DestinationIp];
                if (refObj != null)
                {
                    switch (refObj.ObjectType)
                    {
                        case Cisco_Object.ObjectTypes.Host:
                            DestinationIp = refObj.HostAddress;
                            destinationIpResolved = true;
                            break;

                        case Cisco_Object.ObjectTypes.Network:
                            DestinationIp = refObj.Network;
                            destinationIpResolved = true;
                            break;
                    }
                }
            }
            else
            {
                DestinationIp = aliases.ContainsKey(DestinationIp) ? aliases[DestinationIp] : DestinationIp;
                destinationIpResolved = true;
            }

            if (!destinationIpResolved)
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Cannot resolve route destination IP address (" + command.GetParam(2) + "). Using IP 1.1.1.1.";
                Console.WriteLine(ConversionIncidentMessage);

                DestinationIp = "1.1.1.1";
                DestinationNetmask = "255.255.255.255";
            }

            if (!NetworkUtils.IsValidIp(DestinationIp))
            {
                ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                ConversionIncidentMessage = "Invalid IP address (" + DestinationIp + "). Using IP 1.1.1.1.";
                Console.WriteLine(ConversionIncidentMessage);

                DestinationIp = "1.1.1.1";
                DestinationNetmask = "255.255.255.255";
            }

            if (DestinationIp == "0.0.0.0" && DestinationNetmask == "0.0.0.0")
            {
                DefaultRoute = true;
            }
        }
    }

    public class Cisco_AntiSpoofing : CiscoCommand
    {
        public string InterfaceName { get; set; }

        public override string Name() { return "ip verify reverse-path interface"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            if (command.GetParam(1) == "verify" && command.GetParam(2) == "reverse-path" && command.GetParam(3) == "interface")
            {
                InterfaceName = command.GetParam(4);
            }
        }
    }

    public class Cisco_SameSecurityTraffic : CiscoCommand
    {
        public enum InterfaceTrafficType { NA, Inter, Intra };

        public InterfaceTrafficType TrafficType { get; set; }

        public override string Name() { return "same-security-traffic"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            if (command.GetParam(1) == "permit")
            {
                switch (command.GetParam(2))
                {
                    case "inter-interface":
                        TrafficType = InterfaceTrafficType.Inter;
                        break;

                    case "intra-interface":
                        TrafficType = InterfaceTrafficType.Intra;
                        break;
                }
            }
        }
    }

    public class Cisco_Nat : CiscoCommand
    {
        public bool Inactive { get; set; }
        public string RealInterface { get; set; }
        public string MappedInterface { get; set; }
        public bool IsStatic { get; set; }
        public bool IsHideBehindInterface { get; set; }
        public bool IsUnidirectional { get; set; }
        public bool IsAutoAfter { get; set; }
        public string StaticNatIpAddressOrObjectName { get; set; }
        public string DynamicNatIpAddressOrObjectName { get; set; }
        public string SourceId { get; set; }
        public string TranslatedSourceId { get; set; }
        public string DestinationId { get; set; }
        public string TranslatedDestinationId { get; set; }
        public string ServiceProtocol { get; set; }
        public string ServiceId { get; set; }
        public string TranslatedServiceId { get; set; }

        public override string Name() { return "nat"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            /**************************************************************************************
             * There are two types of NAT:
             * 1. Object NAT - child object of a Network Object - this is the commonly used NAT
             * 2. Regular NAT - twice or manual NAT rule - more scalable, enables extra features over Object NAT
             *
             * Each of these two types may be Static or Dynamic.
             * Static NAT allows bidirectional traffic (mirrored rules).
             * 
             * Each NAT command is started as follows:
             * ---------------------------------------
             * nat [(real_interface, mapped_interface)] ...
             * 
            **************************************************************************************/

            base.Parse(command, prevCommand, ciscoIds, aliases);

            string param = command.GetParam(1).Trim(new char[] { '(', ')' });
            string[] interfaces = param.Split(',');

            if (interfaces.Length > 0)
            {
                RealInterface = interfaces[0];
                MappedInterface = (interfaces.Length > 1) ? interfaces[1] : "";
            }
            else
            {
                RealInterface = "";
                MappedInterface = "";
            }

            Inactive = false;
            IsStatic = false;
            IsHideBehindInterface = false;
            IsUnidirectional = false;
            StaticNatIpAddressOrObjectName = "";
            DynamicNatIpAddressOrObjectName = "";
            SourceId = "";
            TranslatedSourceId = "";
            DestinationId = "";
            TranslatedDestinationId = "";
            ServiceProtocol = "";
            ServiceId = "";
            TranslatedServiceId = "";

            if (command.IndentationLevel > 0)
            {
                ParseObjectNatCommand(command, prevCommand, ciscoIds);
            }
            else
            {
                ParseRegularNatCommand(command, prevCommand, ciscoIds);
            }

            if (command.GetParamPosition("unidirectional") > 0/* || command.GetParamPosition("no-proxy-arp") > 0*/)   // commented due to A.R. suggestion...
            {
                IsUnidirectional = true;
            }

            if (command.GetParamPosition("inactive") > 0)
            {
                Inactive = true;
            }
        }

        private void ParseObjectNatCommand(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds)
        {
            /********************************************************
             * Parsing options for Object NAT:
             * -------------------------------
             * ... static {mapped_host_ip_address | mapped_object_name | interface} [service {tcp | udp} real_port mapped_port]
             * 
             * ... dynamic {mapped_host_ip_address | mapped_object_name | interface}
             * 
             * + mapped_object may be a host or network or range
            */

            switch (command.GetParam(2))
            {
                case "static":
                    IsStatic = true;

                    if (command.GetParam(3) == "interface")
                    {
                        IsHideBehindInterface = true;   // Static NAT with port-translation
                    }
                    else
                    {
                        // static hide behind an arbitrary ip/network
                        StaticNatIpAddressOrObjectName = command.GetParam(3);
                    }

                    int servicePos = command.GetParamPosition("service");
                    if (servicePos > 0)
                    {
                        ServiceProtocol = command.GetParam(servicePos + 1);
                        if (ServiceProtocol == "tcp" || ServiceProtocol == "udp")
                        {
                            ServiceId = CiscoKnownServices.ConvertServiceToPort(command.GetParam(servicePos + 2));
                            TranslatedServiceId = CiscoKnownServices.ConvertServiceToPort(command.GetParam(servicePos + 3));
                        }
                        else
                        {
                            ServiceProtocol = "";

                            ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                            ConversionIncidentMessage = "Unrecognized service protocol (" + ServiceProtocol + ")";
                            Console.WriteLine(ConversionIncidentMessage);
                        }
                    }
                    break;

                case "dynamic":
                    if (command.GetParam(3) == "interface")
                    {
                        IsHideBehindInterface = true;
                    }
                    else
                    {
                        // dynamic hide behind an arbitrary ip/network
                        DynamicNatIpAddressOrObjectName = command.GetParam(3);
                    }

                    // Check for interface fall-back configuration
                    if (command.GetParam(4) == "interface")
                    {
                        ConversionIncidentType = ConversionIncidentType.Informative;
                        ConversionIncidentMessage = "Interface fall-back for dynamic object NAT is not supported";
                        Console.WriteLine(ConversionIncidentMessage);
                    }
                    break;
            }
        }

        private void ParseRegularNatCommand(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds)
        {
            /********************************************************
             * Parsing options for regular (manual or twice) NAT:
             * --------------------------------------------------
             * ... [after-object] source static real_object_name [mapped_object_name | interface] [destination static mapped_object_name real_object_name] [service real_service_name mapped_service_name]
             * 
             * ... [after-auto] source dynamic {real_object_name | any} {mapped_object_name | interface} [destination static mapped_object_name real_object_name] [service mapped_service_name real_service_name]
             * 
             * + real_object/mapped_object may be a host or network
            */

            int sourcePos = 2;

            if (command.GetParam(2) == "after-auto" || command.GetParam(2) == "after-object")
            {
                IsAutoAfter = true;
                sourcePos = 3;
            }

            if (command.GetParam(sourcePos) == "source")
            {
                if (command.GetParam(sourcePos + 1) == "static")
                {
                    IsStatic = true;
                }

                SourceId = command.GetParam(sourcePos + 2);
                TranslatedSourceId = command.GetParam(sourcePos + 3);
                if (TranslatedSourceId == "interface")
                {
                    IsHideBehindInterface = true;
                }

                int destPos = command.GetParamPosition("destination");
                if (destPos > 0)   // twice-NAT
                {
                    // check sanity
                    if (command.GetParam(destPos + 1) != "static")
                    {
                        ConversionIncidentType = ConversionIncidentType.Informative;
                        ConversionIncidentMessage = "Not handling NAT with dynamic destination";
                        Console.WriteLine(ConversionIncidentMessage);
                        return;
                    }

                    DestinationId = command.GetParam(destPos + 2);
                    TranslatedDestinationId = command.GetParam(destPos + 3);
                }

                int servicePos = command.GetParamPosition("service");
                if (servicePos > 0)
                {
                    ServiceId = command.GetParam(servicePos + 1);
                    TranslatedServiceId = command.GetParam(servicePos + 2);
                }
            }
            else
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "Not handling NAT with dynamic source";
                Console.WriteLine(ConversionIncidentMessage);
            }
        }
    }

    public class Cisco_AccessGroup : CiscoCommand
    {
        public enum DirectionType { Inbound, Outbound, Global };

        public DirectionType Direction { get; set; }
        public string AccessListName { get; set; }
        public string InterfaceName { get; set; }

        public override string Name() { return "access-group"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            // Parsing Options:
            //-----------------
            // access-group access_list_name {{in | out} interface interface_name | global}
            //-----------------

            base.Parse(command, prevCommand, ciscoIds, aliases);

            AccessListName = command.GetParam(1);
            InterfaceName = (command.GetParam(3) == "interface") ? command.GetParam(4) : "";

            switch (command.GetParam(2))
            {
                case "in":
                    Direction = DirectionType.Inbound;
                    break;

                case "out":
                    Direction = DirectionType.Outbound;
                    break;

                case "global":
                    Direction = DirectionType.Global;
                    break;

                default:
                    Console.WriteLine("Error: unknown access-group traffic direction (" + command.GetParam(2) + ").");
                    break;
            }

            if (Direction != DirectionType.Inbound && Direction != DirectionType.Global)
            {
                ConversionIncidentType = ConversionIncidentType.Informative;
                ConversionIncidentMessage = "Outbound ACLs will not be converted";
                Console.WriteLine(ConversionIncidentMessage);
            }
        }
    }

    public class Cisco_AccessList : CiscoCommand
    {
        public enum ActionType { NA, Deny, Permit };

        public class SourceDest
        {
            public enum SourceDestType { NA, Any, Any6, ReferenceObject, Host, SubnetAndMask };

            public SourceDestType Type { get; set; }
            public string HostIp { get; set; }
            public string Subnet { get; set; }
            public string Netmask { get; set; }
            public string RefObjectName { get; set; }
            public int WordsCount { get; set; }

            public SourceDest()
            {
                Type = SourceDestType.NA;
                HostIp = "";
                Subnet = "";
                Netmask = "";
                RefObjectName = "";
                WordsCount = -1;
            }

            public SourceDest(List<string> words) : this()
            {
                if (!words.Any())
                {
                    WordsCount = 0;
                    return;
                }

                switch (words[0])
                {
                    case "any":
                    case "any4":
                        Type = SourceDestType.Any;
                        WordsCount = 1;
                        break;

                    case "any6":
                        Type = SourceDestType.Any6;
                        WordsCount = 1;
                        break;

                    case "host":
                        Type = SourceDestType.Host;
                        if (words.Count > 1)
                        {
                            HostIp = words[1];
                            WordsCount = 2;
                        }
                        break;

                    case "object-group":
                    case "object":
                        Type = SourceDestType.ReferenceObject;
                        if (words.Count > 1)
                        {
                            RefObjectName = words[1];
                            WordsCount = 2;
                        }
                        break;

                    case "interface":
                        Type = SourceDestType.ReferenceObject;
                        if (words.Count > 1)
                        {
                            RefObjectName = InterfacePrefix + words[1];
                            WordsCount = 2;
                        }
                        break;

                    default:
                        // both the ip_address and ip_mask are specified
                        Type = SourceDestType.SubnetAndMask;
                        if (words.Count > 1)
                        {
                            Subnet = words[0];
                            Netmask = words[1];
                            WordsCount = 2;
                        }
                        break;
                }
            }
        }

        public class ProtocolProperties
        {
            private Dictionary<string, CiscoCommand> _ciscoIds;

            public ProtocolType Protocol { get; set; }
            public TcpUdpPortOperatorType TcpUdpPortOperator { get; set; }
            public ServiceDirection Where { get; set; }
            public string TcpUdpPortValue { get; set; }
            public int WordsCount { get; set; }

            public ProtocolProperties()
            {
                Protocol = ProtocolType.NA;
                TcpUdpPortOperator = TcpUdpPortOperatorType.NA;
                Where = ServiceDirection.Destination;
                TcpUdpPortValue = "";
                WordsCount = -1;
            }

            public ProtocolProperties(ProtocolType protocol, List<string> words, Dictionary<string, CiscoCommand> ciscoIds, ServiceDirection where) : this()
            {
                _ciscoIds = ciscoIds;
                Protocol = protocol;
                Where = where;
                WordsCount = 0;

                if (protocol == ProtocolType.Ip ||
                    protocol == ProtocolType.Tcp ||
                    protocol == ProtocolType.Udp ||
                    protocol == ProtocolType.ReferenceObject)
                {
                    TcpUdpPortOperator = TcpUdpPortOperatorType.All;

                    if (words.Count > 0)
                    {
                        switch (words[0])
                        {
                            case "range":
                                TcpUdpPortOperator = TcpUdpPortOperatorType.Range;
                                if (words.Count > 2)
                                {
                                    TcpUdpPortValue = CiscoKnownServices.ConvertServiceToPort(words[1]) + "-" +
                                                      CiscoKnownServices.ConvertServiceToPort(words[2]);
                                    WordsCount = 3;
                                }
                                break;

                            case "lt":
                                TcpUdpPortOperator = TcpUdpPortOperatorType.Lt;
                                if (words.Count > 1)
                                {
                                    TcpUdpPortValue = CiscoKnownServices.ConvertServiceToPort(words[1]);
                                    WordsCount = 2;
                                }
                                break;

                            case "gt":
                                TcpUdpPortOperator = TcpUdpPortOperatorType.Gt;
                                if (words.Count > 1)
                                {
                                    TcpUdpPortValue = CiscoKnownServices.ConvertServiceToPort(words[1]);
                                    WordsCount = 2;
                                }
                                break;

                            case "eq":
                                TcpUdpPortOperator = TcpUdpPortOperatorType.Eq;
                                if (words.Count > 1)
                                {
                                    TcpUdpPortValue = CiscoKnownServices.ConvertServiceToPort(words[1]);
                                    WordsCount = 2;
                                }
                                break;

                            case "neq":
                                TcpUdpPortOperator = TcpUdpPortOperatorType.Neq;
                                if (words.Count > 1)
                                {
                                    TcpUdpPortValue = CiscoKnownServices.ConvertServiceToPort(words[1]);
                                    WordsCount = 2;
                                }
                                break;


                            case "object":
                                if (words.Count > 1 && IsServiceObject(words[1]))
                                {
                                    TcpUdpPortOperator = TcpUdpPortOperatorType.ReferenceObject;
                                    TcpUdpPortValue = words[1];
                                    WordsCount = 2;
                                }
                                break;

                            case "object-group":
                                if (words.Count > 1 && IsServiceGroup(words[1]))
                                {
                                    TcpUdpPortOperator = TcpUdpPortOperatorType.ReferenceObject;
                                    TcpUdpPortValue = words[1];
                                    WordsCount = 2;
                                }
                                break;
                        }
                    }
                }
                else if (protocol == ProtocolType.Icmp)
                {
                    if (words.Count > 0)
                    {
                        switch (words[0])
                        {
                            case "object-group":
                                if (words.Count > 1 && IsServiceGroup(words[1]))
                                {
                                    TcpUdpPortOperator = TcpUdpPortOperatorType.ReferenceObject;
                                    TcpUdpPortValue = words[1];
                                    WordsCount = 2;
                                }
                                break;

                            default:
                                if (CiscoKnownServices.IsKnownIcmpService(words[0]))
                                {
                                    TcpUdpPortOperator = TcpUdpPortOperatorType.Eq;
                                    TcpUdpPortValue = CiscoKnownServices.ConvertIcmpServiceToType(words[0]);
                                    WordsCount = 1;
                                }
                                break;
                        }
                    }
                }
                else if (protocol == ProtocolType.KnownOtherIpProtocol)
                {
                }
            }

            private bool IsServiceGroup(string name)
            {
                if (_ciscoIds.ContainsKey(name) && _ciscoIds[name].Name() == "object-group")
                {
                    var group = (Cisco_GroupObject)_ciscoIds[name];
                    if (group.GroupType == Cisco_GroupObject.Group_Type.Service || group.GroupType == Cisco_GroupObject.Group_Type.Icmp)
                    {
                        return true;
                    }
                }

                return false;
            }

            private bool IsServiceObject(string name)
            {
                if (_ciscoIds.ContainsKey(name) && _ciscoIds[name].Name() == "object")
                {
                    var obj = (Cisco_Object)_ciscoIds[name];
                    if (obj.ObjectType == Cisco_Object.ObjectTypes.TcpService ||
                        obj.ObjectType == Cisco_Object.ObjectTypes.UdpService ||
                        obj.ObjectType == Cisco_Object.ObjectTypes.IcmpService)
                    {
                        return true;
                    }
                }

                return false;
            }
        }

        public string ACLName { get; set; }
        public bool Inactive { get; set; }
        public ActionType Action { get; set; }
        public ProtocolType Protocol { get; set; }
        public string ProtocolReference { get; set; }
        public string Remark { get; set; }
        public bool IsRemark { get; set; }
        public bool IsTimeRangeSpecified { get; set; }
        public string TimeRangeName { get; set; }
        public SourceDest Source { get; set; }
        public SourceDest Destination { get; set; }
        public ProtocolProperties SourceProperties { get; set; }
        public ProtocolProperties DestinationProperties { get; set; }

        public override string Name() { return "access-list"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            /*
             * OPTION I - REMARK format - the easiest option:
             * 
            access-list access_list_name remark text
            Example:
            hostname(config)# access-list ACL_OUT remark - this is the inside admin address 
             * 
             * OPTION II - STANDARD format - used for a limited number of features, such as route maps or VPN filters.
             *                               uses IPv4 addresses only, and defines destination addresses only.
             * 
            access-list access_list_name standard {deny | permit} {any/any4 | host ip_address | ip_address ip_mask}
            Example:
            hostname(config)# access-list OSPF standard permit 192.168.1.0 255.255.255.0
             * 
             * OPTION III.I - EXTENDED format - for ICMP based traffic matching
             * 
            access-list access_list_name extended {deny | permit} icmp source_address_argument dest_address_argument [icmp_argument] [time-range time_range_name] [inactive]
            Example:
            hostname(config)# access-list ACL_IN extended permit icmp any any echo
             * 
             * OPTION III.II - EXTENDED format - for TCP and UDP based traffic matching, with ports
             * 
            access-list access_list_name extended {deny | permit} {tcp | udp} source_address_argument [port_argument] dest_address_argument [port_argument] [time-range time_range_name] [inactive]
            Example:
            hostname(config)# access-list ACL_IN extended deny tcp any host 209.165.201.29 eq www
            hostname(config)# access-list ACL_IN extended deny tcp 192.168.1.0 255.255.255.0 209.165.201.0 255.255.255.224
             * 
             * OPTION III.III - EXTENDED format - for general IP address and FQDN based matching
             * 
            access-list access_list_name extended {deny | permit} protocol_argument source_address_argument dest_address_argument [time-range time_range_name] [inactive]
            Example:
            hostname(config)# access-list ACL_IN extended permit ip any any
             * 
             * **********************
             * ACL COMMAND ARGUMENTS:
             * 
             * protocol_argument specification: one of the following options:
             * --------------------------------------------------------------
             * protocol_name/protocol_number
             * object service_object_id --> may be also a icmp service object
             * object-group service_group_id
             * object-group protocol_group_id
             * 
             * source_address_argument/dest_address_argument specification: one of the following options:
             * ------------------------------------------------------------------------------------------
             * any/any4/any6
             * host ip_address
             * interface interface_name
             * object network_object_id
             * object-group network_group_id
             * ip_address ip_mask
             * 
             * icmp_argument specification: one of the following options:
             * ----------------------------------------------------------
             * icmp_type
             * object-group icmp_group_id --> object-group icmp-type command
             * 
             * port_argument specification: one of the following options:
             * ----------------------------------------------------------
             * operator port --> where operator can be one of: lt, gt, eq, neq, range; port can be number or name of a TCP or UDP port
             * object-group service_group_id
             * 
            */

            base.Parse(command, prevCommand, ciscoIds, aliases);

            ACLName = command.GetParam(1);
            Inactive = false;
            Action = ActionType.NA;
            Protocol = ProtocolType.NA;
            ProtocolReference = "";
            Remark = "";
            IsRemark = false;
            IsTimeRangeSpecified = false;

            var prevAclCommand = prevCommand as Cisco_AccessList;

            if (command.GetParam(2) == "remark")
            {
                IsRemark = true;

                // Note that there may be several consecutive remark lines, so we need to aggregate to a single remark
                string dataForNextElement = "";
                if (prevAclCommand != null && prevAclCommand.IsRemark && !string.IsNullOrEmpty(prevAclCommand.DataForNextElement))
                {
                    dataForNextElement = prevAclCommand.DataForNextElement;
                }

                string text = command.Text.Trim();
                int offset = text.IndexOf("remark") + 7;

                if (!string.IsNullOrEmpty(dataForNextElement))
                {
                    dataForNextElement += ",  ";
                }

                dataForNextElement += text.Substring(offset).Trim();
                DataForNextElement = dataForNextElement;

                return;
            }

            if (prevAclCommand != null && ACLName.Equals(prevAclCommand.ACLName) && !string.IsNullOrEmpty(prevAclCommand.DataForNextElement))
            {
                Remark = prevAclCommand.DataForNextElement;

                if (CiscoParser.SpreadAclRemarks)
                {
                    DataForNextElement = Remark;
                }
            }

            int denyPosition = command.GetParamPosition("deny");
            int permitPosition = command.GetParamPosition("permit");
            int protocolPosition = Math.Max(denyPosition, permitPosition) + 1;   // protocol field should follow the action field (either deny or permit)
            int sourcePosition = protocolPosition + 1;

            if (denyPosition > 0)
            {
                Action = ActionType.Deny;
            }

            if (permitPosition > 0)
            {
                Action = ActionType.Permit;
            }

            if (command.GetParam(2) == "standard")
            {
                Protocol = ProtocolType.Ip;

                Source = new SourceDest
                {
                    Type = SourceDest.SourceDestType.Any
                };

                SourceProperties = new ProtocolProperties
                {
                    Protocol = Protocol,
                    TcpUdpPortOperator = TcpUdpPortOperatorType.All
                };

                Destination = new SourceDest(command.GetParams(4));

                DestinationProperties = new ProtocolProperties
                {
                    Protocol = Protocol,
                    TcpUdpPortOperator = TcpUdpPortOperatorType.All
                };

                return;
            }

            if (command.GetParamPosition("time-range") > 0)
            {
                IsTimeRangeSpecified = true;
                int indexTimeRange = command.GetParamPosition("time-range");
                TimeRangeName = command.GetParam(indexTimeRange + 1);
            }

            if (command.GetParamPosition("inactive") > 0)
            {
                Inactive = true;
            }

            string strProtocol = command.GetParam(protocolPosition);
            switch (strProtocol)
            {
                case "ip":
                    Protocol = ProtocolType.Ip;
                    break;

                case "icmp":
                case "icmp6":
                    Protocol = ProtocolType.Icmp;
                    break;

                case "udp":
                    Protocol = ProtocolType.Udp;
                    break;

                case "tcp":
                    Protocol = ProtocolType.Tcp;
                    break;

                case "object-group":
                case "object":
                    Protocol = ProtocolType.ReferenceObject;
                    ProtocolReference = command.GetParam(protocolPosition + 1);
                    sourcePosition++;
                    break;

                default:
                    string serviceName;
                    if (CiscoKnownServices.IsKnownService(strProtocol))
                    {
                        Protocol = ProtocolType.KnownOtherIpProtocol;
                    }
                    else if (CiscoKnownServices.IsKnownServiceNumber(strProtocol, out serviceName))   // protocol number is used!!!
                    {
                        Protocol = ProtocolType.KnownOtherIpProtocol;
                        strProtocol = serviceName;
                    }
                    else
                    {
                        ProtocolReference = strProtocol;
                        ConversionIncidentType = ConversionIncidentType.ManualActionRequired;
                        ConversionIncidentMessage = "Unrecognized service protocol (" + strProtocol + ")";
                        Console.WriteLine(ConversionIncidentMessage);
                    }
                    break;
            }

            Source = new SourceDest(command.GetParams(sourcePosition));
            SourceProperties = new ProtocolProperties(Protocol, command.GetParams(sourcePosition + Source.WordsCount), ciscoIds, ServiceDirection.Source);
            Destination = new SourceDest(command.GetParams(sourcePosition + Source.WordsCount + SourceProperties.WordsCount));
            DestinationProperties = new ProtocolProperties(Protocol, command.GetParams(sourcePosition + Source.WordsCount + SourceProperties.WordsCount + Destination.WordsCount), ciscoIds, ServiceDirection.Destination);

            if (Protocol == ProtocolType.KnownOtherIpProtocol)
            {
                // This information is needed in order to create/query appropriate service objects
                DestinationProperties.TcpUdpPortValue = strProtocol;
                DestinationProperties.WordsCount = 1;
            }
        }
    }

    public class Cisco_ClassMap : CiscoCommand
    {
        public string ClassMapName;
        public List<string> MatchedAclNames = new List<string>();

        public override string Name() { return "class-map"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            base.Parse(command, prevCommand, ciscoIds, aliases);

            ClassMapName = command.GetParam(1);

            if (command.Children == null)
            {
                return;
            }

            foreach (CiscoCommand child in command.Children)
            {
                if (child.Name() == "match" && !string.IsNullOrEmpty(((Cisco_Match_AccessList)child).AccessListName))
                {
                    MatchedAclNames.Add(((Cisco_Match_AccessList)child).AccessListName);
                }
            }
        }
    }

    public class Cisco_Match_AccessList : CiscoCommand
    {
        public string AccessListName { get; set; }

        public override string Name() { return "match"; }

        public override void Parse(CiscoCommand command, CiscoCommand prevCommand, Dictionary<string, CiscoCommand> ciscoIds, Dictionary<string, string> aliases)
        {
            // Parsing Options:
            //-----------------
            // match access-list access_list_name
            //-----------------

            base.Parse(command, prevCommand, ciscoIds, aliases);

            AccessListName = (command.GetParam(1) == "access-list") ? command.GetParam(2) : "";
        }
    }
}
