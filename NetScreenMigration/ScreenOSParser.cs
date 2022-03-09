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

using MigrationBase;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace NetScreenMigration
{
    /// <summary>
    /// Parses the ScreenOS SSG configuration file and creates corresponding ScreenOS objects repository.
    /// </summary>
    public class ScreenOSParser : VendorParser
    {
        #region Private Members

        private IList<ScreenOSCommand> _flatList = new List<ScreenOSCommand>();
        private IList<ScreenOSCommand> _screenOSCommands = new List<ScreenOSCommand>();
        private readonly Dictionary<string, List<string>> _addressNamesOverZonesLookup = new Dictionary<string, List<string>>(StringComparer.InvariantCultureIgnoreCase);
        private int _numOfVsysInConfiguration;

        #endregion

        #region Properties

        public IList<ScreenOSCommand> ScreenOSAllCommands
        {
            get { return _flatList; }
        }

        public IList<ScreenOSCommand> ScreenOSProcessedCommands
        {
            get { return _screenOSCommands; }
        }

        #endregion

        #region Public Methods

        public ScreenOSParser()
        {
            _numOfVsysInConfiguration = 0;
        }

        /// <summary>
        /// Parse ScreenOS configuration file
        /// </summary>
        /// <param name="filename">Source file name</param>
        public override void Parse(string filename)
        {
            ParseCommands(filename);
            IsMultipleVSYS();
            ParseInterfacesTopology();
        }

        /// <summary>
        /// Exporting parsed commands to JSON
        /// </summary>
        /// <param name="filename">Parsed file</param>
        public override void Export(string filename)
        {
            File.WriteAllText(filename, JsonConvert.SerializeObject(_screenOSCommands, Formatting.Indented));
        }

        /// <summary>
        /// Checks if ScreenOS object name contained in multiple zones
        /// </summary>
        /// <param name="name">ScreenOS object name</param>
        /// <returns>true,false</returns>
        public bool IsNetworkObjectContainedInMultipleZones(string name)
        {
            List<string> addressZones;
            return (_addressNamesOverZonesLookup.TryGetValue(name, out addressZones) && addressZones.Count > 1);
        }

        #endregion

        #region Protected Methods

        protected override void ParseVersion(object versionProvider)
        {
        }

        #endregion

        #region Private Methods

        private void ParseCommands(string filename)
        {
            string[] lines = File.ReadAllLines(filename, Encoding.GetEncoding("us-ascii", new EncoderReplacementFallback(""), new DecoderReplacementFallback("")));
            ParsedLines = lines.Count();

            int lineId = 0;
            foreach (string line in lines)
            {
                lineId++;

                // Check for an empty line or line with just spaces.
                if (line.Trim().Length == 0)
                {
                    continue;
                }

                ScreenOSCommand command = new ScreenOSCommand()
                {
                    Id = lineId,
                    Text = line
                };

                _flatList.Add(FindCommand(command));
                _flatList.Last().Parse(command);
            }

            _screenOSCommands = _flatList.AggregateCommands();

            HandleDuplicatedAddressName();
        }

        private void IsMultipleVSYS()
        {
            if (_numOfVsysInConfiguration > 1)
            {
                throw new Exception("Configuration contains multiple VSYS, Smart Move doesn't support multiple VSYS!!!");
            }
        }

        private ScreenOSCommand FindCommand(ScreenOSCommand command)
        {
            string[] irrelevantCommands =
            {
                "key", "clock", "vrouter", "auto-route-export", "protocol", "area", "alg", "auth-server", "auth","admin", "flow", "hostname", "pki", "nsrp",
                "dns", "user", "ike", "crypto-policy", "ipsec", "vpn", "url", "syslog", "nsmgmt", "ssh", "snmp" , "user-group" , "scheduler" , "console" ,
                "telnet" , "snmpv3" , "config"
            };

            string[] relevantCommands =
            {
                "dst-address", "src-address" , "vsys-id"
            };

            if (irrelevantCommands.Contains(command.ObjectWord))
            {
                command.NotAnInterestingCommand = true;
                return command;
            }

            if (relevantCommands.Contains(command.ObjectWord))
            {
                if(command.ObjectWord == "vsys-id")
                {
                    _numOfVsysInConfiguration++;
                }
                command.KnownCommand = true;
                return command;
            }

            IEnumerable<Type> ScreenOSCommandTypes = Assembly.GetExecutingAssembly().GetTypes().Where(commandType => commandType.GetInterfaces().Contains(typeof(IScreenOSCommand)));

            foreach (Type commandType in ScreenOSCommandTypes)
            {
                object knownCommand = Activator.CreateInstance(commandType);
                string knownCommandName = (string)knownCommand.GetType().GetMethod("Name").Invoke(knownCommand, null);

                if (knownCommandName == command.ObjectWord)
                {
                    ((ScreenOSCommand)knownCommand).Id = command.Id;
                    ((ScreenOSCommand)knownCommand).Text = command.Text;
                    return (ScreenOSCommand)knownCommand;
                }
            }

            return command;
        }

        private void ParseInterfacesTopology()
        {
            IEnumerable<ScreenOSCommand> interfaces = _screenOSCommands.OfType<ScreenOSCommand_Interface>();
            IEnumerable<ScreenOSCommand> routes = _screenOSCommands.OfType<ScreenOSCommand_Route>();

            foreach (ScreenOSCommand_Interface ifc in interfaces)
            {
                foreach (ScreenOSCommand_Route route in routes)
                {
                    if (route.NotAnInterestingCommand)
                    {
                        continue;
                    }

                    if ((!string.IsNullOrEmpty(ifc.InterfaceName) && route.Interface == ifc.InterfaceObjName) 
                        || ifc.CheckIfInterfaceIsGateway(route.Network))
                    {
                        ifc.Topology.Add(new ScreenOSCommand_Interface.Subnet(route.Network, route.Mask, route));

                        if (route.DefaultRoute)
                        {
                            ifc.LeadsToInternet = true;
                        }
                    }
                }
            }
        }

        private void HandleDuplicatedAddressName()
        {
            foreach (ScreenOSCommand command in _screenOSCommands)
            {
                string addressName = "";
                string zoneName = "";
                if (command.Name() == "address")
                {
                    addressName = ((ScreenOSCommand_Address)command).ObjectName;
                    zoneName = ((ScreenOSCommand_Address)command).Zone;
                }
                else if (command.Name() == "group address")
                {
                    addressName = ((ScreenOSCommand_GroupAddress)command).GroupName;
                    zoneName = ((ScreenOSCommand_GroupAddress)command).Zone;
                }
                else
                {
                    continue;
                }

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
        }

        #endregion
    }

    public static class AggregatedGroupEnumerable
    {
        public static IList<ScreenOSCommand> AggregateCommands(this IEnumerable<ScreenOSCommand> source)
        {
            IList<ScreenOSCommand> newCommandsList = new List<ScreenOSCommand>();
            foreach (ScreenOSCommand command in source)
            {
                if (command.GotTreated)
                {
                    continue;
                }

                IList<ScreenOSCommand> commandsGroup = null;
                switch (command.Name())
                {
                    case "interface":
                        if (((ScreenOSCommand_Interface)command).InterfaceObjectType != ScreenOSCommand_Interface.InterfaceObjectTypeEnum.Zone)
                        {
                            continue;
                        }
                        commandsGroup = source.OfType<ScreenOSCommand_Interface>().AggregateInterface((ScreenOSCommand_Interface)command);
                        break;

                    case "service":
                        if (((ScreenOSCommand_Service)command).OfPolicyContext == true)
                        {
                            continue;
                        }
                        commandsGroup = source.OfType<ScreenOSCommand_Service>().AggregateService((ScreenOSCommand_Service)command);
                        break;

                    case "group service":
                        if (!string.IsNullOrEmpty(((ScreenOSCommand_GroupService)command).ServiceObjectName))
                        {
                            continue;
                        }
                        commandsGroup = source.OfType<ScreenOSCommand_GroupService>().AggregateGroupService((ScreenOSCommand_GroupService)command);
                        break;

                    case "group address":
                        if (!string.IsNullOrEmpty(((ScreenOSCommand_GroupAddress)command).AddressObjectName))
                        {
                            continue;
                        }
                        commandsGroup = source.OfType<ScreenOSCommand_GroupAddress>().AggregateGroupAddress((ScreenOSCommand_GroupAddress)command);
                        break;

                    case "policy":
                        if (((ScreenOSCommand_Policy)command).PolicyId == 0)
                        {
                            command.GotTreated = true;
                            newCommandsList.Add(command);
                            continue;
                        }
                        commandsGroup = source.AggregatePolicy((ScreenOSCommand_Policy)command);
                        break;

                    case "dip group":
                        if (((ScreenOsCommand_GroupNatDIP)command).DipMember != 0)
                        {
                            continue;
                        }
                        commandsGroup = source.OfType<ScreenOsCommand_GroupNatDIP>().AggregateGroupDip((ScreenOsCommand_GroupNatDIP)command);
                        break;

                    default:
                        command.GotTreated = true;
                        newCommandsList.Add(command);
                        continue;
                }

                newCommandsList.Add(command);
                command.GotTreated = true;
                for (int i = 0; i< commandsGroup.Count;++i)
                {
                    if (commandsGroup[i].GotTreated == true)
                    {
                        continue;
                    }

                    if (newCommandsList.Last().AdditionalRealatedObjects == null)
                    {
                        newCommandsList.Last().AdditionalRealatedObjects = new List<ScreenOSCommand>();
                    }

                    newCommandsList.Last().AdditionalRealatedObjects.Add(commandsGroup[i]);
                    commandsGroup[i].GotTreated = true;
                }
            }

            return newCommandsList;
        }

        private static IList<ScreenOSCommand> AggregateInterface(this IEnumerable<ScreenOSCommand_Interface> source, ScreenOSCommand_Interface interfaceObj)
        {
            IEnumerable<IGrouping<string, ScreenOSCommand_Interface>> groups = source.GroupBy(i => i.InterfaceObjName);
            return groups.FirstOrDefault(g => g.Key.Equals(interfaceObj.InterfaceObjName)).ToList<ScreenOSCommand>();
        }

        private static IList<ScreenOSCommand> AggregateService(this IEnumerable<ScreenOSCommand_Service> source, ScreenOSCommand_Service serviceObj)
        {
            var groups = source.GroupBy(i => new { i.ServiceName, i.OfPolicyContext });
            return groups.FirstOrDefault(g => g.Key.ServiceName.Equals(serviceObj.ServiceName) && g.Key.OfPolicyContext.Equals(false)).ToList<ScreenOSCommand>();
        }

        private static IList<ScreenOSCommand> AggregateGroupService(this IEnumerable<ScreenOSCommand_GroupService> source, ScreenOSCommand_GroupService groupServiceObj)
        {
            IEnumerable<IGrouping<string, ScreenOSCommand_GroupService>> groups = source.GroupBy( i => i.GroupName );
            return groups.FirstOrDefault(g => g.Key.Equals(groupServiceObj.GroupName)).ToList<ScreenOSCommand>();
        }

        private static IList<ScreenOSCommand> AggregateGroupAddress(this IEnumerable<ScreenOSCommand_GroupAddress> source, ScreenOSCommand_GroupAddress groupAddressObj)
        {
            var groups = source.GroupBy(i => new { i.GroupName, i.Zone });
            return groups.FirstOrDefault(g => g.Key.GroupName.Equals(groupAddressObj.GroupName) && g.Key.Zone.Equals(groupAddressObj.Zone)).ToList<ScreenOSCommand>();
        }

        private static IList<ScreenOSCommand> AggregatePolicy(this IEnumerable<ScreenOSCommand> source, ScreenOSCommand_Policy PolicyObj)
        {
            List<ScreenOSCommand> commandsGroup = new List<ScreenOSCommand>();
            int index = ((List<ScreenOSCommand>)source).IndexOf((ScreenOSCommand)PolicyObj);
            while (index < source.Count() && ((List<ScreenOSCommand>)source)[index].ObjectWord != "exit")
            {
                commandsGroup.Add(((List<ScreenOSCommand>)source)[index]);
                index++;
            }

            /* Add exit command to policy*/
            if (((List<ScreenOSCommand>)source)[index].ObjectWord == "exit")
            {
                commandsGroup.Add(((List<ScreenOSCommand>)source)[index]);
            }

            return commandsGroup;
        }

        private static IList<ScreenOSCommand> AggregateGroupDip(this IEnumerable<ScreenOsCommand_GroupNatDIP> source, ScreenOsCommand_GroupNatDIP groupDipObj)
        {
            IEnumerable<IGrouping<int, ScreenOsCommand_GroupNatDIP>> groups = source.GroupBy(i => i.GroupDipId);
            return groups.FirstOrDefault(g => g.Key.Equals(groupDipObj.GroupDipId)).ToList<ScreenOSCommand>();
        }
    }
}
