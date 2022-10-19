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
using System.Reflection;
using Newtonsoft.Json;
using CommonUtils;
using MigrationBase;
using System.Text;

namespace CiscoMigration
{
    /// <summary>
    /// Parses the Cisco ASA configuration file and creates corresponding Cisco Command objects repository.
    /// </summary>
    public class CiscoParser : VendorParser
    {
        //if we are using cisco code for fire power vendor we need set this flag to true value
        public bool isUsingForFirePower { get; set; } = false;

        #region Private Members
        
        #region Helper Classes

        private class Indentation
        {
            public int? Id { get; private set; }
            public int Spaces { get; private set; }

            public Indentation(int? id, int spaces)
            {
                Id = id;
                Spaces = spaces;
            }
        }

        #endregion



        private IList<CiscoCommand> _ciscoCommands = new List<CiscoCommand>();
        private Dictionary<string, CiscoCommand> _ciscoIds = new Dictionary<string, CiscoCommand>();
        private Dictionary<string, string> _ciscoAliases = new Dictionary<string, string>();

        public static bool SpreadAclRemarks = false;
        
        #endregion

        #region Public Methods

        public override void Parse(string filename)
        {
            ParseCommands(filename);   // this must come first!!!
            if (isUsingForFirePower)
                ParseVersion("NGFW");
            else
                ParseVersion(null);
            ParseInterfacesTopology();
        }

        public override void Export(string filename)
        {
            File.WriteAllText(filename, JsonConvert.SerializeObject(_ciscoCommands, Formatting.Indented));
        }

        public List<CiscoCommand> Filter(string commandName = "")
        {
            var filter = new List<CiscoCommand>();

            foreach (CiscoCommand command in _ciscoCommands)
            {
                if (commandName == "" || command.Name() == commandName)
                {
                    filter.Add(command);
                }
            }

            return filter;
        }

        public List<CiscoCommand> Flatten()
        {
            var flatten = new List<CiscoCommand>();

            foreach (CiscoCommand command in _ciscoCommands)
            {
                foreach (CiscoCommand flat in command.Flatten())
                {
                    flatten.Add(flat);
                }
            }

            return flatten;
        }

        public CiscoCommand GetCommandByCiscoId(string ciscoId)
        {
            return (from kvp in _ciscoIds where kvp.Key == ciscoId select kvp.Value).FirstOrDefault();
        }

        #endregion

        #region Private Methods

        protected override void ParseVersion(object versionProvider)
        {
            if (versionProvider != null)
            {
                //FirePower
                string allowedVersionType = (string)versionProvider;
                foreach (FirePower asa in Filter(allowedVersionType))
                {
                    VendorVersion = asa.Version;
                }
            }
            else
            {
                foreach (Cisco_ASA asa in Filter("ASA"))
                {
                    VendorVersion = asa.Version;
                }
            }
        }
        private void chengeLines(List<String> newLines, int index, string ip)
        {
            if ((newLines[index - 1][0] == ' ' && !newLines[index - 1].Contains("description")) || (newLines[index + 1][0] == ' ' && !newLines[index + 1].Contains("description")))
            {
                newLines[index] = " network-object host " + ip;
                int inserIndex = index;
                while (newLines[inserIndex][0] == ' ')
                {
                    inserIndex -= 1;
                }
                newLines.Insert(inserIndex, "object network " + ip);
                newLines.Insert(inserIndex+1, " host " + ip);
            }
        }

        private void ParseCommands(string filename)
        {
            string[] lines = File.ReadAllLines(filename, Encoding.GetEncoding("us-ascii", new EncoderReplacementFallback(""), new DecoderReplacementFallback("")));
            ParsedLines = lines.Count();

            var newLines = lines.ToList();

            for (var i = 0; i < newLines.Count; i++)
            {
                if (newLines[i].Contains("255.255.255.255") && newLines[i].Contains("network-object"))
                    chengeLines(newLines, i, newLines[i].Split(' ')[2]);
            }
            lines = newLines.ToArray();

            var parents = new Stack<Indentation>();
            var flatList = new List<CiscoCommand>();
            parents.Push(new Indentation(null, 0));

            int prevIndentationLevel = 0;
            int lineId = 0;
            
            foreach (string line in lines)
            {
                lineId++;
                
                

                // Check for an empty line or line with just spaces.
                if (line.Trim().Length == 0)
                {
                    continue;
                }

                // Check for weird stuff
                if (line.StartsWith("#") || line.StartsWith("<-"))
                {
                    continue;
                }

                var text = line;
                if ((!text.Contains("no nameif") && text.Contains("nameif")) || text.Contains("ip verify reverse-path interface") || text.Contains("mtu"))
                {
                    text = System.Text.RegularExpressions.Regex.Replace(text, @"[()#/@;:<>{}`+=~|!?,]", "");
                }
                var command = new CiscoCommand
                {
                    Id = lineId,
                    Text = text
                };

                int indentationChange = command.IndentationLevel - prevIndentationLevel;
                if (indentationChange > 0)
                {
                    parents.Push(new Indentation(flatList.Last().Id, flatList.Last().IndentationLevel));
                }
                else if (indentationChange < 0 && parents.Count > 0)
                {
                    parents.Pop();
                    while ((parents.Count > 0) && (parents.Peek().Spaces > command.IndentationLevel))
                    {
                        parents.Pop();
                    }
                }

                command.ParentId = (parents.Count > 0) ? parents.Peek().Id : null;

                prevIndentationLevel = command.IndentationLevel;
                flatList.Add(FindCommand(command));

            }

            _ciscoCommands = flatList.BuildTree();

            CiscoCommand prevCommand = null;
            foreach (CiscoCommand command in _ciscoCommands)
            {
                ParseWithChildren(command, prevCommand);
                prevCommand = command;
            }

            // Remove duplicates
            foreach (var ciscoId in _ciscoIds)
            {
                if (_ciscoAliases.ContainsKey(ciscoId.Key))
                {
                    _ciscoAliases.Remove(ciscoId.Key);
                }
            }
        }

        private void ParseInterfacesTopology()
        {
            // Add related static routing information to interface topology
            IEnumerable<CiscoCommand> ciscoInterfaceCommands = Filter("interface");
            IEnumerable<CiscoCommand> ciscoRouteCommands = Filter("route");

            foreach (Cisco_Interface ciscoInterface in ciscoInterfaceCommands)
            {
                if (!string.IsNullOrEmpty(ciscoInterface.CiscoId))
                {
                    foreach (Cisco_Route route in ciscoRouteCommands)
                    {
                        string routeInterfaceName = CiscoCommand.InterfacePrefix + route.InterfaceName;
                        if (routeInterfaceName == ciscoInterface.CiscoId)
                        {
                            ciscoInterface.Topology.Add(new Cisco_Interface.Subnet(route.DestinationIp, route.DestinationNetmask, route.Id));

                            if (route.DefaultRoute)
                            {
                                ciscoInterface.LeadsToInternet = true;
                            }

                            if (route.ConversionIncidentType != ConversionIncidentType.None)
                            {
                                ciscoInterface.ConversionIncidentType = route.ConversionIncidentType;
                                ciscoInterface.ConversionIncidentMessage = route.ConversionIncidentMessage;
                            }
                        }
                    }
                }
            }
        }

        private CiscoCommand FindCommand(CiscoCommand command)
        {
            string[] irrelevantCommands =
            {
                "!", ":", "speed", "dns-guard", "domain-name", "duplex", "passwd", "banner", "boot", "dns", "failover", "asdm", "arp", "clock", "mtu", "timeout"
            };

            if (irrelevantCommands.Contains(command.FirstWord))
            {
                command.NotAnInterestingCommand = true;
            }

            var ciscoCommandTypes = Assembly.GetExecutingAssembly().GetTypes().Where(commandType => commandType.GetInterfaces().Contains(typeof(ICiscoCommand)));

            foreach (Type commandType in ciscoCommandTypes)
            {
                object knownCommand = Activator.CreateInstance(commandType);
                string knownCommandName = (string)knownCommand.GetType().GetMethod("Name").Invoke(knownCommand, null);

                if (knownCommandName == command.FirstWord)
                {
                    ((CiscoCommand)knownCommand).CiscoId = command.CiscoId;
                    ((CiscoCommand)knownCommand).Id = command.Id;
                    ((CiscoCommand)knownCommand).Text = command.Text;
                    ((CiscoCommand)knownCommand).ParentId = command.ParentId;
                    ((CiscoCommand)knownCommand).KnownCommand = true;
                    ((CiscoCommand)knownCommand).NotAnInterestingCommand = false;

                    return (CiscoCommand)knownCommand;
                }
            }

            command.KnownCommand = false;
            return command;
        }

        private void ParseWithChildren(CiscoCommand command, CiscoCommand prevCommand)
        {
            if (command.Children == null || !command.Children.Any())
            {
                command.Parse(command, prevCommand, _ciscoIds, _ciscoAliases);

                if (!string.IsNullOrEmpty(command.CiscoId) && !_ciscoIds.ContainsKey(command.CiscoId))
                {
                    _ciscoIds.Add(command.CiscoId, command);
                }

                return;
            }

            CiscoCommand prevChild = null;
            foreach (CiscoCommand child in command.Children)
            {
                ParseWithChildren(child, prevChild);
                prevChild = child;
            }

            command.Parse(command, prevCommand, _ciscoIds, _ciscoAliases);

            if (!string.IsNullOrEmpty(command.CiscoId) && !_ciscoIds.ContainsKey(command.CiscoId))
            {
                _ciscoIds.Add(command.CiscoId, command);
            }
        }

        #endregion
    }

    public static class GroupEnumerable
    {
        public static IList<CiscoCommand> BuildTree(this IEnumerable<CiscoCommand> source)
        {
            var groups = source.GroupBy(i => i.ParentId);
            var roots = groups.FirstOrDefault(g => g.Key.HasValue == false).ToList();

            if (roots.Count > 0)
            {
                var children = groups.Where(g => g.Key.HasValue).ToDictionary(g => g.Key.Value, g => g.ToList());
                for (int i = 0; i < roots.Count; i++)
                {
                    AddChildren(roots[i], children);
                }
            }

            return roots;
        }

        private static void AddChildren(CiscoCommand node, IDictionary<int, List<CiscoCommand>> source)
        {
            if (source.ContainsKey(node.Id))
            {
                node.Children = source[node.Id];
                for (int i = 0; i < node.Children.Count; i++)
                {
                    AddChildren(node.Children[i], source);
                }
            }
            else
            {
                node.Children = new List<CiscoCommand>();
            }
        }
    }
}
