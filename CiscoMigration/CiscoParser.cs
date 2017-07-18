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

namespace CiscoMigration
{
    /// <summary>
    /// Parses the Cisco ASA configuration file and creates corresponding Cisco Command objects repository.
    /// </summary>
    public class CiscoParser
    {
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

        #region Private Members

        private int _lineCount = 0;
        private string _version = "";

        private IList<CiscoCommand> _ciscoCommands = new List<CiscoCommand>();
        private Dictionary<string, CiscoCommand> _ciscoIds = new Dictionary<string, CiscoCommand>();
        private Dictionary<string, string> _ciscoAliases = new Dictionary<string, string>();

        #endregion

        #region Properties

        public int LineCount
        {
            get { return _lineCount; }
        }

        public string Version
        {
            get { return _version; }
        }

        public int MajorVersion
        {
            get 
            {
                int dotPos = _version.IndexOf('.');
                if (dotPos > 0)
                {
                    string sMajorVersion = _version.Substring(0, dotPos);
                    int nMajorVersion = 0;
                    int.TryParse(sMajorVersion, out nMajorVersion);

                    return nMajorVersion;
                }

                return 0;
            }
        }

        public int MinorVersion
        {
            get
            {
                int dotPos = _version.IndexOf('.');
                if (dotPos > 0)
                {
                    string sMinorVersion = _version.Substring(dotPos + 1, 1);
                    int nMinorVersion = 0;
                    int.TryParse(sMinorVersion, out nMinorVersion);

                    return nMinorVersion;
                }

                return 0;
            }
        }

        #endregion

        #region Public Methods

        public void Parse(string filename)
        {
            string[] lines = File.ReadAllLines(filename);
            _lineCount = lines.Count();

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

                var command = new CiscoCommand
                {
                    Id = lineId,
                    Text = line
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
                flatList.Add(findCommand(command));
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

            // Add related routing information to interface topology
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
                            ciscoInterface.Topology.Add(new Cisco_Interface.Subnet(route.DestinationIp, route.DestinationNetmask));

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

            // Add version
            foreach (Cisco_ASA asa in Filter("ASA"))
            {
                _version = asa.Version;
            }
        }

        public void Export(string filename)
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

        private CiscoCommand findCommand(CiscoCommand command)
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
