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
using System.IO;

namespace NetScreenMigration
{
    /// <summary>
    /// Represents predefined services of ScreenOS SSG.
    /// Parses all predefined info from several files.
    /// </summary>
    class ScreenOSKnownServices
    {
        private static readonly Dictionary<string, string> _screenOSPredefinedServices = new Dictionary<string, string>();
        private static readonly Dictionary<string, List<string>> _screenOSPredefinedServicesGroup = new Dictionary<string, List<string>>();
        private static readonly Dictionary<string, List<string>> _screenOSPredefinedServicesByName = new Dictionary<string, List<string>>();
        private static readonly Dictionary<string, string> _screenOSPredefinedServicesGroupToCpGroup = new Dictionary<string, string>();

        public Dictionary<string, string> ScreenOSPredefinedServices { get { return _screenOSPredefinedServices; } }
        public Dictionary<string, List<string>> ScreenOSPredefinedServicesGroup { get { return _screenOSPredefinedServicesGroup; } }
        public Dictionary<string, List<string>> ScreenOSPredefinedServicesByName { get { return _screenOSPredefinedServicesByName; } }
        public Dictionary<string, string> ScreenOSPredefinedServicesGroupToCpGroup { get { return _screenOSPredefinedServicesGroupToCpGroup; } }

        static ScreenOSKnownServices()
        {
            /* ScreenOS Predefined services*/
            string[] lines = File.ReadAllLines("ScreenOSPredefinedServices.csv");
            foreach (string line in lines)
            {
                string[] words = line.Split(',');
                /* Check if valid line*/
                if (words.Length < 3)
                {
                    continue;
                }
                switch (words[1])
                {
                    case "TCP":
                    case "UDP":
                    case "OTHER":
                    case "SUN-RPC":
                    case "MS-RPC":
                        _screenOSPredefinedServices[words[1] + "_" + words[2]] = words[0];
                        if (!_screenOSPredefinedServicesByName.ContainsKey(words[0]))
                        {
                            _screenOSPredefinedServicesByName[words[0]] = new List<string>();
                        }
                        _screenOSPredefinedServicesByName[words[0]].Add(words[1] + "_" + words[2]);
                        break;

                    case "ICMP":
                        _screenOSPredefinedServices[words[1] + "_" + words[2] + "_" + words[3]] = words[0];
                        if (!_screenOSPredefinedServicesByName.ContainsKey(words[0]))
                        {
                            _screenOSPredefinedServicesByName[words[0]] = new List<string>();
                        }
                        _screenOSPredefinedServicesByName[words[0]].Add(words[1] + "_" + words[2] + "_" + words[3]);
                        break;

                    default:
                        break;
                }
            }

            /* ScreenOS Predefined service groups*/
            lines = File.ReadAllLines("ScreenOSPredefinedServiceGroups.csv");
            foreach (string line in lines)
            {
                string[] words = line.Split(',');

                if (words.Length < 1)
                {
                    continue;
                }

                _screenOSPredefinedServicesGroup[words[0]] = new List<string>();
                for (int i = 1; i < words.Length; ++i)
                {
                    _screenOSPredefinedServicesGroup[words[0]].Add(words[i]);
                }
            }

            /* ScreenOS Predefined service groups map to CP groups*/
            lines = File.ReadAllLines("ScreenOSPredefinedGroupServiceCpMap.csv");
            foreach (string line in lines)
            {
                string[] words = line.Split(',');

                if (words.Length < 1)
                {
                    continue;
                }

                _screenOSPredefinedServicesGroupToCpGroup[words[0]] = words[1];
            }
        }

        /* Predefined services*/
        public static List<string> ConvertPredefinedServiceNameToPort(string serviceNameOrNumber)
        {
            if (_screenOSPredefinedServicesByName.ContainsKey(serviceNameOrNumber))
            {
                return _screenOSPredefinedServicesByName[serviceNameOrNumber];
            }
            return new List<string>();
        }

        public static bool ConvertPredefinedServicePortToName(string predefinedServicePort, out string predefinedServiceName)
        {
            predefinedServiceName = "";
            if (_screenOSPredefinedServices.ContainsKey(predefinedServicePort))
            {
                predefinedServiceName = _screenOSPredefinedServices[predefinedServicePort];
                return true;
            }
            return false;
        }

        public static bool IsKnownPredefinedServicePort(string serviceTypeAndNumber)
        {
            return _screenOSPredefinedServices.ContainsKey(serviceTypeAndNumber);
        }

        public static bool IsKnownPredefinedServiceName(string serviceName)
        {
            return _screenOSPredefinedServices.ContainsValue(serviceName);
        }

        /* Predefined services*/
        public static List<string> ConvertPredefinedServiceGroupNameToList(string serviceGroupName)
        {
            if (_screenOSPredefinedServicesGroup.ContainsKey(serviceGroupName))
            {
                return _screenOSPredefinedServicesGroup[serviceGroupName];
            }

            return new List<string>();
        }

        public static bool ConvertPredefinedServiceToGroupName(string predefinedServiceName, out string predefinedServiceGroupName)
        {
            predefinedServiceGroupName = "";
            if (IsKnownPredefinedServiceNameInGroup(predefinedServiceName))
            {
                foreach (KeyValuePair<string, List<string>> pair in _screenOSPredefinedServicesGroup)
                {
                    if (pair.Value.Contains(predefinedServiceName))
                    {
                        predefinedServiceGroupName = pair.Key;
                        return true;
                    }
                }
            }
            return false;
        }

        public static bool IsKnownPredefinedServiceNameInGroup(string serviceName)
        {
            foreach (KeyValuePair<string, List<string>> pair in _screenOSPredefinedServicesGroup)
            {
                if (pair.Value.Contains (serviceName))
                {
                    return true;
                }
            }
            return false;
        }

        public static bool IsKnownPredefinedServiceGroupName(string serviceGroupName)
        {
            return _screenOSPredefinedServicesGroup.ContainsKey(serviceGroupName);
        }

        /* ScreenOS Predefined service groups map to CP groups*/
        public static bool IsKnownPredefinedServiceGroupInCp(string screenOsGroupName,out string cpGroupName)
        {
            cpGroupName = "";
            if (_screenOSPredefinedServicesGroupToCpGroup.ContainsKey(screenOsGroupName))
            {
                cpGroupName = _screenOSPredefinedServicesGroupToCpGroup[screenOsGroupName];
                return true;
            }
            return false;
        }
    }
}
