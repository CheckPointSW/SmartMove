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
using System.Linq;

namespace CiscoMigration
{
    /// <summary>
    /// Helper class for Cisco protocols and ports identification
    /// </summary>
    public class CiscoKnownServices
    {
        private static readonly Dictionary<string, int> CiscoNameToNumber = new Dictionary<string, int>();
        private static readonly Dictionary<string, int> CiscoIcmpNameToType = new Dictionary<string, int>();

        static CiscoKnownServices()
        {
            string[] lines = File.ReadAllLines("CiscoNameToNumber.csv");
            foreach (string line in lines)
            {
                string[] words = line.Split(',');

                int number;
                if (int.TryParse(words[1], out number))
                {
                    CiscoNameToNumber.Add(words[0], number);
                }
            }

            lines = File.ReadAllLines("CiscoIcmpNameToType.csv");
            foreach (string line in lines)
            {
                string[] words = line.Split(',');

                int type;
                if (int.TryParse(words[1], out type))
                {
                    CiscoIcmpNameToType.Add(words[0], type);
                }
            }
        }

        public static string ConvertServiceToPort(string ciscoNameOrNumber)
        {
            return CiscoNameToNumber.ContainsKey(ciscoNameOrNumber) ? CiscoNameToNumber[ciscoNameOrNumber].ToString() : ciscoNameOrNumber;
        }

        public static string ConvertIcmpServiceToType(string ciscoIcmpNameOrType)
        {
            return CiscoIcmpNameToType.ContainsKey(ciscoIcmpNameOrType) ? CiscoIcmpNameToType[ciscoIcmpNameOrType].ToString() : ciscoIcmpNameOrType;
        }

        public static bool IsKnownService(string ciscoNameOrNumber)
        {
            return CiscoNameToNumber.ContainsKey(ciscoNameOrNumber);
        }

        public static bool IsKnownIcmpService(string ciscoIcmpNameOrType)
        {
            return CiscoIcmpNameToType.ContainsKey(ciscoIcmpNameOrType);
        }

        public static bool IsKnownServiceNumber(string ciscoNumber, out string ciscoName)
        {
            ciscoName = "";

            int number;
            int.TryParse(ciscoNumber, out number);

            if (CiscoNameToNumber.ContainsValue(number))
            {
                ciscoName = CiscoNameToNumber.FirstOrDefault(kvp => kvp.Value == number).Key;
                return true;
            }

            return false;
        }
    }
}
