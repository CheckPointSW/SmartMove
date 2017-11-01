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

namespace JuniperMigration
{
    /// <summary>
    /// Helper class for Cisco protocols and ports identification
    /// </summary>
    public class JuniperKnownApplications
    {
        private static readonly Dictionary<string, int> JuniperNameToNumber = new Dictionary<string, int>();
        private static readonly Dictionary<string, int> JuniperIcmpNameToType = new Dictionary<string, int>();
        private static readonly Dictionary<string, int> JuniperIcmpNameToCode = new Dictionary<string, int>();

        static JuniperKnownApplications()
        {
            string[] lines = File.ReadAllLines("JuniperNameToNumber.csv");
            foreach (string line in lines)
            {
                string[] words = line.Split(',');

                int number;
                if (int.TryParse(words[1], out number))
                {
                    JuniperNameToNumber.Add(words[0], number);
                }
            }

            lines = File.ReadAllLines("JuniperIcmpNameToType.csv");
            foreach (string line in lines)
            {
                string[] words = line.Split(',');

                int type;
                if (int.TryParse(words[1], out type))
                {
                    JuniperIcmpNameToType.Add(words[0], type);
                }
            }

            lines = File.ReadAllLines("JuniperIcmpNameToCode.csv");
            foreach (string line in lines)
            {
                string[] words = line.Split(',');

                int type;
                if (int.TryParse(words[1], out type))
                {
                    JuniperIcmpNameToCode.Add(words[0], type);
                }
            }
        }

        public static string ConvertProtocolOrPortNameToNumber(string juniperNameOrNumber)
        {
            return JuniperNameToNumber.ContainsKey(juniperNameOrNumber) ? JuniperNameToNumber[juniperNameOrNumber].ToString() : juniperNameOrNumber;
        }

        public static string ConvertProtocolOrPortNumberToName(string juniperNameOrNumber)
        {
            // Check if it is already a name
            if (JuniperNameToNumber.ContainsKey(juniperNameOrNumber))
            {
                return juniperNameOrNumber;
            }

            // Convert a number to name
            int juniperNumber;
            int.TryParse(juniperNameOrNumber, out juniperNumber);

            if (JuniperNameToNumber.ContainsValue(juniperNumber))
            {
                return JuniperNameToNumber.FirstOrDefault(kvp => kvp.Value == juniperNumber).Key;
            }

            return juniperNameOrNumber;
        }

        public static bool IsKnownProtocolOrPortName(string juniperNameOrNumber)
        {
            return JuniperNameToNumber.ContainsKey(juniperNameOrNumber);
        }

        public static bool IsKnownProtocolOrPortNumber(string juniperNumber, out string juniperName)
        {
            juniperName = "";

            int number;
            int.TryParse(juniperNumber, out number);

            if (JuniperNameToNumber.ContainsValue(number))
            {
                juniperName = JuniperNameToNumber.FirstOrDefault(kvp => kvp.Value == number).Key;
                return true;
            }

            return false;
        }

        public static string ConvertIcmpNameToType(string icmpNameOrType)
        {
            return JuniperIcmpNameToType.ContainsKey(icmpNameOrType) ? JuniperIcmpNameToType[icmpNameOrType].ToString() : icmpNameOrType;
        }

        public static bool IsKnownIcmpName(string icmpNameOrType)
        {
            return JuniperIcmpNameToType.ContainsKey(icmpNameOrType);
        }

        public static string ConvertIcmpNameToCode(string icmpNameOrCode)
        {
            return JuniperIcmpNameToCode.ContainsKey(icmpNameOrCode) ? JuniperIcmpNameToCode[icmpNameOrCode].ToString() : icmpNameOrCode;
        }

        public static bool IsKnownIcmpCode(string icmpNameOrCode)
        {
            return JuniperIcmpNameToCode.ContainsKey(icmpNameOrCode);
        }
    }
}
