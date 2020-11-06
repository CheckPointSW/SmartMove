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
using System.Net;
using System.Net.Sockets;

namespace CommonUtils
{
    /// <summary>
    /// Network stuff helper utilities
    /// </summary>
    public static class NetworkUtils
    {
        public static bool IsValidIpv4(string sIp)
        {
            return IsValidIp(sIp, new AddressFamily[] { AddressFamily.InterNetwork });
        }
        public static bool IsValidIpv6(string sIp)
        {
            return IsValidIp(sIp, new AddressFamily[] { AddressFamily.InterNetworkV6 });
        }

        public static bool IsValidIp(string sIp)
        {
            return IsValidIp(sIp, new AddressFamily[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 });
        }

        private static bool IsValidIp(String sIp, AddressFamily[] allowedAddressFamilies)
        {
            if (allowedAddressFamilies == null || allowedAddressFamilies.Length == 0)
            {
                return false;
            }

            if (IPAddress.TryParse(sIp, out IPAddress ip) && Array.Exists(allowedAddressFamilies, e => e == ip.AddressFamily))
            {
                return true;
            }
            return false;
        }

        public static bool IsValidNetmaskv4(string sNetmask)
        {
            return IsValidNetmask(sNetmask, new AddressFamily[] { AddressFamily.InterNetwork });
        }

        public static bool IsValidNetmaskv6(string sNetmask)
        {
            return IsValidNetmask(sNetmask, new AddressFamily[] { AddressFamily.InterNetworkV6 });
        }

        public static bool IsValidNetmask(string sNetmask)
        {
            return IsValidNetmask(sNetmask, new AddressFamily[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 });
        }

        private static bool IsValidNetmask(String sNetmask, AddressFamily[] allowedAddressFamilies)
        {
            if (allowedAddressFamilies == null || allowedAddressFamilies.Length == 0)
            {
                return false;
            }

            if (IPAddress.TryParse(sNetmask, out IPAddress netmask) && Array.Exists(allowedAddressFamilies, e => e == netmask.AddressFamily))
            {
                return IPNetwork.ValidNetmask(netmask);
            }
            return false;
        }
        public static bool TryParseNetwortWithPrefix(String sNetwork, out String sIp, out String sMaskLenght)
        {
            sIp = "";
            sMaskLenght = "";
            String[] splitedNetwork = sNetwork.Split('/');
            if (splitedNetwork.Length == 2 && IPAddress.TryParse(splitedNetwork[0], out IPAddress ipAddr) && int.TryParse(splitedNetwork[1], out int maskLengthNum))
            {
                sMaskLenght = Convert.ToString(maskLengthNum);
                sIp = Convert.ToString(ipAddr);
                return true;
            }
            return false;
        }

        public static int GetMaskLength(string sMask)
        {
            UInt32 mask = Ip2Number(sMask);
            if (mask == 0)
            {
                return 0;
            }

            int length = 0;
            int pos = 32;

            while (pos - 1 < 32 && length < 32 && IsBitSet(mask, pos - 1))
            {
                pos--;
                length++;
            }

            return length;
        }

        public static bool IsWildCardNetmask(string sMask)
        {
            IPAddress netmask;
            if (IPAddress.TryParse(sMask, out netmask) && (netmask.AddressFamily == AddressFamily.InterNetwork))
            {
                UInt32 maskInNumber = ~Ip2Number(sMask);
                string wildcardMask = Number2Ip(maskInNumber);
                IPAddress wildmask;
                IPAddress.TryParse(wildcardMask, out wildmask);
                return IPNetwork.ValidNetmask(wildmask);
            }

            return false;
        }

        public static string WildCardMask2Netmask(string sMask)
        {
            IPAddress netmask;
            if (IPAddress.TryParse(sMask, out netmask) && (netmask.AddressFamily == AddressFamily.InterNetwork))
            {
                UInt32 maskInNumber = ~Ip2Number(sMask);
                return Number2Ip(maskInNumber);
            }
            return sMask;
        }

        public static string GetNetwork(string sIp, string sMask)
        {
            UInt32 ip = Ip2Number(sIp);
            UInt32 mask = Ip2Number(sMask);
            UInt32 network = ip & mask;

            return Number2Ip(network);
        }

        public static string NetworkRange2Netmask(string sFrom, string sTo)
        {
            UInt32 from = Ip2Number(sFrom);
            UInt32 to = Ip2Number(sTo);

            if (from > to)
            {
                UInt32 tmp = from;
                from = to;
                to = tmp;
            }

            UInt32 diffs = from ^ to;
            int cidr = 32;

            // Count the number of consecutive zero bits starting at the most significant bit.
            // Keep shifting right until it's zero (all the non-zero bits are shifted off).
            while (diffs != 0)
            {
                diffs >>= 1;
                --cidr;   // every time we shift, that's one fewer consecutive zero bits in the prefix length
            }

            return MaskLength2Netmask(cidr);
        }

        public static UInt32 Ip2Number(IPAddress ip)
        {
            byte[] octets = ip.GetAddressBytes();
            UInt32 number = 0;

            for (int i = 0; i <= 3; i++)
            {
                number = number | ((UInt32)octets[i] << (3 - i) * 8);
            }

            return number;
        }

        public static UInt32 Ip2Number(string sIp)
        {
            IPAddress ip;
            if (!IPAddress.TryParse(sIp, out ip))
            {
                return 0;
            }

            return Ip2Number(ip);
        }

        public static string Number2Ip(UInt32 number)
        {
            string oct1 = ((number & 0xff000000) >> 24).ToString();
            string oct2 = ((number & 0x00ff0000) >> 16).ToString();
            string oct3 = ((number & 0x0000ff00) >> 08).ToString();
            string oct4 = ((number & 0x000000ff)).ToString();

            return oct1 + "." + oct2 + "." + oct3 + "." + oct4;
        }

        public static string MaskLength2Netmask(int maskLength)
        {
            UInt32 mask = 0;
            for (int i = 0; i < maskLength; i++)
            {
                mask += (UInt32)Math.Pow(2, 31 - i);
            }
            return Number2Ip(mask);
        }

        public static uint[] GetNetworkRangeInNumbers(string sIp, string sMask)
        {
            uint ip = Ip2Number(sIp);
            uint mask = Ip2Number(sMask);

            uint from = ip & mask;
            uint to = from | (0xffffffff & ~mask);

            return new uint[] { from, to };
        }

        public static uint[] GetNetworkRangeInNumbers(string sIp, int maskLength)
        {
            return GetNetworkRangeInNumbers(sIp, MaskLength2Netmask(maskLength));
        }

        private static bool IsBitSet(UInt32 b, int pos)
        {
            return ((b & (1 << pos)) != 0);
        }
    }
}
