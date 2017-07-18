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
        public static bool IsValidIp(string sIp)
        {
            IPAddress ip;
            if (IPAddress.TryParse(sIp, out ip) && (ip.AddressFamily == AddressFamily.InterNetwork))
            {
                return true;
            }

            return false;
        }

        public static int GetMaskLength(string sMask)
        {
            UInt32 mansk = Ip2Number(sMask);
            if (mansk == 0)
            {
                return 0;
            }

            int length = 0;
            int pos = 32;

            while (pos - 1 < 32 && length < 32 && IsBitSet(mansk, pos - 1))
            {
                pos--;
                length++;
            }

            return length;
        }

        public static string GetNetwork(string sIp, string sMask)
        {
            UInt32 ip = Ip2Number(sIp);
            UInt32 mask = Ip2Number(sMask);
            UInt32 network = ip & mask;

            return Number2Ip(network);
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
            string oct4 = ((number & 0x000000ff)      ).ToString();

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
