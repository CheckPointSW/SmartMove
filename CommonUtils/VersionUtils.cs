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

namespace CommonUtils
{
    /// <summary>
    /// Vendor configuration file version extraction helper utilities
    /// </summary>
    public static class VersionUtils
    {
        public static int MajorVersion(string version)
        {
            if (!string.IsNullOrEmpty(version))
            {
                int dotPos = version.IndexOf('.');
                if (dotPos > 0)
                {
                    string sMajor = version.Substring(0, dotPos);
                    int nMajor;
                    int.TryParse(sMajor, out nMajor);

                    return nMajor;
                }
            }

            return 0;
        }

        public static int MinorVersion(string version)
        {
            if (!string.IsNullOrEmpty(version))
            {
                int dotPos = version.IndexOf('.');
                if (dotPos > 0)
                {
                    string sMinor = version.Substring(dotPos + 1, 1);
                    int nMinor;
                    int.TryParse(sMinor, out nMinor);

                    return nMinor;
                }
            }

            return 0;
        }
    }
}
