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

using CommonUtils;

namespace MigrationBase
{
    /// <summary>
    /// Base class for vendor configuration file parsing.
    /// </summary>
    public abstract class VendorParser
    {
        #region Private Members

        protected string VendorVersion = "";
        
        #endregion

        #region Properties

        public int ParsedLines { get; set; }

        public string Version
        {
            get { return VendorVersion; }
        }

        public int MajorVersion
        {
            get { return VersionUtils.MajorVersion(Version); }
        }

        public int MinorVersion
        {
            get { return VersionUtils.MinorVersion(Version); }
        }

        #endregion

        #region Methods

        protected abstract void ParseVersion(object versionProvider);
        public abstract void Parse(string filename);
        public abstract void Export(string filename);

        #endregion
    }
}
