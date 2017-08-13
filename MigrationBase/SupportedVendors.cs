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

namespace MigrationBase
{
    public class SupportedVendors
    {
        #region Constants

        public const string CiscoConfigurationFileLabel = "Cisco configuration file:";
        public const string CiscoProduct = "Cisco to Check Point Migration Tool";
        public const string CiscoProductDescription = "This tool supports migration of Cisco ASA 8.3\nand above configuration files.";
        
        #endregion

        #region Private Members

        private readonly List<Vendor> _vendors = new List<Vendor> { Vendor.CiscoASA };
        
        #endregion

        #region Properties

        public List<Vendor> Vendors
        {
            get { return _vendors; }
        }

        public Vendor SelectedVendor { get; set; }
        
        #endregion
    }

    public enum Vendor
    {
        CiscoASA
    }
}
