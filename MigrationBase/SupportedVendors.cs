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
using System.ComponentModel;

namespace MigrationBase
{
    public class SupportedVendors
    {
        #region Constants

        public const string CiscoConfigurationFileLabel = "Cisco configuration file:";
        public const string CiscoProduct = "Cisco to Check Point Migration Tool";
        public const string CiscoProductDescription = "This tool supports migration of Cisco ASA 8.3\nand above configuration files.";
        public const string JuniperConfigurationFileLabel = "JunosOS XML configuration file:";
        public const string JuniperProduct = "Juniper JunosOS to Check Point Migration Tool";
        public const string JuniperProductDescription = "This tool supports migration of JunosOS SRX 12.1\nand above XML configuration files.";
        public const string NetScreenConfigurationFileLabel = "ScreenOS configuration file:";
        public const string NetScreenProduct = "Juniper ScreenOS to Check Point Migration Tool";
        public const string NetScreenProductDescription = "This tool supports migration of ScreenOS SSG 6.3 (R19B/R22)\nand above configuration files.";
        public const string FortiGateConfigurationFileLabel = "FortiGate configuration file:";
        public const string FortiGateProduct = "FortiGate to Check Point Migration Tool";
        public const string FortiGateProductDescription = "This tool supports migration of FortiGate 5.x \nand above configuration files.";
        public const string PaloAltoConfigurationFileLabel = "PaloAlto configuration file:";
        public const string PaloAltoProduct = "PaloAlto PAN-OS to Check Point Migration Tool";
        public const string PaloAltoProductDescription = "This tool supports migration of PaloAlto PAN-OS 7.x \nand above configuration files.";
        public const string PaloAltoPanoramaConfigurationFileLabel = "PaloAlto Panorama configuration files archive:";
        public const string PaloAltoPanoramaProduct = "PaloAlto Panorama to Check Point Migration Tool";
        public const string PaloAltoPanoramaProductDescription = "This tool supports migration of PaloAlto Panorama 7.x \nand above configuration files.";
        
        #endregion

        #region Private Members

        private readonly List<Vendor> _vendors = new List<Vendor> { Vendor.CiscoASA, Vendor.JuniperJunosOS, Vendor.JuniperScreenOS, Vendor.FortiGate, Vendor.PaloAlto };
        
        #endregion

        #region Properties

        public List<Vendor> Vendors
        {
            get { return _vendors; }
        }

        public Vendor SelectedVendor { get; set; }
        
        #endregion
    }

    [TypeConverter(typeof(VendorDescriptionConverter))]
    public enum Vendor
    {
        [Description("Cisco ASA")]
        CiscoASA,
        [Description("Juniper JunosOS SRX")]
        JuniperJunosOS,
        [Description("Juniper ScreenOS SSG/ISG/NS")]
        JuniperScreenOS,
        [Description("Fortinet FortiGate")]
        FortiGate,
        [Description("PaloAlto PAN-OS")]
        PaloAlto,
        [Description("PaloAlto Panorama")]
        PaloAltoPanorama
    }
}
