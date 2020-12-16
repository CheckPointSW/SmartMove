using System.Collections.Generic;
using System.Xml.Serialization;

namespace PanoramaPaloAltoMigration
{
    #region Abstract Interfaces

    public abstract class PA_Entry
    {
        [XmlAttribute("name")]
        public string Name { get; set; }
    }

    public abstract class PA_EntryExt : PA_Entry
    {
        private string _description;

        [XmlElement("description")]
        public string Description
        {
            get
            {
                if (_description == null)
                    return "";
                else
                    return _description;
            }
            set
            {
                _description = value;
            }
        }

        [XmlArray("tag")]
        [XmlArrayItem("member")]
        public List<string> TagMembers { get; set; }
    }

    #endregion

    #region Main XML tags binding

    [XmlRoot("config")]
    public class Panorama_Config
    {
        [XmlAttribute("version")]
        public string Version { get; set; }

        [XmlElement("shared")]
        public PA_Shared Shared { get; set; }

        [XmlElement("devices")]
        public PA_Devices Devices { get; set; }

    }

    public class PA_Shared : PA_Objects
    {
        [XmlElement("pre-rulebase")]
        public PA_PreRulebase PreRulebase { get; set; }
        [XmlElement("post-rulebase")]
        public PA_PostRulebase PostRulebase { get; set; }
    }

    #region devices XML tags binding
    public class PA_Devices
    {
        [XmlElement("entry")]
        public PA_DevicesEntry DevicesEntry { get; set; }
    }
    #endregion


    public class PA_DevicesEntry : PA_Entry
    {
        [XmlArray("device-group")]
        [XmlArrayItem("entry")]
        public List<PA_DeviceGroupEntry> DeviceGroupEntries { get; set; }

        [XmlArray("template")]
        [XmlArrayItem("entry")]
        public List<PA_TemplateEntry> TemplateEntries { get; set; }

        [XmlArray("template-stack")]
        [XmlArrayItem("entry")]
        public List<PA_TemplateStackEntry> TemplateStackEntries { get; set; }
    }

    public class PA_TemplateStackEntry : PA_Entry
    {
        [XmlArray("templates")]
        [XmlArrayItem("member")]
        public List<string> StackTemplatesMembers{ get; set; }
       

        [XmlArray("devices")]
        [XmlArrayItem("entry")]
        public List<PA_DevicesTemplateStackEntry> DevicesEntries { get; set; }
    }
/*
    public class PA_StackTemplates: PA_Entry
    {        
        [XmlElement("member")]
        public List<string> StackTemplateMembers { get; set; }
    }
*/
    public class PA_DevicesTemplateStackMemberEntry: PA_Entry
    {

    }
     public class PA_DevicesTemplateStackEntry : PA_Entry
    {

    }


    public class PA_TemplateEntry : PA_Entry
    {
        [XmlElement("config")]
        public PA_TemplateConfig Config { get; set; }
        
    }

    public class PA_TemplateConfig : PA_Entry
    {
        [XmlElement("devices")]        
        public PA_DevicesTemplateEntry TemplateDevices { get; set; }

    }       

    public class PA_DevicesTemplateEntry : PA_Entry
    {
        [XmlElement("entry")]
        public PA_DevicesTemplateDevicesEntry TemplateDevicesEntry { get; set; }
    }

    public class PA_DevicesTemplateDevicesEntry : PA_Entry
    {
        [XmlElement("network")]
        public PA_Network Network { get; set; }

        [XmlArray("vsys")]
        [XmlArrayItem("entry")]
        public List<PA_VsysEntry> VsysEntries { get; set; }
    }  

    public class PA_DeviceGroupEntry : PA_Objects
    {
        [XmlElement("pre-rulebase")]
        public PA_PreRulebase PreRulebase { get; set; }
        [XmlElement("post-rulebase")]
        public PA_PostRulebase PostRulebase { get; set; }

        [XmlArray("devices")]
        [XmlArrayItem("entry")]
        public List<PA_DevicesGroupDevicesEntry> DevicesGroupDevicesEntries { get; set; }
    }

    public class PA_PostRulebase
    {
        [XmlElement("default-security-rules")]
        public PA_Security Security { get; set; }
    }

    public class PA_DevicesGroupDevicesEntry : PA_Entry // devices serial numbers
    {       

    }

    public class PA_PreRulebase
    {
        [XmlElement("security")]
        public PA_Security Security { get; set; }

        [XmlElement("nat")]
        public PA_Nat Nat { get; set; }
    }
    #endregion

    #region Network XML tags binding

    public class PA_Network
    {
        [XmlElement("interface")]
        public PA_Interface Interface { get; set; }
    }

    public class PA_Interface
    {
        [XmlArray("ethernet")]
        [XmlArrayItem("entry")]
        public List<PA_EthernetEntry> EthernetEntries { get; set; }
    }

    public class PA_EthernetEntry : PA_Entry
    {
        [XmlElement("layer3")]
        public PA_EthernetLayer3 Layer3 { get; set; }
    }

    public class PA_EthernetLayer3
    {

    }

    #endregion

    #region XML tags binding of Content

    public class PA_Objects : PA_Entry
    {
        [XmlArray("tag")]
        [XmlArrayItem("entry")]
        public List<PA_TagEntry> TagsEntries { get; set; }

        [XmlArray("address")]
        [XmlArrayItem("entry")]
        public List<PA_AddressEntry> AddressEntries { get; set; }

        [XmlArray("address-group")]
        [XmlArrayItem("entry")]
        public List<PA_AddressGroupEntry> AddressGroupEntries { get; set; }

        [XmlArray("service")]
        [XmlArrayItem("entry")]
        public List<PA_ServiceEntry> ServiceEntries { get; set; }

        [XmlArray("service-group")]
        [XmlArrayItem("entry")]
        public List<PA_ServiceGroupEntry> ServiceGroupEntries { get; set; }

        [XmlArray("application-group")]
        [XmlArrayItem("entry")]
        public List<PA_ApplicationGroupEntry> ApplicationGroupsEntries { get; set; }

        [XmlArray("application-filter")]
        [XmlArrayItem("entry")]
        public List<PA_ApplicationFilterEntry> ApplicationFiltersEntries { get; set; }

        [XmlArray("schedule")]
        [XmlArrayItem("entry")]
        public List<PA_ScheduleEntry> ScheduleEntries { get; set; }
    }

    public class PA_Vsys
    {
        [XmlElement("entry")]
        public List<PA_VsysEntry> VsysEntries { get; set; }
    }

    public class PA_VsysEntry : PA_Objects
    {
        [XmlArray("zone")]
        [XmlArrayItem("entry")]
        public List<PA_ZoneEntry> ZoneEntries { get; set; }
/*
        [XmlElement("rulebase")]
        public PA_Rulebase Rulebase { get; set; }*/
    }

    public class PA_TagEntry : PA_Entry { /* the class is empty as we need to know only 'name' attribute of Tag entry */ }

    public class PA_Rulebase
    {
        [XmlElement("security")]
        public PA_Security Security { get; set; }

        [XmlElement("nat")]
        public PA_Nat Nat { get; set; }
    }

    #endregion

    #region Zone XML tags binding

    public class PA_ZoneEntry : PA_EntryExt { /* the class is empty as we need to know Zone's name only */ }

    #endregion

    #region Addresses & Address Groups XML tags binding

    public class PA_AddressEntry : PA_EntryExt
    {
        //control elements which tells which object we have

        [XmlElement("ip-netmask")]
        public string IpNetmask { get; set; }

        [XmlElement("ip-range")]
        public string IpRange { get; set; }

        [XmlElement("fqdn")]
        public string Fqdn { get; set; }
    }

    public class PA_AddressGroupEntry : PA_EntryExt
    {
        [XmlArray("static")]
        [XmlArrayItem("member")]
        public List<string> StaticMembers { get; set; }

        [XmlElement("dynamic")]
        public PA_AddressGroupEntryDynamic Dynamic { get; set; }
    }

    public class PA_AddressGroupEntryDynamic
    {
        [XmlElement("filter")]
        public string Filter { get; set; }
    }

    #endregion

    #region Services & Service Groups XML tags binding

    public class PA_ServiceEntry : PA_EntryExt
    {
        [XmlElement("protocol")]
        public PA_ServiceProtocol Protocol { get; set; }
    }

    public class PA_ServiceProtocol
    {
        [XmlElement("tcp")]
        public PA_ServiceTcpUdp ServiceTcp { get; set; }

        [XmlElement("udp")]
        public PA_ServiceTcpUdp ServiceUdp { get; set; }
    }

    public class PA_ServiceTcpUdp
    {
        [XmlElement("port")]
        public string Port { get; set; }

        [XmlElement("source-port")]
        public string SourcePort { get; set; }
    }

    // Definition for the groups of services

    public class PA_ServiceGroupEntry : PA_EntryExt
    {
        [XmlArray("members")]
        [XmlArrayItem("member")]
        public List<string> Members { get; set; }
    }

    #endregion

    #region Application Group and Application Filter XML tags binding

    public class PA_ApplicationGroupEntry : PA_Entry
    {
        [XmlArray("members")]
        [XmlArrayItem("member")]
        public List<string> ApplicationGroupMembers { get; set; }
    }

    public class PA_ApplicationFilterEntry : PA_Entry
    {
        [XmlArray("category")]
        [XmlArrayItem("member")]
        public List<string> CategoryMembers { get; set; }

        [XmlArray("subcategory")]
        [XmlArrayItem("member")]
        public List<string> SubcategoryMembers { get; set; }
    }

    #endregion

    #region Schedules XML tags binding

    public class PA_ScheduleEntry : PA_EntryExt
    {
        [XmlElement("schedule-type")]
        public PA_ScheduleType Type { get; set; }
    }

    public class PA_ScheduleType
    {
        [XmlElement("recurring")]
        public PA_ScheduleRecurring Recurring { get; set; }

        [XmlElement("non-recurring")]
        public PA_ScheduleNonRecurring NonRecurring { get; set; }
    }

    public class PA_ScheduleRecurring
    {
        [XmlArray("daily")]
        [XmlArrayItem("member")]
        public List<string> MembersDaily { get; set; }

        [XmlElement("weekly")]
        public PA_ScheduleRecurringWeekly Weekly { get; set; }
    }

    public class PA_ScheduleRecurringWeekly
    {
        [XmlArray("monday")]
        [XmlArrayItem("member")]
        public List<string> MembersMonday { get; set; }

        [XmlArray("tuesday")]
        [XmlArrayItem("member")]
        public List<string> MembersTuesday { get; set; }

        [XmlArray("wednesday")]
        [XmlArrayItem("member")]
        public List<string> MembersWednesday { get; set; }

        [XmlArray("thursday")]
        [XmlArrayItem("member")]
        public List<string> MembersThursday { get; set; }

        [XmlArray("friday")]
        [XmlArrayItem("member")]
        public List<string> MembersFriday { get; set; }

        [XmlArray("saturday")]
        [XmlArrayItem("member")]
        public List<string> MembersSaturday { get; set; }

        [XmlArray("sunday")]
        [XmlArrayItem("member")]
        public List<string> MembersSunday { get; set; }
    }

    public class PA_ScheduleNonRecurring
    {
        [XmlElement("member")]
        public List<string> Memebers { get; set; }
    }

    #endregion

    #region Security XML tags binding (policy rules)

    public class PA_Security
    {
        [XmlArray("rules")]
        [XmlArrayItem("entry")]
        public List<PA_SecurityRuleEntry> RulesList { get; set; }
    }

    public class PA_SecurityRuleEntry : PA_EntryExt
    {
        [XmlArray("from")] //Source Zone List
        [XmlArrayItem("member")]
        public List<string> FromList { get; set; }

        [XmlArray("to")] //Destination Zone List
        [XmlArrayItem("member")]
        public List<string> ToList { get; set; }

        [XmlArray("source")]
        [XmlArrayItem("member")]
        public List<string> SourceList { get; set; }

        [XmlArray("destination")]
        [XmlArrayItem("member")]
        public List<string> DestinationList { get; set; }

        [XmlArray("source-user")]
        [XmlArrayItem("member")]
        public List<string> SourceUserList { get; set; }

        [XmlArray("application")]
        [XmlArrayItem("member")]
        public List<string> ApplicationList { get; set; }

        [XmlArray("service")]
        [XmlArrayItem("member")]
        public List<string> ServiceList { get; set; }

        [XmlElement("action")]
        public string Action { get; set; }

        [XmlElement("schedule")]
        public string Schedule { get; set; }

        [XmlElement("rule-type")]
        public string RuleType { get; set; }

        [XmlElement("log-start")]
        public string LogStart { get; set; }

        [XmlElement("log-end")]
        public string LogEnd { get; set; }

        [XmlElement("disabled")]
        public string Disabled { get; set; }

        [XmlArray("category")]
        [XmlArrayItem("member")]
        public List<string> CategoryList { get; set; }

        [XmlElement("negate-source")]
        public string NegateSource { get; set; }

        [XmlElement("negate-destination")]
        public string NegateDestination { get; set; }

        [XmlElement("target")]
        public PA_Target Target { get; set; }
    }


    public class PA_Target : PA_Entry
    {
        [XmlElement("negate")]
        public string Negate { get; set; }

        [XmlArray("devices")]
        [XmlArrayItem("entry")]
        public List<PA_TargetDeviceEntry> DevicesEntry { get; set; }
    }

    public class PA_TargetDeviceEntry : PA_Entry{}

#endregion

    #region NAT XML tags binding (NAT rules)

    public class PA_Nat
        {
            [XmlArray("rules")]
            [XmlArrayItem("entry")]
            public List<PA_NatRuleEntry> RulesList { get; set; }
        }

    public class PA_NatRuleEntry : PA_EntryExt
    {
        [XmlArray("source")]
        [XmlArrayItem("member")]
        public List<string> SourceList { get; set; }

        [XmlArray("destination")]
        [XmlArrayItem("member")]
        public List<string> DestinationList { get; set; }

        [XmlElement("service")]
        public string Service { get; set; }

        [XmlElement("source-translation")]
        public PA_SourceTranslation SourceTranslation { get; set; }

        [XmlElement("destination-translation")]
        public PA_DestinationTranslation DestinationTranslation { get; set; }

        [XmlElement("dynamic-destination-translation")]
        public PA_DynamicDestinationTranslation DynamicDestinationTranslation { get;set;}

        [XmlElement("disabled")]
        public string Disabled { get; set; }

        [XmlElement("target")]
        public PA_Target Target { get; set; }
    }

    public class PA_SourceTranslation
    {
        [XmlElement("static-ip")]
        public PA_StaticIp StaticIp { get; set; }

        [XmlElement("dynamic-ip")]
        public PA_DynamicIp DynamicIp { get; set; }

        [XmlElement("dynamic-ip-and-port")]
        public PA_DynamicIpAndPort DynamicIpAndPort { get; set; }
    }

    public class PA_StaticIp
    {
        [XmlElement("translated-address")]
        public string TranslatedAddress { get; set; }

        [XmlElement("bi-directional")]
        public string IsBiDirectional { get; set; }
    }

    public class PA_DynamicIp
    {
        [XmlArray("translated-address")]
        [XmlArrayItem("member")]
        public List<string> TranslatedAddresses { get; set; }
    }

    public class PA_DynamicIpAndPort
    {
        [XmlArray("translated-address")]
        [XmlArrayItem("member")]
        public List<string> TranslatedAddresses { get; set; }

        [XmlElement("interface-address")]
        public PA_InterfaceAddress InterfaceAddress { get; set; }
    }

    public class PA_InterfaceAddress
    {
        [XmlElement("ip")]
        public string Ip { get; set; }
    }

    public class PA_DestinationTranslation
    {
        [XmlElement("translated-address")]
        public string TranslatedAddress { get; set; }

        [XmlElement("translated-port")]
        public string TranslatedPort { get; set; }
    }

    public class PA_DynamicDestinationTranslation
    {
        [XmlElement("translated-address")]
        public string TranslatedAddress { get; set; }

        [XmlElement("translated-port")]
        public string TranslatedPort { get; set; }
    }

    #endregion
}
