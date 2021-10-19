using CheckPointObjects;
using MigrationBase;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FortiGateMigration
{
    public class FortiGateAnalizStatistic : VendorAnalizStatistic
    {
        public int UnusedNetworkRecalculated { get; set; }
        public int UnusedServicesRecalculated { get; set; }
        List<CheckPoint_Network> _cpNetworks;
        List<CheckPoint_NetworkGroup> _cpNetworkGroups;
        List<CheckPoint_Host> _cpHosts;
        List<CheckPoint_Range> _cpRanges;
        List<CheckPoint_TcpService> _cpTcpServices;
        List<CheckPoint_UdpService> _cpUdpServices;
        List<CheckPoint_SctpService> _cpSctpServices;
        List<CheckPoint_IcmpService> _cpIcmpServices;
        List<CheckPoint_DceRpcService> _cpDceRpcServices;
        List<CheckPoint_OtherService> _cpOtherServices;
        List<CheckPoint_ServiceGroup> _cpServiceGroups;
        List<CheckPoint_Package> _cpPackages;
        List<CheckPoint_NAT_Rule> _cpNatRules;

        public void CalculateCorrectAll(List<CheckPoint_Network> _cpNetworks,
                                               List<CheckPoint_NetworkGroup> _cpNetworkGroups,
                                               List<CheckPoint_Host> _cpHosts,
                                               List<CheckPoint_Range> _cpRanges,
                                               List<CheckPoint_TcpService> _cpTcpServices,
                                               List<CheckPoint_UdpService> _cpUdpServices,
                                               List<CheckPoint_SctpService> _cpSctpServices,
                                               List<CheckPoint_IcmpService> _cpIcmpServices,
                                               List<CheckPoint_DceRpcService> _cpDceRpcServices,
                                               List<CheckPoint_OtherService> _cpOtherServices,
                                               List<CheckPoint_ServiceGroup> _cpServiceGroups,
                                               List<CheckPoint_Package> _cpPackages,
                                               List<CheckPoint_NAT_Rule> _cpNatRules)
        {
            this._cpNetworks = _cpNetworks;
            this._cpNetworkGroups = _cpNetworkGroups;
            this._cpHosts = _cpHosts;
            this._cpRanges = _cpRanges;
            this._cpTcpServices = _cpTcpServices;
            this._cpUdpServices = _cpUdpServices;
            this._cpSctpServices = _cpSctpServices;
            this._cpIcmpServices = _cpIcmpServices;
            this._cpDceRpcServices = _cpDceRpcServices;
            this._cpOtherServices = _cpOtherServices;
            this._cpServiceGroups = _cpServiceGroups;
            this._cpPackages = _cpPackages;
            this._cpNatRules = _cpNatRules;

            //CalculateCorrectNetwork();
        }

        private void CalculateCorrectNetwork()
        {
            _totalNetworkObjectsCount = _cpNetworks.Count + _cpHosts.Count + _cpNetworkGroups.Count + _cpRanges.Count;
            //DUPLICATE CALCULATION
            foreach (var item in _cpNetworks)
            {
                if (_cpNetworks.Where(nt => nt.Name == item.Name & nt.Netmask == item.Netmask & nt.Subnet == nt.Subnet).Count() > 1) { _duplicateServicesObjectsCount++; }
            }
            foreach (var item in _cpHosts)
            {
                if (_cpHosts.Where(nt => nt.Name == item.Name & nt.IpAddress == item.IpAddress).Count() > 1) { _duplicateServicesObjectsCount++; }
            }
            foreach (var item in _cpRanges)
            {
                if (_cpRanges.Where(nt => nt.Name == item.Name & nt.RangeFrom == item.RangeFrom & nt.RangeTo == nt.RangeTo).Count() > 1) { _duplicateServicesObjectsCount++; }
            }
            //
            List<string> vs = new List<string>();
            foreach (var item in _cpNetworkGroups) { vs.AddRange(item.Members); }
            _nestedNetworkGroupsCount = vs.Distinct().Count();
            //
            var networks = _cpNetworks;
            foreach (var item in _cpNatRules)
            {
                vs.RemoveAll(vv => item.Service != null ? (vv == item.Service.Name) : false || item.Source != null ? (vv == item.Source.Name) : false || item.Destination != null ? (vv == item.Destination.Name) : false);
            }
            foreach(var package in _cpPackages)
            {
                foreach (var rule in package.ParentLayer.Rules)
                {
                    foreach(var dest in rule.Destination)
                    {
                        if (typeof(CheckPoint_Network) == dest.GetType())
                            networks.RemoveAll(nn => nn.Subnet == ((CheckPoint_Network)dest).Subnet);
                    }
                }
                foreach (var subPolicy in package.SubPolicies)
                {
                    foreach (var rule in subPolicy.Rules)
                    {
                        foreach (var dest in rule.Destination)
                        {
                            if (typeof(CheckPoint_Network) == dest.GetType())
                                networks.RemoveAll(nn => nn.Subnet == ((CheckPoint_Network)dest).Subnet);
                        }
                    }
                }
            }
            foreach (var rule in _cpNatRules)
            {
                if (typeof(CheckPoint_Network) == rule.Destination.GetType())
                    networks.RemoveAll(nn => nn.Subnet == ((CheckPoint_Network)rule.Destination).Subnet);
            }

        }

        public override void CalculateNetworks(List<CheckPoint_Network> _cpNetworks,
                                               List<CheckPoint_NetworkGroup> _cpNetworkGroups,
                                               List<CheckPoint_Host> _cpHosts,
                                               List<CheckPoint_Range> _cpRanges)
        {
            _totalNetworkObjectsCount = _cpNetworks.Count + _cpHosts.Count + _cpNetworkGroups.Count + _cpRanges.Count;
            List<string> vs = new List<string>();
            foreach (var item in _cpNetworkGroups) { vs.AddRange(item.Members); }
            _nestedNetworkGroupsCount = vs.Distinct().Count();

            foreach (var item in _cpNetworks)
            {
                if (_cpNetworks.Where(nt => nt.Name == item.Name & nt.Netmask == item.Netmask & nt.Subnet == nt.Subnet).Count() > 1) { _duplicateServicesObjectsCount++; }
            }
            foreach (var item in _cpHosts)
            {
                if (_cpHosts.Where(nt => nt.Name == item.Name & nt.IpAddress == item.IpAddress).Count() > 1) { _duplicateServicesObjectsCount++; }
            }
            foreach (var item in _cpRanges)
            {
                if (_cpRanges.Where(nt => nt.Name == item.Name & nt.RangeFrom == item.RangeFrom & nt.RangeTo == nt.RangeTo).Count() > 1) { _duplicateServicesObjectsCount++; }
            }
            foreach (var item in _cpNatRules)
            {
                vs.RemoveAll(vv => item.Service != null ? (vv == item.Service.Name) : false || item.Source != null ? (vv == item.Source.Name) : false || item.Destination != null ? (vv == item.Destination.Name) : false);
            }
            _unusedNetworkObjectsCount = vs.Count();
        }

        public override void CalculateRules(List<CheckPoint_Package> _cpPackages,
                                            List<CheckPoint_NAT_Rule> _cpNatRules)
        {
            _rulesServicesutilizingServicesAnyCount = 0;
            foreach (var rule in _cpNatRules)
            {
                bool first = true;
                if (!rule.Enabled) { _disabledServicesRulesCount++; }
                if (rule.Comments == "") { _uncommentedServicesRulesCount++; }
                if (rule.Name == "") { _unnamedServicesRulesCount++; }
                if (rule.Source != null && (rule.Source.Name == "any" | rule.Source.Name == "ANY")) { _rulesServicesutilizingServicesAnySourceCount++; if (first) { _rulesServicesutilizingServicesAnyCount++; first = false; } }
                if (rule.Destination != null && (rule.Destination.Name == "any" | rule.Destination.Name == "ANY")) { _rulesServicesutilizingServicesAnyDestinationCount++; if (first) { _rulesServicesutilizingServicesAnyCount++; first = false; } }
                if (rule.Service != null && (rule.Service.Name == "any" | rule.Service.Name == "ANY")) { _rulesServicesutilizingServicesAnyServiceCount++; if (first) { _rulesServicesutilizingServicesAnyCount++; first = false; } }
            }
            foreach (var package in _cpPackages)
            {
                _totalServicesRulesCount += package.ParentLayer.Rules.Count;
                foreach (var rule in package.ParentLayer.Rules)
                {
                    bool first = true;
                    if (!rule.Enabled) { _disabledServicesRulesCount++; }
                    if (rule.Comments == "") { _uncommentedServicesRulesCount++; }
                    if (rule.Name == "") { _unnamedServicesRulesCount++; }
                    if (rule.Track == CheckPoint_Rule.TrackTypes.None) { _nonServicesLoggingServicesRulesCount++; }
                    if (rule.Source.Where(sr => sr.Name == "any" | sr.Name == "ANY").Count() != 0) { _rulesServicesutilizingServicesAnySourceCount++; if (first) { _rulesServicesutilizingServicesAnyCount++; first = false; } }
                    if (rule.Destination.Where(dst => dst.Name == "any" | dst.Name == "ANY").Count() != 0) { _rulesServicesutilizingServicesAnyDestinationCount++; if (first) { _rulesServicesutilizingServicesAnyCount++; first = false; } }
                    if (rule.Service.Where(srv => srv.Name == "any" | srv.Name == "ANY").Count() != 0) { _rulesServicesutilizingServicesAnyServiceCount++; if (first) { _rulesServicesutilizingServicesAnyCount++; first = false; } }
                    if (rule.Time.Count() != 0) { _timesServicesRulesCount++; }
                    if (rule.IsCleanupRule()) { _cleanupServicesRuleCount++; }
                }
                foreach (var subPolicy in package.SubPolicies)
                {
                    _totalServicesRulesCount += subPolicy.Rules.Count;
                    foreach (var subRule in subPolicy.Rules)
                    {
                        bool first = true;
                        if (!subRule.Enabled) { _disabledServicesRulesCount++; }
                        if (subRule.Comments == "") { _uncommentedServicesRulesCount++; }
                        if (subRule.Name == "") { _unnamedServicesRulesCount++; }
                        if (subRule.Track == CheckPoint_Rule.TrackTypes.None) { _nonServicesLoggingServicesRulesCount++; }
                        if (subRule.Source.Where(sr => sr.Name == "any" | sr.Name == "ANY").Count() != 0) { _rulesServicesutilizingServicesAnySourceCount++; if (first) { _rulesServicesutilizingServicesAnyCount++; first = false; } }
                        if (subRule.Destination.Where(dst => dst.Name == "any" | dst.Name == "ANY").Count() != 0) { _rulesServicesutilizingServicesAnyDestinationCount++; if (first) { _rulesServicesutilizingServicesAnyCount++; first = false; } }
                        if (subRule.Service.Where(srv => srv.Name == "any" | srv.Name == "ANY").Count() != 0) { _rulesServicesutilizingServicesAnyServiceCount++; if (first) { _rulesServicesutilizingServicesAnyCount++; first = false; } }
                        if (subRule.Time.Count() != 0) { _timesServicesRulesCount++; }
                        if (subRule.IsCleanupRule()) { _cleanupServicesRuleCount++; }
                    }
                }
            }
            _optimizationServicesPotentialCount = _disabledServicesRulesCount +
                                                  _unnamedServicesRulesCount +
                                                  _timesServicesRulesCount +
                                                  _nonServicesLoggingServicesRulesCount;

        }

        public override void CalculateServices(List<CheckPoint_TcpService> _cpTcpServices,
                                               List<CheckPoint_UdpService> _cpUdpServices,
                                               List<CheckPoint_SctpService> _cpSctpServices,
                                               List<CheckPoint_IcmpService> _cpIcmpServices,
                                               List<CheckPoint_DceRpcService> _cpDceRpcServices,
                                               List<CheckPoint_OtherService> _cpOtherServices,
                                               List<CheckPoint_ServiceGroup> _cpServiceGroups)
        {
            _totalServicesObjectsCount = _cpTcpServices.Count + _cpUdpServices.Count + _cpSctpServices.Count + _cpDceRpcServices.Count + _cpOtherServices.Count;
            List<string> vs = new List<string>();
            foreach (var item in _cpServiceGroups) { vs.AddRange(item.Members); _totalServicesObjectsCount += item.Members.Count; }
            _nestedServicesGroupsCount = vs.Distinct().Count();

            List<string> allServiceNames = new List<string>();
            allServiceNames.AddRange(_cpTcpServices.Select(n => n.Name).ToList());
            allServiceNames.AddRange(_cpUdpServices.Select(n => n.Name).ToList());
            allServiceNames.AddRange(_cpSctpServices.Select(n => n.Name).ToList());
            allServiceNames.AddRange(_cpIcmpServices.Select(n => n.Name).ToList());
            allServiceNames.AddRange(_cpDceRpcServices.Select(n => n.Name).ToList());
            allServiceNames.AddRange(_cpOtherServices.Select(n => n.Name).ToList());
            _duplicateServicesObjectsCount = allServiceNames.Count - allServiceNames.Distinct().Count();

            foreach (var item in _cpNatRules)
            {
                vs.RemoveAll(vv => item.Service != null ? (vv == item.Service.Name) : false || item.Service != null ? (vv == item.Source.Name) : false || item.Service != null ? (vv == item.Destination.Name) : false);
            }
            foreach (var item in _cpPackages)
            {
                foreach (var rule in item.ParentLayer.Rules)
                {
                    vs.RemoveAll(vv => rule.Service != null ? (rule.Service.Where(sr => sr.Name == vv).Count() > 0) : false || rule.Source != null ? (rule.Source.Where(sr => sr.Name == vv).Count() > 0) : false || rule.Service != null ? (rule.Destination.Where(ds => ds.Name == vv).Count() > 0) : false);
                }
                foreach (var subPol in item.SubPolicies)
                {
                    foreach (var rule in subPol.Rules)
                    {
                        vs.RemoveAll(vv => rule.Service != null ? (rule.Service.Where(sr => sr.Name == vv).Count() > 0) : false || rule.Source != null ? (rule.Source.Where(sr => sr.Name == vv).Count() > 0) : false || rule.Service != null ? (rule.Destination.Where(ds => ds.Name == vv).Count() > 0) : false);
                    }
                }
            }
            _unusedServicesObjectsCount = vs.Count();
        }
    }
}
