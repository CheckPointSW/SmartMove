using CheckPointObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MigrationBase
{
    public abstract class VendorAnalizStatistic
    {
        public int _totalNetworkObjectsCount = 0;
        public int _unusedNetworkObjectsCount = 0;
        public int _duplicateNetworkObjectsCount = 0;
        public int _nestedNetworkGroupsCount = 0;

        public int _totalServicesObjectsCount = 0;
        public int _unusedServicesObjectsCount = 0;
        public int _duplicateServicesObjectsCount = 0;
        public int _nestedServicesGroupsCount = 0;

        public int _totalServicesRulesCount = 0;
        public int _rulesServicesutilizingServicesAnyCount = 0;
        public int _rulesServicesutilizingServicesAnySourceCount = 0;
        public int _rulesServicesutilizingServicesAnyDestinationCount = 0;
        public int _rulesServicesutilizingServicesAnyServiceCount = 0;
        public int _disabledServicesRulesCount = 0;
        public int _unnamedServicesRulesCount = 0;
        public int _timesServicesRulesCount = 0;
        public int _nonServicesLoggingServicesRulesCount = 0;
        public int _stealthServicesRuleCount = 0;
        public int _cleanupServicesRuleCount = 0;
        public int _uncommentedServicesRulesCount = 0;
        public int _optimizationServicesPotentialCount = 0;

        public int TotalNetworkObjectsPercent { get { return 100; } }
        public float UnusedNetworkObjectsPercent { get { return _totalNetworkObjectsCount > 0 ? ((float)_unusedNetworkObjectsCount / (float)_totalNetworkObjectsCount) * 100 : 0; } }
        public float DuplicateNetworkObjectsPercent { get { return _totalNetworkObjectsCount > 0 ? ((float)_duplicateNetworkObjectsCount / (float)_totalNetworkObjectsCount) * 100 : 0; } }
        public float NestedNetworkGroupsPercent { get { return _totalNetworkObjectsCount > 0 ? ((float)_nestedNetworkGroupsCount / (float)_totalNetworkObjectsCount) * 100 : 0; } }

        public float TotalServicesObjectsPercent { get { return 100; } }
        public float UnusedServicesObjectsPercent { get { return _totalServicesObjectsCount > 0 ? ((float)_unusedServicesObjectsCount / (float)_totalServicesObjectsCount) * 100 : 0; } }
        public float DuplicateServicesObjectsPercent { get { return _totalServicesObjectsCount > 0 ? ((float)_duplicateServicesObjectsCount / (float)_totalServicesObjectsCount) * 100 : 0; } }
        public float NestedServicesGroupsPercent { get { return _totalServicesObjectsCount > 0 ? ((float)_nestedServicesGroupsCount / (float)_totalServicesObjectsCount) * 100 : 0; } }

        public float TotalServicesRulesPercent { get { return 100; } }
        public float RulesServicesutilizingServicesAnyPercent { get { return _totalServicesRulesCount > 0 ? ((float)_rulesServicesutilizingServicesAnyCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float DisabledServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_disabledServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float UnnamedServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_unnamedServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float TimesServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_timesServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float NonServicesLoggingServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_nonServicesLoggingServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float StealthServicesRulePercent { get { return _totalServicesRulesCount > 0 ? ((float)_stealthServicesRuleCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float CleanupServicesRulePercent { get { return _totalServicesRulesCount > 0 ? ((float)_cleanupServicesRuleCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float UncommentedServicesRulesPercent { get { return _totalServicesRulesCount > 0 ? ((float)_uncommentedServicesRulesCount / (float)_totalServicesRulesCount) * 100 : 0; } }
        public float OptimizationServicesPotentialPercent { get { return _totalServicesRulesCount > 0 ? ((float)_optimizationServicesPotentialCount / (float)_totalServicesRulesCount) * 100 : 0; } }

        public abstract void CalculateNetworks(List<CheckPoint_Network> _cpNetworks,
                                               List<CheckPoint_NetworkGroup> _cpNetworkGroups,
                                               List<CheckPoint_Host> _cpHosts,
                                               List<CheckPoint_Range> _cpRanges);
        public abstract void CalculateServices(List<CheckPoint_TcpService> _cpTcpServices,
                                               List<CheckPoint_UdpService> _cpUdpServices,
                                               List<CheckPoint_SctpService> _cpSctpServices,
                                               List<CheckPoint_IcmpService> _cpIcmpServices,
                                               List<CheckPoint_DceRpcService> _cpDceRpcServices,
                                               List<CheckPoint_OtherService> _cpOtherServices,
                                               List<CheckPoint_ServiceGroup> _cpServiceGroups);
        public abstract void CalculateRules(List<CheckPoint_Package> _cpPackages,
                                            List<CheckPoint_NAT_Rule> _cpNatRules);

    }
}
