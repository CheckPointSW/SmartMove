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

namespace CheckPointObjects
{
    /// <summary>
    /// Repository for Check Point objects created during the convertion from 3rd party configuration and 
    /// predefined Check Point objects.
    /// Objects are identified by their names.
    /// </summary>
    public class CheckPointObjectsRepository
    {
        #region Private Members

        private class ObjectInfo
        {
            public CheckPointObject Object  { get; private set; }
            public bool IsPredefined  { get; private set; }

            public ObjectInfo(CheckPointObject cpObject, bool isPredefined)
            {
                Object = cpObject;
                IsPredefined = isPredefined;
            }
        }

        private readonly Dictionary<string, ObjectInfo> _repository = new Dictionary<string, ObjectInfo>();
        private readonly Dictionary<string, string> _knownServices = new Dictionary<string, string>();

        #endregion

        #region Methods

        /// <summary>
        /// Initializes the repository with Check Point's predefined objects
        /// </summary>
        public void Initialize()
        {
            string[] names = { CheckPointObject.Any, "icmp-proto" };   // general objects
            foreach (string name in names)
            {
                var cpPredifinedObject = new CheckPoint_PredifinedObject { Name = name };
                _repository.Add(cpPredifinedObject.Name, new ObjectInfo(cpPredifinedObject, true));
            }

            string[] knownTcpServices = File.ReadAllLines("CP_KnownTcpPorts.csv");
            foreach (string line in knownTcpServices)
            {
                string[] services = line.Split(',');

                var cpPredifinedObject = new CheckPoint_PredifinedObject { Name = services[0].Trim('"') };
                _repository.Add(cpPredifinedObject.Name, new ObjectInfo(cpPredifinedObject, true));

                // Key is the port number/range, Value is the service name
                string key = "TCP_" + services[1].Trim('"');
                string value = services[0].Trim('"');

                if (!_knownServices.ContainsKey(key))
                {
                    _knownServices.Add(key, value);
                }
            }

            string[] knownUdpServices = File.ReadAllLines("CP_KnownUdpPorts.csv");
            foreach (string line in knownUdpServices)
            {
                string[] services = line.Split(',');

                var cpPredifinedObject = new CheckPoint_PredifinedObject { Name = services[0].Trim('"') };
                _repository.Add(cpPredifinedObject.Name, new ObjectInfo(cpPredifinedObject, true));

                // Key is the port number/range, Value is the service name
                string key = "UDP_" + services[1].Trim('"');
                string value = services[0].Trim('"');

                if (!_knownServices.ContainsKey(key))
                {
                    _knownServices.Add(key, value);
                }
            }

            string[] knownOtherServices = File.ReadAllLines("CP_KnownOtherPorts.csv");
            foreach (string line in knownOtherServices)
            {
                string[] services = line.Split(',');

                var cpPredifinedObject = new CheckPoint_PredifinedObject { Name = services[0].Trim('"') };
                _repository.Add(cpPredifinedObject.Name, new ObjectInfo(cpPredifinedObject, true));

                // Key is the protocol number, Value is the service name
                string key = "OTHER_" + services[1].Trim('"');
                string value = services[0].Trim('"');

                if (!_knownServices.ContainsKey(key))
                {
                    _knownServices.Add(key, value);
                }
            }

            string[] knownIcmpServices = File.ReadAllLines("CP_KnownIcmpTypes.csv");
            foreach (string line in knownIcmpServices)
            {
                string[] services = line.Split(',');

                var cpPredifinedObject = new CheckPoint_PredifinedObject { Name = services[0].Trim('"') };
                _repository.Add(cpPredifinedObject.Name, new ObjectInfo(cpPredifinedObject, true));

                // Key is the ICMP type, Value is the ICMP service name
                string key = "ICMP_" + services[1].Trim('"');
                string value = services[0].Trim('"');

                if (!_knownServices.ContainsKey(key))
                {
                    _knownServices.Add(key, value);
                }
            }

            string[] knownServiceGroups = File.ReadAllLines("CP_KnownServiceGroups.csv");
            foreach (string knownServiceGroup in knownServiceGroups)
            {
                var cpPredifinedObject = new CheckPoint_PredifinedObject { Name = knownServiceGroup.Trim('"') };
                _repository.Add(cpPredifinedObject.Name, new ObjectInfo(cpPredifinedObject, true));
            }
        }

        public void AddObject(CheckPointObject cpObject)
        {
            if (cpObject != null && !string.IsNullOrEmpty(cpObject.Name) && !HasObject(cpObject.Name))
            {
                _repository.Add(cpObject.Name, new ObjectInfo(cpObject, false));
            }
        }

        public bool HasObject(string objectName)
        {
            return (!string.IsNullOrEmpty(objectName) && _repository.ContainsKey(objectName));
        }

        public CheckPointObject GetObject(string objectName)
        {
            if (HasObject(objectName))
            {
                return _repository[objectName].Object;
            }

            return null;
        }

        public void RemoveObject(string objectName)
        {
            if (!string.IsNullOrEmpty(objectName))
            {
                _repository.Remove(objectName);
            }
        }

        public List<CheckPointObject> GetPredefinedObjects()
        {
            return (from objectInfo in _repository where objectInfo.Value.IsPredefined select objectInfo.Value.Object).ToList();
        }

        public string GetKnownServiceName(string id, out bool found)
        {
            found = false;

            if (_knownServices.ContainsKey(id))
            {
                found = true;
                return _knownServices[id];
            }

            return id;
        }

        public bool IsKnownService(string serviceName)
        {
            return (serviceName == CheckPointObject.Any || serviceName == "icmp-proto" || _knownServices.ContainsValue(serviceName));
        }

        #endregion
    }
}
