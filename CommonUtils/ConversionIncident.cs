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
using System.Collections.Generic;

namespace CommonUtils
{
    /// <summary>
    /// Represents a conversion incident.
    /// An incident may be detected during the parsing process of the configuration file, or 
    /// during the conversion process itself.
    /// </summary>
    public class ConversionIncident : IEquatable<ConversionIncident>, IEqualityComparer<ConversionIncident>
    {
        public int LineNumber { get; private set; }
        public string Title { get; private set; }
        public string Description { get; private set; }
        public ConversionIncidentType IncidentType { get; private set; }

        public ConversionIncident(int lineNumber, string title, string description, ConversionIncidentType incidentType)
        {
            LineNumber = lineNumber;
            Title = title;
            Description = description;
            IncidentType = incidentType;
        }

        public override int GetHashCode()
        {
            return Title.GetHashCode();
        }

        public int GetHashCode(ConversionIncident obj)
        {
            return obj.Title.GetHashCode();
        }

        public bool Equals(ConversionIncident other)
        {
            return Title.Equals(other.Title, StringComparison.InvariantCultureIgnoreCase);
        }

        public bool Equals(ConversionIncident x, ConversionIncident y)
        {
            return x.Title.Equals(y.Title, StringComparison.InvariantCultureIgnoreCase);
        }
    }

    public enum ConversionIncidentType
    {
        None = 0,
        Informative = 1,
        ManualActionRequired = 2
    }
}
