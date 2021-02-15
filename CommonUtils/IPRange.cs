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
using System.Linq;
using System.Net;

namespace CommonUtils
{
    /// <summary>
    /// IP address range manipulations
    /// </summary>
    public class IPRange
    {
        #region Constants

        public const string Any = "any";

        #endregion

        #region Private Members

        private IPAddress _fromIP;
        private IPAddress _toIP;
        private UInt32 _minimum;
        private UInt32 _maximum;

        #endregion

        #region Properties

        public UInt32 Size
        {
            get { return Maximum - Minimum + 1; }
        }

        public UInt32 Minimum
        {
            get { return _minimum; }
            set
            {
                _minimum = value;
                _fromIP = IPAddress.Parse(NetworkUtils.Number2Ip(_minimum));
            }
        }

        public UInt32 Maximum
        {
            get { return _maximum; }
            set
            {
                _maximum = value;
                _toIP = IPAddress.Parse(NetworkUtils.Number2Ip(_maximum));
            }
        }

        #endregion

        #region Construction

        public IPRange()
        {
        }

        public IPRange(string any)
        {
            _fromIP = IPAddress.Parse("0.0.0.0");
            _toIP = IPAddress.Parse("0.0.0.0");
            _minimum = 0;
            _maximum = 0;

            if (any == Any)
            {
                _toIP = IPAddress.Parse("255.255.255.255");
                _maximum = UInt32.MaxValue;
            }
        }

        public IPRange(IPAddress ip)
        {
            _fromIP = ip;
            _toIP = ip;
            _minimum = NetworkUtils.Ip2Number(_fromIP);
            _maximum = NetworkUtils.Ip2Number(_fromIP);
        }

        public IPRange(IPNetwork ip)
        {
            _fromIP = ip.Network;
            _toIP = ip.Broadcast;
            _minimum = NetworkUtils.Ip2Number(_fromIP);
            _maximum = NetworkUtils.Ip2Number(_toIP == null ? _fromIP : _toIP);
        }

        public IPRange(IPAddress from, IPAddress to)
        {
            _fromIP = from;
            _toIP = to;
            _minimum = NetworkUtils.Ip2Number(_fromIP);
            _maximum = NetworkUtils.Ip2Number(_toIP);
        }

        public IPRange(UInt32 min, UInt32 max)
        {
            _fromIP = IPAddress.Parse(NetworkUtils.Number2Ip(min));
            _toIP = IPAddress.Parse(NetworkUtils.Number2Ip(max));
            _minimum = min;
            _maximum = max;
        }

        #endregion

        #region Methods

        public IPRange Copy()
        {
            return new IPRange(Minimum, Maximum);
        }

        public bool IsValid()
        {
            return (Minimum <= Maximum);
        }

        public bool IsEmpty()
        {
            return (Size <= 0);
        }

        public override string ToString()
        {
            return string.Format("[{0} - {1}]", _fromIP, _toIP);
        }

        #endregion
    }

    /// <summary>
    /// Represents a list of IP address ranges
    /// </summary>
    public class IPRanges
    {
        #region Private Members

        private List<IPRange> _ranges = null;

        #endregion

        #region Properties

        public List<IPRange> Ranges
        {
            get { return _ranges ?? (_ranges = new List<IPRange>()); }
        }

        #endregion

        #region Construction

        public IPRanges()
        {
        }

        public IPRanges(IPRange range)
        {
            Ranges.Add(range);
        }

        public IPRanges(List<IPRange> ranges)
        {
            Ranges.AddRange(ranges);
        }

        #endregion

        #region Methods

        public bool Overlaps(IPRanges other)
        {
            foreach (var r1 in Ranges)
            {
                foreach (var r2 in other.Ranges)
                {
                    // one range contains the other
                    if (r1.Minimum <= r2.Minimum && r1.Maximum >= r2.Maximum) return true;
                    if (r2.Minimum <= r1.Minimum && r2.Maximum >= r1.Maximum) return true;

                    // one ends before the second starts
                    if (r1.Minimum <= r2.Minimum && r1.Maximum >= r2.Minimum) return true;
                    if (r2.Minimum <= r1.Minimum && r2.Maximum >= r1.Minimum) return true;
                }
            }

            return false;
        }

        public void Add(IPRanges other)
        {
            Ranges.AddRange(other.Ranges);
        }

        public override string ToString()
        {
            return string.Concat((this).Ranges.Select(o => o.ToString() + Environment.NewLine));
        }

        public static IPRanges Any()
        {
            return new IPRanges(new IPRange(IPRange.Any));
        }

        public static IPRanges operator +(IPRanges r1, IPRanges r2)
        {
            if (r1 == null) return r2;
            if (r2 == null) return r1;

            r1.Ranges.AddRange(r2.Ranges);

            return r1;
        }

        public static IPRanges Merge(IPRanges rangesToMerge)
        {
            if (rangesToMerge.Ranges.Count == 1)
            {
                return new IPRanges(rangesToMerge.Ranges);
            }

            var mergedRanges = new List<IPRange>();
            var rangesToMergeSorted = rangesToMerge.Ranges.OrderBy(o => o.Minimum).ThenBy(y => y.Maximum).ToList();

            IPRange rangeA = rangesToMergeSorted[0].Copy();
            IPRange rangeB = new IPRange();

            bool addA = false;
            bool addB = false;

            for (int i = 1; i < rangesToMergeSorted.Count; i++)
            {
                rangeB = rangesToMergeSorted[i];

                if (rangeB.Minimum > rangeA.Maximum)
                {
                    mergedRanges.Add(rangeA.Copy());
                    rangeA = rangeB.Copy();
                    addB = true;
                    addA = false;
                }
                else
                {
                    if (rangeB.Maximum > rangeA.Maximum)
                    {
                        rangeA.Maximum = rangeB.Maximum;
                    }
                    addA = true;
                    addB = false;
                }
            }

            if (addA) mergedRanges.Add(rangeA);
            if (addB) mergedRanges.Add(rangeB);

            return new IPRanges(mergedRanges);
        }

        public static IPRanges Negate(IPRange r1, IPRanges negatedRanges)
        {
            if (!r1.IsValid())
            {
                return null;
            }

            // merge subnets to negate
            var mergedNegatedRanges = Merge(negatedRanges).Ranges;

            var res = new List<IPRange>();

            // no overlap
            if (r1.Maximum < mergedNegatedRanges[0].Minimum || r1.Minimum > mergedNegatedRanges.Last().Maximum)
            {
                res.Add(r1);
                return (new IPRanges(res));
            }

            var lastRange = new IPRange(r1.Minimum, r1.Maximum);

            foreach (IPRange negatedRange in mergedNegatedRanges)
            {
                if (lastRange.Minimum < negatedRange.Minimum)
                {
                    res.Add(new IPRange(lastRange.Minimum, negatedRange.Minimum - 1));
                    lastRange.Minimum = negatedRange.Maximum + 1;
                }
                else
                {
                    if (negatedRange.Maximum < lastRange.Minimum)
                    {
                        // do nothing - ignore this range
                    }
                    else
                    {
                        if (negatedRange.Maximum < lastRange.Maximum)
                        {
                            lastRange.Minimum = negatedRange.Maximum + 1;
                        }
                    }
                }
            }

            if (!lastRange.IsEmpty())
            {
                res.Add(lastRange);
            }

            return new IPRanges(res);
        }

        #endregion
    }
}
