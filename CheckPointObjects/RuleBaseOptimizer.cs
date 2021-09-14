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
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using CommonUtils;

namespace CheckPointObjects
{
    /// <summary>
    /// Optimizes the security policy rulebase by merging several rules from the same sub-policy into a single rule.
    /// Two rules can be merged into one rule if:
    ///    1. both rules have the same action, and
    ///    2. both rules are enabled or disabled, and
    ///    3. both rules have source and destination columns negated or not, and
    ///    4. both rules have the same time objects, and 
    ///    5. either one of the following is true:
    ///       5.1. both the source and destination columns match
    ///       5.2. both the source and service columns match
    ///       5.3. both the destination and service columns match
    /// </summary>
    public static class RuleBaseOptimizer
    {
        public static CheckPoint_Layer Optimize(CheckPoint_Layer originalLayer, string newName)
        {
            CheckPoint_Layer curLayer = originalLayer;
            CheckPoint_Layer newLayer;

            while (true)
            {
                var nextLayer = new CheckPoint_Layer { Name = newName };

                foreach (CheckPoint_Rule rule in curLayer.Rules)
                {
                    AddRule(nextLayer, rule);
                }

                if (nextLayer.Rules.Count == curLayer.Rules.Count)
                {
                    newLayer = nextLayer;
                    break;
                }

                curLayer = nextLayer;
            }

            for (int i = 0; i < newLayer.Rules.Count; ++i)
            {
                newLayer.Rules[i].ConversionComments = OptimizeConverstionComments(newLayer.Rules[i].ConversionComments);
            }

            return newLayer;
        }

        private static void AddRule(CheckPoint_Layer layer, CheckPoint_Rule newRule)
        {
            bool match = false;

            int pos = GetFirstRuleWithSameAction(layer, newRule.Action);
            if (pos >= 0)
            {
                for (int i = pos; i < layer.Rules.Count(); i++)
                {
                    if (IsRuleSimilarToRule(layer.Rules[i], newRule))
                    {
                        layer.Rules[i] = MergeRules(layer.Rules[i], newRule);
                        match = true;
                        break;
                    }
                }
            }

            if (!match)
            {
                CheckPoint_Rule rule = newRule.Clone();
                rule.Layer = layer.Name;
                rule.Comments = "";
                rule.ConversionComments = newRule.ConversionComments;
                layer.Rules.Add(rule);
            }
        }

        private static CheckPoint_Rule MergeRules(CheckPoint_Rule rule1, CheckPoint_Rule rule2)
        {
            var mergedRule = new CheckPoint_Rule();

            var sources = new List<CheckPointObject>();
            var destinations = new List<CheckPointObject>();
            var services = new List<CheckPointObject>();
            var times = new List<CheckPointObject>();

            sources.AddRange(rule1.Source);
            sources.AddRange(rule2.Source);
            mergedRule.Source = sources.Distinct().ToList();
            OmitAnyFromList(mergedRule.Source);

            destinations.AddRange(rule1.Destination);
            destinations.AddRange(rule2.Destination);
            mergedRule.Destination = destinations.Distinct().ToList();
            OmitAnyFromList(mergedRule.Destination);

            services.AddRange(rule1.Service);
            services.AddRange(rule2.Service);
            mergedRule.Service = services.Distinct().ToList();
            OmitAnyFromList(mergedRule.Service);

            times.AddRange(rule1.Time);
            times.AddRange(rule2.Time);
            mergedRule.Time = times.Distinct().ToList();
            OmitAnyFromList(mergedRule.Time);

            mergedRule.Enabled = (rule1.Enabled && rule2.Enabled);
            mergedRule.Layer = rule1.Layer;
            mergedRule.Action = rule1.Action;
            mergedRule.Track = rule1.Track;
            mergedRule.SourceNegated = rule1.SourceNegated;
            mergedRule.DestinationNegated = rule1.DestinationNegated;
            mergedRule.Comments = "";
            mergedRule.ConversionComments = rule1.ConversionComments + " | " + rule2.ConversionComments;
            mergedRule.ConvertedCommandId = rule1.ConvertedCommandId;
            mergedRule.ConversionIncidentType = ConversionIncidentType.None;

            if (rule1.ConversionIncidentType != ConversionIncidentType.None || rule2.ConversionIncidentType != ConversionIncidentType.None)
            {
                if (rule1.ConversionIncidentType > rule2.ConversionIncidentType)
                {
                    mergedRule.ConvertedCommandId = rule1.ConvertedCommandId;
                    mergedRule.ConversionIncidentType = rule1.ConversionIncidentType;
                }
                else
                {
                    mergedRule.ConvertedCommandId = rule2.ConvertedCommandId;
                    mergedRule.ConversionIncidentType = rule2.ConversionIncidentType;
                }
            }

            return mergedRule;
        }

        private static void OmitAnyFromList(List<CheckPointObject> list)
        {
            if (list.Count > 1)
            {
                foreach (var item in list.Where(item => item.Name == CheckPointObject.Any))
                {
                    list.Remove(item);
                    break;
                }
            }
        }

        private static int GetFirstRuleWithSameAction(CheckPoint_Layer layer, CheckPoint_Rule.ActionType action)
        {
            int matchedRules = 0;
            int pos = layer.Rules.Count - 1;

            while (pos >= 0 && layer.Rules[pos].Action == action)
            {
                matchedRules++;
                pos--;
            }

            return (matchedRules == 0) ? -1 : (pos + 1);
        }

        private static bool IsRuleSimilarToRule(CheckPoint_Rule rule1, CheckPoint_Rule rule2)
        {
            if (rule1.Action != rule2.Action)
            {
                return false;
            }

            if (rule1.Enabled != rule2.Enabled)
            {
                return false;
            }

            if (rule1.SourceNegated != rule2.SourceNegated || rule1.DestinationNegated != rule2.DestinationNegated)
            {
                return false;
            }

            if ((rule1.Time.Count != rule2.Time.Count) || 
                (rule1.Time.Count > 0 && rule2.Time.Count > 0 && rule1.Time[0].Name != rule2.Time[0].Name))
            {
                return false;
            }

            bool sourceMatch = CompareLists(rule1.Source, rule2.Source);
            bool destMatch = CompareLists(rule1.Destination, rule2.Destination);
            bool serviceMatch = CompareLists(rule1.Service, rule2.Service);

            return (sourceMatch && destMatch || destMatch && serviceMatch || sourceMatch && serviceMatch);
        }

        private static bool CompareLists(List<CheckPointObject> items, List<CheckPointObject> searchedItems)
        {
            var list1 = (from o in items select o.Name).ToList();
            var list2 = (from o in searchedItems select o.Name).ToList();

            var firstNotSecond = list1.Except(list2).ToList();
            var secondNotFirst = list2.Except(list1).ToList();

            return (!firstNotSecond.Any() && !secondNotFirst.Any());
        }

        /// <summary>
        /// Method for creation comment by the template 'optimized of access-list #x #y'
        /// </summary>
        /// <param name="commentToProcess">comment to process</param>
        /// <returns>optimized comment at the right format</returns>
        private static string OptimizeConverstionComments(string commentToProcess)
        {
            string commentBuilder = "optimized of access-list";
            List<string> rules = new List<string>();
            List<string> comments_parts = commentToProcess.Split(' ').ToList();
            Regex regex = new Regex(@"[0-9]+[)]");

            if (regex.IsMatch(comments_parts[0]))
                foreach (string part in comments_parts)
                {
                    if (regex.IsMatch(part))
                        commentBuilder += " " + part.Remove(part.Length - 1);
                }
            else
                return commentToProcess;

            return commentBuilder;
        }
    }
}
