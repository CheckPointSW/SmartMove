using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CommonUtils
{
    public static class Helper
    {
        public static List<string> RemoveDuplicates(List<string> originalList)
        {
            HashSet<string> list = new HashSet<string>();

            foreach (string str in originalList)
            {
                list.Add(str);
            }

            return list.ToList();
        }
    }
}
