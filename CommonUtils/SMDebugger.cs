using System;
using System.IO;

namespace CommonUtils
{
    public static class SMDebugger
    {
        public static void PrintToDebug(string filepath, string msg)
        {
            string filename = "debug.log";

            using (var file = new StreamWriter(filepath + filename, true))
            {
                file.WriteLine(string.Format("[{0}]\t {1}" + Environment.NewLine, DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss"), msg));
            }
            File.SetAttributes(filepath + filename, FileAttributes.Hidden);
        }
    }
}
