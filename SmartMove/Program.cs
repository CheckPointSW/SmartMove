using System;
using System.Runtime.InteropServices;

namespace SmartMove
{
    public static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool FreeConsole();

        [STAThread]
        /*
         * Entry point
         */
        public static int Main(string[] args)
        {
            if (args != null && args.Length > 0)
            {
                CommandLine commandLine = new CommandLine(args);                

                //display command help
                if (args[0].Equals("-help") || args[0].Equals("/?"))
                {
                    return commandLine.DisplayHelp();
                }

                args = commandLine.regenerateArgs(Environment.CommandLine);

                commandLine = commandLine.Parse(args);
/*
                Console.WriteLine();
                Console.WriteLine(" -> Config file name: " + commandLine.ConfigFileName);
                Console.WriteLine(" -> Target folder: " + commandLine.TargetFolder);
                Console.WriteLine(" -> Vendor: " + commandLine.Vendor);
                Console.WriteLine(" -> Domain: " + commandLine.Domain);
                Console.WriteLine(" -> Convert NAT option: " + commandLine.ConvertNat);
                Console.WriteLine(" -> LDAP account unit: " + commandLine.LdapAccountUnit);
                Console.WriteLine(" -> Convert user configuration option: " + commandLine.ConvertUserConfiguration);
                Console.WriteLine(" -> Don't import unused objects option: " + commandLine.DontImportUnusedObjects);
                Console.WriteLine();*/

                int exitCode = commandLine.CheckOptionsValidity(commandLine);
                
                if (exitCode == 0)
                {
                    return 0;
                } else 
                {                 
                commandLine.DoMigration(commandLine);                
                return 0;
                }
            }
            else
            {
                FreeConsole();
                var app = new App();
                return app.Run();
            }
        }
        
    }
}
