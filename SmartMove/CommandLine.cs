using System;
using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using System.IO;
using CiscoMigration;
using JuniperMigration;
using MigrationBase;
using NetScreenMigration;
using FortiGateMigration;
using PaloAltoMigration;
using PanoramaPaloAltoMigration;
using System.Text.RegularExpressions;

namespace SmartMove
{
    /// <summary>
    /// Represents command line logic
    /// </summary>
    class CommandLine
    {    
        private string[] arguments { get; set; }

        public CommandLine(string[] args)
        {
            this.arguments = args;
        }

        #region command line options
        //–f “D:\SmartMove\Content\config.txt” 
        private string configFileName { get; set; }
        public string ConfigFileName
        {
            get { return configFileName; }
            set { configFileName = value; }
        }
        
        //–v CiscoASA
        private string vendor { get; set; }
        public string Vendor
        {
            get { return vendor; }
            set { vendor = value; }
        }

        //-t “D:\SmartMove\Content
        private string targetFolder { get; set; }
        public string TargetFolder
        {
            get { return targetFolder; }
            set { targetFolder = value; }
        }
        
        //-d domain
        private string domain { get; set; }
        public string Domain
        {
            get { return domain; }
            set { domain = value; }
        }

        //-n
        private bool convertNat { get; set; }
        public bool ConvertNat
        {
            get { return convertNat; }
            set { convertNat = value; }
        }

        //-u unit1
        private string ldapAccountUnit { get; set; }
        public string LdapAccountUnit
        {
            get { return ldapAccountUnit; }
            set { ldapAccountUnit = value; }
        }

        private bool convertUserConfiguration { get; set; }
        public bool ConvertUserConfiguration
        {
            get { return convertUserConfiguration; }
            set { convertUserConfiguration = value; }
        }
        //-i
        private bool dontImportUnusedObjects { get; set; }
        public bool DontImportUnusedObjects
        {
            get { return dontImportUnusedObjects; }
            set { dontImportUnusedObjects = value; }
        }
        #endregion

        public int DisplayHelp()
        {
            Console.WriteLine("SmartMove command usage:");
            Console.WriteLine();
            Console.WriteLine("SmartMove.exe [–f config_file_name] [-v vendor] [-t target_folder] [-d domain] [-n] [-u LDAP_Account_unit] [-i]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("\t" + "-f" + "\t" + "full path to vendor configuration file");
            Console.WriteLine("\t" + "-v" + "\t" + "vendor for conversion (available options: CiscoASA, JuniperSRX, JuniperSSG, FortiNet, PaloAlto, Panorama)");
            Console.WriteLine("\t" + "-t" + "\t" + "migration output folder");
            Console.WriteLine("\t" + "-d" + "\t" + "domain name (for CiscoASA, JuniperSRX, JuniperSSG only)");
            Console.WriteLine("\t" + "-n" + "\t" + "convert NAT configuration");
            Console.WriteLine("\t" + "-u" + "\t" + "LDAP Account unit for convert user configuration option (for FortiNet, PaloAlto and Panorama only)");
            Console.WriteLine("\t" + "-i" + "\t" + "do not import unused objects (for FortiNet, PaloAlto and Panorama only)");
            Console.WriteLine();
            Console.WriteLine("Example:");
            Console.WriteLine("\t" + "SmartMove.exe –f \"D:\\SmartMove\\Content\\config.txt\" –v CiscoASA - t \"D:\\SmartMove\\Content\" –n");
            return 0;
        }

        /*
         * Verifies that mandatory options are specified in command line.
         * Also checks options validity for the specific vendor.
         */
        public int CheckOptionsValidity(CommandLine commandLine)
        {
            var fullVendorsList = new List<string> { "CiscoASA", "JuniperSRX", "JuniperSSG", "FortiNet", "PaloAlto", "Panorama" };
            var vendorsList1 = new List<string> { "CiscoASA", "JuniperSRX", "JuniperSSG" };
            var vendorsList2 = new List<string> { "FortiNet", "PaloAlto", "Panorama" };
            if (String.IsNullOrEmpty(commandLine.Vendor))
            {
                Console.WriteLine("Option -v is mandatory but not specified.", MessageTypes.Error);
                Console.WriteLine("For command help run \"SmartMove.exe -help\"", MessageTypes.Error);
                return 0;
            }
            if (String.IsNullOrEmpty(commandLine.ConfigFileName))
            {
                Console.WriteLine("Option -f is mandatory but not specified.", MessageTypes.Error);
                Console.WriteLine("For command help run \"SmartMove.exe -help\"", MessageTypes.Error);
                return 0;
            }
            if (!fullVendorsList.Contains(commandLine.Vendor))
            {
                Console.WriteLine("Specified vendor \"" + commandLine.Vendor + "\" is not available.", MessageTypes.Error);
                Console.WriteLine("Available options are: CiscoASA, JuniperSRX, JuniperSSG, FortiNet, PaloAlto, Panorama", MessageTypes.Error);
                Console.WriteLine("For command help run \"SmartMove.exe -help\"", MessageTypes.Error);
                return 0;
            }
            if (vendorsList1.Contains(commandLine.Vendor))
            {
                if (commandLine.ConvertUserConfiguration == true)
                {
                    Console.WriteLine("Option -u is not valid for vendor " + commandLine.Vendor + "!");
                    Console.WriteLine("For command help run \"SmartMove.exe -help\"", MessageTypes.Error);
                    return 0;
                }

                if (commandLine.DontImportUnusedObjects == true)
                {
                    Console.WriteLine("Option -i is not valid for vendor " + commandLine.Vendor + "!");
                    Console.WriteLine("For command help run \"SmartMove.exe -help\"", MessageTypes.Error);
                    return 0;
                }

            }
            if (vendorsList2.Contains(commandLine.Vendor))
            {
                if (commandLine.ConvertUserConfiguration == true && commandLine.LdapAccountUnit == null)
                {
                    Console.WriteLine("Value for option -u is not specified!");
                    Console.WriteLine("For command help run \"SmartMove.exe -help\"", MessageTypes.Error);
                    return 0;
                }

            }
            if ((commandLine.vendor == "JuniperSRX" || commandLine.vendor == "PaloAlto") && !commandLine.configFileName.EndsWith(".xml"))
            {
                Console.WriteLine("Config file for " + commandLine.vendor + " must be in .xml format!");
                return 0;
            }
            if (commandLine.vendor == "Panorama" && !commandLine.configFileName.EndsWith(".tgz"))
            {
                Console.WriteLine("Config files archive for " + commandLine.vendor + " must be in .tgz format!");
                return 0;
            }
            return 1;
        }

        /*
         * Workaround method to prevent incorrect interpretation of \" sequense in target directory option while reading command line arguments.
         * The reason is that a double quotation mark preceded by a backslash, \", is interpreted as a literal double quotation mark (").
         * This method creates an array of command line arguments from the command line string.
         * e.g.
         * -t "D:\SmartMove\Content\"
         */

        public string[] regenerateArgs(string commandLineString)
        {
            String[] args = null;
            
            var parts = Regex.Matches(commandLineString, @"[\""].+?[\""]|[^ ]+")
                            .Cast<Match>()
                            .Select(m => m.Value)
                            .ToList();
            parts.RemoveAt(0);

            string buf;
            List<String> finalArgs = new List<String> ();
            foreach (var item in parts)
            {
                if (item.StartsWith("\"") && item.EndsWith("\""))
                {
                    buf = item.Substring(1, item.Length - 2);
                    finalArgs.Add(buf);
                }
                else
                {
                    finalArgs.Add(item);
                }
                    
            }
                args = finalArgs.ToArray();
                      
            return args;
        }

        /*
         * Parses input options and writes its values to ComamndLine class fields
         */
        public CommandLine Parse(string[] args)
        {                    
             for (int i = 0; i < args.Length; i++)
             {                
                switch (args[i])
                {
                    case "-f":
                        {
                            if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                            {                         
                                if (args[i + 1].IndexOf("\\") != -1)
                                {                                    
                                    this.ConfigFileName = args[i + 1];
                                }
                                else
                                {
                                    this.configFileName = Directory.GetCurrentDirectory() + "\\" + args[i + 1];
                             
                                }
                                //set default velue of target folder to cofig file directory
                                this.TargetFolder = this.ConfigFileName.Substring(0, this.ConfigFileName.LastIndexOf("\\"));
                                
                            } else
                            {
                                Console.WriteLine("Value for mandatory option -f is not specified! ", MessageTypes.Error);
                            } 

                            break;
                        }
                    case "-v":
                        {
                            if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                                this.vendor = args[i + 1];
                             else
                                 Console.WriteLine("Value for mandatory option -v is not specified! ", MessageTypes.Error);
                            break;
                        }
                    case "-t":
                        {
                            if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                                this.targetFolder = args[i + 1]; 
                            else
                                Console.WriteLine("Value for target folder option -t is not specified. Default value will be set!", MessageTypes.Error);
                            break;
                        }
                    case "-d":
                        {
                            if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                                this.domain = args[i + 1];
                            else
                                Console.WriteLine("Value for option -d is not specified! ", MessageTypes.Error);
                            break;
                        }
                    case "-n":
                        {
                            this.convertNat = true;
                            break;
                        }
                    case "-u":
                        {
                            if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                            {
                                this.ldapAccountUnit = args[i + 1];
                                this.ConvertUserConfiguration = true;
                            } else
                            {
                                this.ConvertUserConfiguration = true;
                                //Console.WriteLine("Value for option -u is not specified! ", MessageTypes.Error);
                            }
                                
                            break;
                        }
                    case "-i":
                        {
                            this.dontImportUnusedObjects = true;
                            break;
                        }                    
                }                                
             }
             return this;
        }

        /*
         * This is the analog to MainWindow.Go_OnClick() function if application is run as WPF. 
         * It performs the migration.
         */
        public void DoMigration(CommandLine commandLine)
        {
            
            string fileName = Path.GetFileNameWithoutExtension(commandLine.ConfigFileName);
            //Console.WriteLine("File name: " + fileName);

            if (string.IsNullOrEmpty(commandLine.ConfigFileName) || string.IsNullOrEmpty(fileName))            
            {
                Console.WriteLine("Configuration file is not selected.", MessageTypes.Error);                
                return;
            }

            if (!File.Exists(commandLine.ConfigFileName))
            {
                Console.WriteLine("Cannot find configuration file.", MessageTypes.Error);
                return;
            }

            if (fileName.Length > 20)
            {
                Console.WriteLine("Configuration file name is restricted to 20 characters at most.", MessageTypes.Error);
                return;
            }
                   
            if (!Directory.Exists(commandLine.TargetFolder))
            {
                Console.WriteLine("Cannot find target folder for conversion output.", MessageTypes.Error);
                return;
            }

            VendorParser vendorParser;

            switch (commandLine.Vendor)            
            {
                case "CiscoASA":                    
                    vendorParser = new CiscoParser();
                    break;
                case "JuniperSRX":
                    vendorParser = new JuniperParser();
                    break;
                case "JuniperSSG":
                    vendorParser = new ScreenOSParser();
                    break;
                case "FortiNet":
                    vendorParser = new FortiGateParser();
                    break;
                case "PaloAlto":                    
                    vendorParser = new PaloAltoParser();                    
                    break;
                case "Panorama":
                    vendorParser = new PanoramaParser();
                    break;
                default:
                    throw new InvalidDataException("Unexpected!!!");
            }

            try
            {                
                string ciscoFile = commandLine.ConfigFileName;
                Console.WriteLine("Parsing configuration file...");
                
                if (commandLine.Vendor.Equals("Panorama"))
                {
                    PanoramaParser panParser = (PanoramaParser)vendorParser;
                    panParser.ParseWithTargetFolder(ciscoFile, TargetFolder);
                }
                else
                {
                    vendorParser.Parse(ciscoFile);
                }
            }
            catch (Exception ex)
            {                
                Console.WriteLine(string.Format("Could not parse configuration file.\n\nMessage: {0}\nModule:\t{1}\nClass:\t{2}\nMethod:\t{3}", ex.Message, ex.Source, ex.TargetSite.ReflectedType.Name, ex.TargetSite.Name), MessageTypes.Error);
                return;
            }

            #region check middleware version
            switch (commandLine.Vendor)
            {
                case "CiscoASA":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        Console.WriteLine("Unspecified ASA version.\nCannot find ASA version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 8 || (vendorParser.MajorVersion == 8 && vendorParser.MinorVersion < 3))
                    {
                        Console.WriteLine("Unsupported ASA version (" + vendorParser.Version + ").\nThis tool supports ASA 8.3 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;

                case "JuniperSRX":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        Console.WriteLine("Unspecified SRX version.\nCannot find SRX version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 12 || (vendorParser.MajorVersion == 12 && vendorParser.MinorVersion < 1))
                    {
                        Console.WriteLine("Unsupported SRX version (" + vendorParser.Version + ").\nThis tool supports SRX 12.1 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;

                case "JuniperSSG":
                    break;

                case "FortiNet":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        Console.WriteLine("Unspecified FortiGate version.\nCannot find FortiGate version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 5)
                    {
                        Console.WriteLine("Unsupported FortiGate version (" + vendorParser.Version + ").\nThis tool supports FortiGate 5.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;
                case "PaloAlto":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        Console.WriteLine("Unspecified PaloAlto version.\nCannot find PaloAlto PAN-OS version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        Console.WriteLine("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto PAN-OS 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;
                case "Panorama":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        Console.WriteLine("Unspecified PaloAlto Panorama version.\nCannot find PaloAlto Panorama version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        Console.WriteLine("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto Panorama 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        return;
                    }
                    break;
            }
            #endregion                       

            string vendorFileName = Path.GetFileNameWithoutExtension(commandLine.ConfigFileName);            

            string toolVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            
            string targetFolder = commandLine.TargetFolder + "\\";                        

            bool convertNat = commandLine.ConvertNat;
            
            string ldapAccountUnit = commandLine.LdapAccountUnit;
            
            vendorParser.Export(targetFolder + vendorFileName + ".json");

            VendorConverter vendorConverter;

            switch (commandLine.Vendor)
            {
                case "CiscoASA":                    
                    vendorConverter = new CiscoConverter();
                    break;
                case "JuniperSRX":
                    vendorConverter = new JuniperConverter();
                    break;
                case "JuniperSSG":
                    vendorConverter = new ScreenOSConverter();
                    break;
                case "FortiNet":
                    FortiGateConverter fgConverter = new FortiGateConverter();
                    fgConverter.OptimizeConf = commandLine.DontImportUnusedObjects;
                    fgConverter.ConvertUserConf = commandLine.ConvertUserConfiguration;
                    fgConverter.LDAPAccoutUnit = ldapAccountUnit;
                    vendorConverter = fgConverter;
                    break;
                case "PaloAlto":
                    PaloAltoConverter paConverter = new PaloAltoConverter();
                    paConverter.OptimizeConf = commandLine.DontImportUnusedObjects;
                    paConverter.ConvertUserConf = commandLine.ConvertUserConfiguration;
                    paConverter.LDAPAccoutUnit = ldapAccountUnit;
                    vendorConverter = paConverter;                    
                    break;
                case "Panorama":
                    PanoramaConverter panoramaConverter = new PanoramaConverter();
                    panoramaConverter.OptimizeConf = commandLine.DontImportUnusedObjects;
                    panoramaConverter.ConvertUserConf = commandLine.ConvertUserConfiguration;
                    panoramaConverter.LDAPAccoutUnit = ldapAccountUnit;
                    vendorConverter = panoramaConverter;
                    break;
                default:
                    throw new InvalidDataException("Unexpected!!!");
            }

            vendorConverter.Initialize(vendorParser, commandLine.ConfigFileName, toolVersion, targetFolder, commandLine.Domain);
            
            try
            {
                Console.WriteLine("Conversion is in progress...");
                vendorConverter.Convert(convertNat);
                Console.WriteLine("Conversion is finished.");
            }
            catch (Exception ex)
            {
               
                Console.WriteLine(string.Format("Could not convert configuration file.\n\nMessage: {0}\nModule:\t{1}\nClass:\t{2}\nMethod:\t{3}", ex.Message, ex.Source, ex.TargetSite.ReflectedType.Name, ex.TargetSite.Name), MessageTypes.Error);
                return;
            }                     
            
            vendorConverter.ExportConfigurationAsHtml();            
            vendorConverter.ExportPolicyPackagesAsHtml();            
            if (commandLine.ConvertNat)
            {
                vendorConverter.ExportNatLayerAsHtml();               
            }          
        }
    }
}
