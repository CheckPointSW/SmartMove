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
using CommonUtils;
using System.Threading;
using CheckPointObjects;

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
        //–s “D:\SmartMove\Content\config.txt” 
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

        //-l unit1
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
        //-k
        private bool dontImportUnusedObjects { get; set; }
        public bool DontImportUnusedObjects
        {
            get { return dontImportUnusedObjects; }
            set { dontImportUnusedObjects = value; }
        }
        //-f
        private string formatOutput { get; set; }
        public string FormatOutput
        {
            get { return formatOutput; }
            set { formatOutput = value; }
        }

        //-a
        private bool isAnalyze { get; set; } = false;
        public bool IsAnalyze
        {
            get { return isAnalyze; }
            set { isAnalyze = value; }
        }

        private bool _successCommands = true;
        private bool _isInteractive = true;

        private bool _isCiscoSpreadAclRemarks = false;
        private bool _isOptimizeByComments;
        #endregion

        public int DisplayHelp()
        {
            Console.WriteLine("SmartMove command usage:");
            Console.WriteLine();
            Console.WriteLine("SmartMove.exe [–s config_file_name] [-v vendor] [-t target_folder] [-d domain] [-n] [-l LDAP_Account_unit] [-k]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("\t" + "-s | --source" + "\t\t" + "full path to the vendor configuration file");
            Console.WriteLine("\t" + "-v | --vendor" + "\t\t" + "vendor for conversion (available options: CiscoASA, FirePower, JuniperSRX, JuniperSSG, FortiNet, PaloAlto, Panorama)");
            Console.WriteLine("\t" + "-t | --target" + "\t\t" + "migration output folder");
            Console.WriteLine("\t" + "-d | --domain" + "\t\t" + "domain name (for CiscoASA, FirePower, JuniperSRX, JuniperSSG only)");
            Console.WriteLine("\t" + "-n | --nat" + "\t\t" + @"(""-n false"" |"" -n true"" [default])  convert NAT configuration [enabled by default]");
            Console.WriteLine("\t" + "-l | --ldap" + "\t\t" + "LDAP Account unit for convert user configuration option (for FortiNet, PaloAlto and Panorama only)");
            Console.WriteLine("\t" + "-k | --skip" + "\t\t" + @"(""-k false"" |"" -k true"" [default]) do not import unused objects (for FortiNet, Firepower, PaloAlto, CiscoASA, Panorama, JuniperSRX and JuniperSSG only) [enabled by default]");
            Console.WriteLine("\t" + "-f | --format" + "\t\t" + "format of the output file (JSON[default], TEXT)");
            Console.WriteLine("\t" + "-i | --interactive" + "\t" + @"-i false | -i true [default] Interactive mode provides a better user experience.Disable when automation is required[enabled by default]");
            Console.WriteLine("\t" + "-a | --analyzer" + "\t\t" + @"mode for analyze package");
            Console.WriteLine("\t" + "-obc | --optimize-by-comments" + "\t" + @"(""-obc false"" | ""-obc true"" [default]) create optimized policy by comment and spread acl remarks - only for CiscoASA, FirePower");
            Console.WriteLine();
            Console.WriteLine("Example:");
            Console.WriteLine("\t" + "SmartMove.exe –s \"D:\\SmartMove\\Content\\config.txt\" –v CiscoASA - t \"D:\\SmartMove\\Content\" –n true -k false -f json -a");
            return 0;
        }

        /*
         * Verifies that mandatory options are specified in command line.
         * Also checks options validity for the specific vendor.
         */
        public int CheckOptionsValidity(CommandLine commandLine)
        {
            var fullVendorsList = new List<string> { "CiscoASA", "JuniperSRX", "JuniperSSG", "FortiNet", "PaloAlto", "Panorama", "FirePower" }; //all vendors
            var vendorsList1 = new List<string> { "CiscoASA", "JuniperSRX", "JuniperSSG", "FirePower" };                                        //option -d
            var vendorsList2 = new List<string> { "FortiNet", "PaloAlto", "Panorama", "CiscoASA", "JuniperSRX", "JuniperSSG", "FirePower" };    //option -k
            if (String.IsNullOrEmpty(commandLine.Vendor))
            {
                Console.WriteLine("Option -v is mandatory but not specified.", MessageTypes.Error);
                Console.WriteLine("For command help run \"SmartMove.exe -h or --help\"", MessageTypes.Error);
                return 0;
            }
            if (String.IsNullOrEmpty(commandLine.ConfigFileName))
            {
                Console.WriteLine("Option -s is mandatory but not specified.", MessageTypes.Error);
                Console.WriteLine("For command help run \"SmartMove.exe -h or --help\"", MessageTypes.Error);
                return 0;
            }
            if (!fullVendorsList.Contains(commandLine.Vendor))
            {
                Console.WriteLine("Specified vendor \"" + commandLine.Vendor + "\" is not available.", MessageTypes.Error);
                Console.WriteLine("Available options are: CiscoASA, FirePower, JuniperSRX, JuniperSSG, FortiNet, PaloAlto, Panorama", MessageTypes.Error);
                Console.WriteLine("For command help run \"SmartMove.exe -h or --help\"", MessageTypes.Error);
                return 0;
            }
            if (vendorsList1.Contains(commandLine.Vendor))
            {
                if (commandLine.ConvertUserConfiguration == true)
                {
                    Console.WriteLine("Option -l is not valid for vendor " + commandLine.Vendor + "!");
                    Console.WriteLine("For command help run \"SmartMove.exe -h or --help\"", MessageTypes.Error);
                    return 0;
                }

            }

            if (commandLine.DontImportUnusedObjects == true)
            {
                if (!vendorsList2.Contains(commandLine.Vendor))
                {
                    Console.WriteLine("Option -k is not valid for vendor " + commandLine.Vendor + "!");
                    Console.WriteLine("For command help run \"SmartMove.exe -h or --help\"", MessageTypes.Error);
                    return 0;
                }
            }

            if (vendorsList2.Contains(commandLine.Vendor))
            {
                if (commandLine.ConvertUserConfiguration == true && commandLine.LdapAccountUnit == null)
                {
                    Console.WriteLine("Value for option -l is not specified!");
                    Console.WriteLine("For command help run \"SmartMove.exe -h or --help\"", MessageTypes.Error);
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
            List<String> finalArgs = new List<String>();
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
            //set default values
            ConvertNat = true;
            FormatOutput = "json";
            //not default value, just for disabling null reference exception during conversion
            LdapAccountUnit = string.Empty;


            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-s":
                    case "--source":
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

                            }
                            else
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for mandatory option -s is not specified! ", MessageTypes.Error);
                            }

                            break;
                        }
                    case "-v":
                    case "--vendor":
                        {
                            if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                                this.vendor = args[i + 1];
                            else
                            {
                                Console.WriteLine("Value for mandatory option -v is not specified! ", MessageTypes.Error);
                                _successCommands = false;
                            }
                            break;
                        }
                    case "-t":
                    case "--target":
                        {
                            if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                                this.targetFolder = args[i + 1];
                            else
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for target folder option -t is not specified. Default value will be set!", MessageTypes.Error);
                            }
                            break;
                        }
                    case "-d":
                    case "--domain":
                        {
                            if (args[i] == args.Last())
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option -d is not specified! ", MessageTypes.Error);
                            }
                            else if(args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                                this.domain = args[i + 1];
                            else
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option -d is not specified! ", MessageTypes.Error);
                            }
                            break;
                        }
                    case "-n":
                    case "--nat":
                        {
                            if (args[i] == args.Last())
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option -n is not specified! ", MessageTypes.Error);
                            }
                            else if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                            {
                                bool nat;
                                if (!bool.TryParse(args[i + 1], out nat))
                                {
                                    Console.WriteLine("Value for option -n is not corrected! Only true or false allowed ", MessageTypes.Error);
                                    _successCommands = false;
                                }

                                this.convertNat = nat;
                            }
                            break;
                        }
                    case "-l":
                    case "--ldap":
                        {
                            if (args[i] == args.Last())
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option -l is not specified! ", MessageTypes.Error);
                            }
                            else if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                            {
                                if (args[i + 1].Contains(' ') || args[i + 1].Length == 0)
                                {
                                    Console.WriteLine("Value for option -l is not corrected! Spaces and empty string not allowed ", MessageTypes.Error);
                                    _successCommands = false;
                                }

                                this.ldapAccountUnit = args[i + 1];
                                this.ConvertUserConfiguration = true;
                            }
                            else 
                            {
                                this.ConvertUserConfiguration = true;
                                //Console.WriteLine("Value for option -u is not specified! ", MessageTypes.Error);
                            }

                            break;
                        }
                    case "-k":
                    case "--skip":
                        {
                            if (args[i] == args.Last())
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option -k is not specified! ", MessageTypes.Error);
                            }
                            else if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                            {
                                bool dontImportUnusedObjectsFlag;
                                if (!bool.TryParse(args[i + 1], out dontImportUnusedObjectsFlag))
                                {
                                    Console.WriteLine("Value for option -k is not corrected! Only true or false allowed ", MessageTypes.Error);
                                    _successCommands = false;
                                }

                                this.dontImportUnusedObjects = dontImportUnusedObjectsFlag;
                            }
                            break;
                        }
                    case "-f":
                    case "--format":
                        {
                            if (args[i] == args.Last())
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option -f is not specified! ", MessageTypes.Error);
                            }
                            else if(new List<string>() { "text", "json" }.Contains(args[i + 1].ToLower()))
                                FormatOutput = args[i + 1];
                            else
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option format is not corrected! Allow only 'text' or 'json' ", MessageTypes.Error);
                            }
                            break;
                        }
                    case "-i":
                    case "--interactive":
                        {
                            if (args[i] == args.Last())
                            {
                                _isInteractive = true;
                                _successCommands = false;
                                Console.WriteLine("Value for option -i is not specified! ", MessageTypes.Error);
                            }
                            else if (args[i] != args.Last() && !args[i + 1].StartsWith("-"))
                            {
                                bool interactive;
                                if (!bool.TryParse(args[i + 1], out interactive))
                                {
                                    Console.WriteLine("Value for option interactive is not corrected! Only true or false allowed ", MessageTypes.Error);
                                    _isInteractive = true;
                                    _successCommands = false;
                                }

                                _isInteractive = interactive;
                            }
                            break;
                        }
                    case "--asa-spread-acl-remarks":
                        {
                            if (args[i] == args.Last())
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option --asa-spread-acl-remarks is not specified! ", MessageTypes.Error);
                            }
                            else if (bool.TryParse(args[i + 1].ToLower(), out _isCiscoSpreadAclRemarks))
                                break;
                            else
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option format is not corrected! Allow only 'true' or 'false' ", MessageTypes.Error);
                            }
                            break;
                        }
                    case "-a":
                    case "--analyzer": 
                        {
                            this.isAnalyze = true;
                            break; 
                        }
                    case "-obc":
                    case "--optimize-by-comments": // adding flag to optimize by comments option
                        {
                            if (args[i] == args.Last())
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option --optimize-by-comments is not specified! ", MessageTypes.Error);
                            }
                            else if (bool.TryParse(args[i + 1].ToLower(), out _isOptimizeByComments))
                                break;
                            else
                            {
                                _successCommands = false;
                                Console.WriteLine("Value for option format is not corrected! Allow only 'true' or 'false' ", MessageTypes.Error);
                            }
                            break;
                        }
                }
            }
            return this;
        }

        public void DoAnalyze(CommandLine commandLine)
        {
            if (!_successCommands)
                return;

            string fileName = Path.GetFileNameWithoutExtension(commandLine.ConfigFileName);
            //Console.WriteLine("File name: " + fileName);

            if (string.IsNullOrEmpty(commandLine.ConfigFileName) || string.IsNullOrEmpty(fileName))
            {
                if (FormatOutput == "text")
                    Console.WriteLine("Configuration file is not selected.", MessageTypes.Error);
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Configuration file is not selected.",
                        err: "err_cannot_convert_configuration_file");
                    Console.WriteLine(jsonReport.PrintJson());
                }
                return;
            }

            if (!File.Exists(commandLine.ConfigFileName))
            {
                if (FormatOutput == "text")
                    Console.WriteLine("Cannot find configuration file.", MessageTypes.Error);
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Cannot find configuration file.",
                        err: "err_cannot_convert_configuration_file");
                    Console.WriteLine(jsonReport.PrintJson());
                }
                return;
            }

            if (fileName.Length > 15)
            {
                if (FormatOutput == "text")
                    Console.WriteLine("Configuration file name is restricted to 15 characters at most.", MessageTypes.Error);
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Configuration file name is restricted to 15 characters at most.",
                        err: "err_cannot_convert_configuration_file");
                    Console.WriteLine(jsonReport.PrintJson());
                }
                return;
            }

            if (!Directory.Exists(commandLine.TargetFolder))
            {
                if (FormatOutput == "text")
                    Console.WriteLine("Cannot find target folder for conversion output.", MessageTypes.Error);
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Cannot find target folder for conversion output.",
                        err: "err_cannot_convert_configuration_file");
                    Console.WriteLine(jsonReport.PrintJson());
                }
                return;
            }

            VendorParser vendorParser;

            switch (commandLine.Vendor)
            {
                case "CiscoASA":
                    CiscoParser.SpreadAclRemarks = _isOptimizeByComments;
                    RuleBaseOptimizer.IsOptimizeByComments = _isOptimizeByComments;
                    // verifying that the user or the default option won't reverse the flag to false if asking optimize by comments option
                    CiscoParser.SpreadAclRemarks = _isOptimizeByComments ? true : _isCiscoSpreadAclRemarks;
                    vendorParser = new CiscoParser();
                    break;
                case "FirePower":
                    CiscoParser.SpreadAclRemarks = _isOptimizeByComments;
                    RuleBaseOptimizer.IsOptimizeByComments = _isOptimizeByComments;
                    // verifying that the user or the default option won't reverse the flag to false if asking optimize by comments option
                    CiscoParser.SpreadAclRemarks = _isOptimizeByComments ? true : _isCiscoSpreadAclRemarks;
                    vendorParser = new CiscoParser()
                    {
                        isUsingForFirePower = true
                    };
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
                Console.Write("Parsing configuration file...");

                if (commandLine.Vendor.Equals("Panorama"))
                {

                    PanoramaParser panParser = (PanoramaParser)vendorParser;
                    panParser.ParseWithTargetFolder(ciscoFile, Path.GetFullPath(TargetFolder));
                }
                else
                {
                    vendorParser.Parse(ciscoFile);
                }

                Console.WriteLine("Done.");

            }
#pragma warning disable CS0168 // The variable 'ex' is declared but never used
            catch (Exception ex)
#pragma warning restore CS0168 // The variable 'ex' is declared but never used
            {
                if (FormatOutput == "text")
                {
                    Console.WriteLine("\nCould not parse configuration file.", MessageTypes.Error);
                    return;
                }
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Could not parse configuration file.",
                        err: "err_cannot_parse_configuration_file");
                    Console.WriteLine("\n" + jsonReport.PrintJson());
                    return;
                }
            }

            #region check middleware version
            switch (commandLine.Vendor)
            {
                case "CiscoASA":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified ASA version.\nCannot find ASA version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified ASA version. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 8 || (vendorParser.MajorVersion == 8 && vendorParser.MinorVersion < 3))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported ASA version (" + vendorParser.Version + "). This tool supports ASA 8.3 and above configuration files. The configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported ASA version (" + vendorParser.Version + "). This tool supports ASA 8.3 and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;

                case "JuniperSRX":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified SRX version.\nCannot find SRX version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified SRX version. Cannot find SRX version for the selected configuration. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 12 || (vendorParser.MajorVersion == 12 && vendorParser.MinorVersion < 1))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported SRX version (" + vendorParser.Version + ").\nThis tool supports SRX 12.1 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported SRX version (" + vendorParser.Version + "). This tool supports SRX 12.1 and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;

                case "JuniperSSG":
                    break;

                case "FirePower":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified NGFW version.\nCannot find version for the selected configuration.\nThe configuration may not parse correctly.");
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified NGFW version.\nCannot find version for the selected configuration.\nThe configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 6 || (vendorParser.MajorVersion == 6 && vendorParser.MinorVersion < 4))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported version (" + vendorParser.Version + ").\nThis tool supports NGFW 6.4 and above configuration files.\nThe configuration may not parse correctly.");
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported version(" + vendorParser.Version + ").\nThis tool supports NGFW 6.4 and above configuration files.\nThe configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;

                case "FortiNet":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified FortiGate version.\nCannot find FortiGate version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified FortiGate version. Cannot find FortiGate version for the selected configuration. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 5)
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported FortiGate version (" + vendorParser.Version + ").\nThis tool supports FortiGate 5.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported FortiGate version (" + vendorParser.Version + "). This tool supports FortiGate 5.x and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;
                case "PaloAlto":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified PaloAlto version.\nCannot find PaloAlto PAN-OS version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified PaloAlto version. Cannot find PaloAlto PAN-OS version for the selected configuration. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto PAN-OS 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported PaloAlto version (" + vendorParser.Version + "). This tool supports PaloAlto PAN-OS 7.x and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;
                case "Panorama":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified PaloAlto Panorama version.\nCannot find PaloAlto Panorama version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified PaloAlto Panorama version. Cannot find PaloAlto Panorama version for the selected configuration. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto Panorama 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported PaloAlto version (" + vendorParser.Version + "). This tool supports PaloAlto Panorama 7.x and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
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
                    CiscoConverter converter = new CiscoConverter();
                    converter.SkipUnusedObjects = commandLine.DontImportUnusedObjects;
                    vendorConverter = converter;
                    break;
                case "FirePower":
                    CiscoConverter fpConverter =  new CiscoConverter()
                    {
                        isUsingForFirePower = true
                    };
                    fpConverter.SkipUnusedObjects = commandLine.DontImportUnusedObjects;
                    vendorConverter = fpConverter;
                    break;
                case "JuniperSRX":
                    JuniperConverter juniperConverter = new JuniperConverter();
                    juniperConverter.SkipUnusedObjects = commandLine.DontImportUnusedObjects;
                    vendorConverter = juniperConverter;
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

            vendorConverter.Initialize(vendorParser, commandLine.ConfigFileName, toolVersion, targetFolder, commandLine.Domain, commandLine.formatOutput);
            //if we are in interactive mode
            vendorConverter.IsConsoleRunning = true && _isInteractive;

            try
            {
                Console.WriteLine("Analyze started...");
                float results = vendorConverter.Analyze();

                if (formatOutput.Equals("text"))
                {
                    Console.WriteLine("Analyze finished.");
                    Console.WriteLine("Total Rules: {0}", vendorConverter.TotalRules);
                    Console.WriteLine("Optimization Potential: {0}%", vendorConverter.OptimizationPotential.ToString("0.00"));
                }
                else
                {
                    TotalJsonReportAnalyze jsonReport = new TotalJsonReportAnalyze(
                        msg: "Analyze finished",
                        ttrules: vendorConverter.TotalRules,
                        optPotent: vendorConverter.OptimizationPotential);
                    Console.WriteLine(jsonReport.PrintJson());
                }

            }
            catch (Exception ex)
            {

                if (ex is InvalidDataException && ex.Message != null && ex.Message.Contains("Policy exceeds the maximum number"))
                {
                    if (FormatOutput == "text")
                    {
                        Console.WriteLine(String.Format("{1}{0}{2}{0}{3}", Environment.NewLine, "SmartAnalyze is unable to analyze the provided policy.",
                                                          "Reason: Policy exceeds the maximum number of supported policy layers.",
                                                          "To assure the smooth conversion of your data, it is recommended to contact Check Point Professional Services by sending an e-mail to ps@checkpoint.com"));
                    }
                    else
                    {
                        JsonReport jsonReport = new JsonReport(
                            msg: "SmartAnalyze is unable to analyze the provided policy. Reason: Policy exceeds the maximum number of supported policy layers.",
                            err: "generic_error");
                        Console.WriteLine(jsonReport.PrintJson());
                    }
                }
                else
                {
                    if (FormatOutput == "text")
                        Console.WriteLine("Could not analyze configuration file.", MessageTypes.Error);
                    else
                    {
                        JsonReport jsonReport = new JsonReport(
                            msg: ex.Message,
                            err: "err_cannot_analyze_configuration_file");
                        Console.WriteLine(jsonReport.PrintJson());
                    }
                }
                return;
            }
            finally
            {
                if (vendorConverter.Progress != null)
                    vendorConverter.Progress.Dispose();
            }
        }


        /*
         * This is the analog to MainWindow.Go_OnClick() function if application is run as WPF. 
         * It performs the migration.
         */
        public void DoMigration(CommandLine commandLine)
        {
            if (!_successCommands)
                return;

            string fileName = Path.GetFileNameWithoutExtension(commandLine.ConfigFileName);
            //Console.WriteLine("File name: " + fileName);

            if (string.IsNullOrEmpty(commandLine.ConfigFileName) || string.IsNullOrEmpty(fileName))
            {
                if (FormatOutput == "text")
                    Console.WriteLine("Configuration file is not selected.", MessageTypes.Error);
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Configuration file is not selected.",
                        err: "err_cannot_convert_configuration_file");
                    Console.WriteLine(jsonReport.PrintJson());
                }
                return;
            }

            if (!File.Exists(commandLine.ConfigFileName))
            {
                if (FormatOutput == "text")
                    Console.WriteLine("Cannot find configuration file.", MessageTypes.Error);
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Cannot find configuration file.",
                        err: "err_cannot_convert_configuration_file");
                    Console.WriteLine(jsonReport.PrintJson());
                }
                return;
            }

            if (fileName.Length > 15)
            {
                if (FormatOutput == "text")
                    Console.WriteLine("Configuration file name is restricted to 15 characters at most.", MessageTypes.Error);
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Configuration file name is restricted to 15 characters at most.",
                        err: "err_cannot_convert_configuration_file");
                    Console.WriteLine(jsonReport.PrintJson());
                }
                return;
            }

            if (!Directory.Exists(commandLine.TargetFolder))
            {
                if (FormatOutput == "text")
                    Console.WriteLine("Cannot find target folder for conversion output.", MessageTypes.Error);
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Cannot find target folder for conversion output.",
                        err: "err_cannot_convert_configuration_file");
                    Console.WriteLine(jsonReport.PrintJson());
                }
                return;
            }

            VendorParser vendorParser;

            switch (commandLine.Vendor)
            {
                case "CiscoASA":
                    CiscoParser.SpreadAclRemarks = _isOptimizeByComments;
                    RuleBaseOptimizer.IsOptimizeByComments = _isOptimizeByComments;
                    CiscoParser.SpreadAclRemarks = _isOptimizeByComments ? true : _isCiscoSpreadAclRemarks;
                    vendorParser = new CiscoParser();
                    break;
                case "FirePower":
                    CiscoParser.SpreadAclRemarks = _isOptimizeByComments;
                    RuleBaseOptimizer.IsOptimizeByComments = _isOptimizeByComments;
                    CiscoParser.SpreadAclRemarks = _isOptimizeByComments ? true : _isCiscoSpreadAclRemarks;
                    vendorParser = new CiscoParser()
                    {
                        isUsingForFirePower = true
                    };
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
                Console.Write("Parsing configuration file...");

                if (commandLine.Vendor.Equals("Panorama"))
                {
                    
                    PanoramaParser panParser = (PanoramaParser)vendorParser;
                    panParser.ParseWithTargetFolder(ciscoFile, Path.GetFullPath(TargetFolder));
                }
                else
                {
                    vendorParser.Parse(ciscoFile);
                }

                Console.WriteLine("Done.");

            }
#pragma warning disable CS0168 // The variable 'ex' is declared but never used
            catch (Exception ex)
#pragma warning restore CS0168 // The variable 'ex' is declared but never used
            {
                if (FormatOutput == "text")
                {
                    Console.WriteLine("\nCould not parse configuration file.", MessageTypes.Error);
                    return;
                }
                else
                {
                    JsonReport jsonReport = new JsonReport(
                        msg: "Could not parse configuration file.",
                        err: "err_cannot_parse_configuration_file");
                    Console.WriteLine("\n" + jsonReport.PrintJson());
                    return;
                }
            }

            #region check middleware version
            switch (commandLine.Vendor)
            {
                case "CiscoASA":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified ASA version.\nCannot find ASA version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified ASA version. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 8 || (vendorParser.MajorVersion == 8 && vendorParser.MinorVersion < 3))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported ASA version (" + vendorParser.Version + "). This tool supports ASA 8.3 and above configuration files. The configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported ASA version (" + vendorParser.Version + "). This tool supports ASA 8.3 and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;

                case "JuniperSRX":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified SRX version.\nCannot find SRX version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified SRX version. Cannot find SRX version for the selected configuration. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 12 || (vendorParser.MajorVersion == 12 && vendorParser.MinorVersion < 1))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported SRX version (" + vendorParser.Version + ").\nThis tool supports SRX 12.1 and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported SRX version (" + vendorParser.Version + "). This tool supports SRX 12.1 and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;

                case "JuniperSSG":
                    break;
                
                case "FirePower":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified NGFW version.\nCannot find version for the selected configuration.\nThe configuration may not parse correctly.");
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified NGFW version.\nCannot find version for the selected configuration.\nThe configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 6 || (vendorParser.MajorVersion == 6 && vendorParser.MinorVersion < 4))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported version (" + vendorParser.Version + ").\nThis tool supports NGFW 6.4 and above configuration files.\nThe configuration may not parse correctly.");
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported version(" + vendorParser.Version + ").\nThis tool supports NGFW 6.4 and above configuration files.\nThe configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;

                case "FortiNet":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified FortiGate version.\nCannot find FortiGate version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified FortiGate version. Cannot find FortiGate version for the selected configuration. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 5)
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported FortiGate version (" + vendorParser.Version + ").\nThis tool supports FortiGate 5.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported FortiGate version (" + vendorParser.Version + "). This tool supports FortiGate 5.x and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;
                case "PaloAlto":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified PaloAlto version.\nCannot find PaloAlto PAN-OS version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified PaloAlto version. Cannot find PaloAlto PAN-OS version for the selected configuration. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto PAN-OS 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported PaloAlto version (" + vendorParser.Version + "). This tool supports PaloAlto PAN-OS 7.x and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    break;
                case "Panorama":
                    if (string.IsNullOrEmpty(vendorParser.Version))
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unspecified PaloAlto Panorama version.\nCannot find PaloAlto Panorama version for the selected configuration.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unspecified PaloAlto Panorama version. Cannot find PaloAlto Panorama version for the selected configuration. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
                        return;
                    }
                    else if (vendorParser.MajorVersion < 7)
                    {
                        if (FormatOutput == "text")
                            Console.WriteLine("Unsupported PaloAlto version (" + vendorParser.Version + ").\nThis tool supports PaloAlto Panorama 7.x and above configuration files.\nThe configuration may not parse correctly.", MessageTypes.Warning);
                        else
                        {
                            JsonReport jsonReport = new JsonReport(
                                msg: "Unsupported PaloAlto version (" + vendorParser.Version + "). This tool supports PaloAlto Panorama 7.x and above configuration files. The configuration may not parse correctly.", err: "err_unsupported_version_configuration_file");
                            Console.WriteLine(jsonReport.PrintJson());
                        }
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
                    CiscoConverter converter = new CiscoConverter();
                    converter.SkipUnusedObjects = commandLine.DontImportUnusedObjects;
                    vendorConverter = converter;
                    break;
                case "FirePower":
                    vendorConverter = new CiscoConverter()
                    {
                        isUsingForFirePower = true,
                        SkipUnusedObjects = commandLine.DontImportUnusedObjects
                    };
                    break;
                case "JuniperSRX":
                    JuniperConverter juniperConverter = new JuniperConverter();
                    juniperConverter.SkipUnusedObjects = commandLine.DontImportUnusedObjects;
                    vendorConverter = juniperConverter;
                    break;
                case "JuniperSSG":
                    ScreenOSConverter screenOSConverter = new ScreenOSConverter();
                    screenOSConverter.SkipUnusedObjects = commandLine.DontImportUnusedObjects;
                    vendorConverter = screenOSConverter;
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

            vendorConverter.Initialize(vendorParser, commandLine.ConfigFileName, toolVersion, targetFolder, commandLine.Domain, commandLine.formatOutput);
            //if we are in interactive mode
            vendorConverter.IsConsoleRunning = true && _isInteractive;

            try
            {
                Console.WriteLine("Conversion started...");
                Dictionary<string, int> results = vendorConverter.Convert(convertNat);

                if (formatOutput.Equals("text"))
                {
                    Console.WriteLine("Conversion finished.");
                    if (results.ContainsKey("errors"))
                        Console.WriteLine("Errors: {0}", results["errors"]);
                    if (results.ContainsKey("warnings"))
                        Console.WriteLine("Warnings: {0}", results["warnings"]);
                }
                else
                {
                    TotalJsonReport jsonReport = new TotalJsonReport(
                        msg: "Conversion finished",
                        errs: results.ContainsKey("errors") ? results["errors"].ToString() : null,
                        warnings: results.ContainsKey("warnings") ? results["warnings"].ToString() : null);
                    Console.WriteLine(jsonReport.PrintJson());
                }

            }
            catch (Exception ex)
            {

                if (ex is InvalidDataException && ex.Message != null && ex.Message.Contains("Policy exceeds the maximum number"))
                {
                    if (FormatOutput == "text")
                    {
                        Console.WriteLine(String.Format("{1}{0}{2}{0}{3}", Environment.NewLine, "SmartMove is unable to convert the provided policy.",
                                                          "Reason: Policy exceeds the maximum number of supported policy layers.",
                                                          "To assure the smooth conversion of your data, it is recommended to contact Check Point Professional Services by sending an e-mail to ps@checkpoint.com"));
                    }
                    else
                    {
                        JsonReport jsonReport = new JsonReport(
                            msg: "SmartMove is unable to convert the provided policy. Reason: Policy exceeds the maximum number of supported policy layers.",
                            err: "generic_error");
                        Console.WriteLine(jsonReport.PrintJson());
                    }
                }
                else
                {
                    if (FormatOutput == "text")
                        Console.WriteLine("Could not convert configuration file.", MessageTypes.Error);
                    else
                    {
                        JsonReport jsonReport = new JsonReport(
                            msg: "Could not convert configuration file.",
                            err: "err_cannot_convert_configuration_file");
                        Console.WriteLine(jsonReport.PrintJson());
                    }
                }
                return;
            }
            finally
            {
                if (vendorConverter.Progress != null)
                    vendorConverter.Progress.Dispose();
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
