using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;
using MigrationBase;
using System.Text;

namespace FortiGateMigration
{
    public class FortiGateParser : VendorParser
    {
        private List<FgCommand> _fgCommandsList;

        public List<FgCommand> FgCommandsList
        {
            get { return _fgCommandsList; }
        }

        public FortiGateParser()
        {
            _fgCommandsList = new List<FgCommand>();
        }
        
        #region Override Methods

        protected override void ParseVersion(object versionProvider)
        {
            string versionLine = versionProvider.ToString();

            int indVersionDash = versionLine.IndexOf("-", "#config-version=".Length) + 1; //add 1 because we need to cut w/o colon

            VendorVersion = versionLine.Substring(indVersionDash, versionLine.IndexOf(":") - indVersionDash);
        }

        public override void Parse(string filename)
        {
            ParseCommands(filename);
        }

        public override void Export(string filename)
        {
            File.WriteAllText(filename, JsonConvert.SerializeObject(_fgCommandsList, Formatting.Indented));
        }

        #endregion

        private void ParseCommands(string filename)
        {
            string[] linesCfg = File.ReadAllLines(filename, Encoding.GetEncoding("us-ascii", new EncoderReplacementFallback(""), new DecoderReplacementFallback("")));

            Stack<FgCommandExt> stackFgCommands = new Stack<FgCommandExt>();

            FgCommandExt fgCommandExtC = null;

            int countOpenedConfig = 0;

            foreach (string lineCfg in linesCfg)
            {
                ParsedLines += 1;

                string line = lineCfg.Trim();

                // Check for an empty line or line with just spaces.
                if (line.Trim().Length == 0)
                {
                    continue;
                }

                // Check for weird stuff
                if (line.StartsWith("#"))
                {
                    if(line.StartsWith("#config-version=") && line.Contains(":"))
                    {
                        ParseVersion(line);
                    }
                    continue;
                }

                string commandName = "";
                string commandArgs = "";
                if (line.IndexOf(" ") != -1)
                {
                    commandName = line.Substring(0, line.IndexOf(" ")).Trim();
                    commandArgs = line.Substring(line.IndexOf(" ")).Trim();
                }
                else
                {
                    commandName = line;
                }

                FgCommandExt fgCommandExtT = null;

                switch (commandName)
                {
                    case "config":
                        countOpenedConfig += 1;

                        if (fgCommandExtC != null)
                        {
                            stackFgCommands.Push(fgCommandExtC);
                        }
                        fgCommandExtC = new FgCommand_Config(commandArgs);
                        break;
                    case "edit":
                        stackFgCommands.Push(fgCommandExtC);
                        fgCommandExtC = new FgCommand_Edit(commandArgs);
                        break;
                    case "set":
                        fgCommandExtC.addSubCommandToList(new FgCommand_Set(commandArgs));
                        break;
                    case "unset":
                        fgCommandExtC.addSubCommandToList(new FgCommand_UnSet(commandArgs));
                        break;
                    case "next":
                        fgCommandExtT = stackFgCommands.Pop();
                        fgCommandExtT.addSubCommandToList(fgCommandExtC);
                        fgCommandExtC = fgCommandExtT;
                        fgCommandExtT = null;
                        break;
                    case "end":
                        countOpenedConfig -= 1;

                        if (stackFgCommands.Count == 0)
                        {
                            if (fgCommandExtC != null)
                            {
                                _fgCommandsList.Add(fgCommandExtC);
                            }
                            fgCommandExtC = null;
                        }
                        else
                        {
                            if (countOpenedConfig == 0)
                            {
                                foreach (FgCommandExt fgCommandExtTS in stackFgCommands)
                                {
                                    fgCommandExtTS.addSubCommandToList(fgCommandExtC);
                                    fgCommandExtC = fgCommandExtTS;
                                }

                                stackFgCommands.Clear();

                                _fgCommandsList.Add(fgCommandExtC);

                                fgCommandExtC = null;
                            }
                            else
                            {
                                fgCommandExtT = stackFgCommands.Pop();
                                fgCommandExtT.addSubCommandToList(fgCommandExtC);
                                fgCommandExtC = fgCommandExtT;
                                fgCommandExtT = null;
                            }
                        }
                        break;
                }
            }
        }
    }
}
