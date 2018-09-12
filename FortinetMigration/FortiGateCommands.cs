using System.Collections.Generic;

namespace FortiGateMigration
{

    public abstract class FgCommand
    {
        public string Name { get; set; }

        public FgCommand(string name)
        {
            Name = name;
        }
    }

    public abstract class FgCommandExt : FgCommand
    {
        public List<FgCommand> SubCommandsList { get; set; }

        public FgCommandExt(string name) : base(name)
        {
            SubCommandsList = new List<FgCommand>();
        }

        public void addSubCommandToList(FgCommand fgCommand)
        {
            SubCommandsList.Add(fgCommand);
        }
    }

    public class FgCommand_Config : FgCommandExt
    {
        public string ObjectName { get; set; }

        public FgCommand_Config(string objectName) : base("config")
        {
            ObjectName = objectName;
        }
    }

    public class FgCommand_Edit : FgCommandExt
    {
        public string Table { get; set; }

        public FgCommand_Edit(string tableName) : base("edit")
        {
            Table = tableName.Trim('"');
        }
    }

    public class FgCommand_Set : FgCommand
    {
        public string Field { get; set; }

        public string Value { get; set; }

        public FgCommand_Set(string args) : base("set")
        {
            if (args.IndexOf(" ") != -1)
            {
                Field = args.Substring(0, args.IndexOf(" "));
                Value = args.Substring(args.IndexOf(" ")).Trim();
                Value = Value.Trim('"');
            }
            else
            {
                Field = args;
                Value = "";
            }
        }
    }

    public class FgCommand_UnSet : FgCommand
    {
        public string Field { get; set; }

        public string Value { get; set; }

        public FgCommand_UnSet(string args) : base("unset")
        {
            if (args.IndexOf(" ") != -1)
            {
                Field = args.Substring(0, args.IndexOf(" "));
                Value = args.Substring(args.IndexOf(" ")).Trim();
                Value = Value.Trim('"');
            }
            else
            {
                Field = args;
                Value = "";
            }
        }
    }
}
