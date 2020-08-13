using MigrationBase;
using System.IO;
using System.Xml.Serialization;

namespace PaloAltoMigration
{
    public class PaloAltoParser : VendorParser
    {
        public PA_Config Config { get; set; }

        public override void Export(string filename)
        {            
        }

        public override void Parse(string filename)
        {           

            ParsedLines = File.ReadAllLines(filename).Length;

            XmlSerializer serializer = new XmlSerializer(typeof(PA_Config));

            using (FileStream fileStream = new FileStream(filename, FileMode.Open))
            {
                Config = (PA_Config)serializer.Deserialize(fileStream);

                ParseVersion(null);
            }
        }

        protected override void ParseVersion(object versionProvider)
        {
            VendorVersion = Config.Version;
        }
    }
}
