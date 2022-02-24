using MigrationBase;
using System;
using System.IO;
using System.Text;
using System.Xml.Serialization;

namespace PaloAltoMigration
{
    public class PaloAltoParser : VendorParser
    {

        public PA_Config Config { get; set; }

        public override void Export(string filename)
        {
            Console.WriteLine("EXPORT");
        }

        public override void Parse(string filename)
        {
            Console.WriteLine("PARSE : " + filename);

            ParsedLines = File.ReadAllLines(filename, Encoding.GetEncoding("us-ascii", new EncoderReplacementFallback(""), new DecoderReplacementFallback(""))).Length;

            XmlSerializer serializer = new XmlSerializer(typeof(PA_Config));

            using (FileStream fileStream = new FileStream(filename, FileMode.Open))
            {
                using (StreamReader sr = new StreamReader(fileStream, Encoding.GetEncoding("us-ascii", new EncoderReplacementFallback(""), new DecoderReplacementFallback(""))))
                {
                    Config = (PA_Config)serializer.Deserialize(sr);

                    ParseVersion(null);
                }
            }
        }

        protected override void ParseVersion(object versionProvider)
        {
            VendorVersion = Config.Version;
        }
    }
}
