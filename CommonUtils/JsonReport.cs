using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;

namespace CommonUtils
{
    [DataContract]
    public class JsonReport
    {
        [DataMember]
        public string msg { get; set; }
        
        [DataMember(EmitDefaultValue = false)]
        public string warning { get; set; }
        
        [DataMember(EmitDefaultValue = false)]
        public string error { get; set; }



        public JsonReport() {}
        public JsonReport (string msg, string err = null, string warning = null) : this()
        {
            this.msg = msg;
            if (err != null)
                error = err;
            if (warning != null)
                this.warning = warning;
        }

        public string PrintJson()
        {
            var ms = new MemoryStream();
            var ser = new DataContractJsonSerializer(typeof(JsonReport));
            ser.WriteObject(ms, this);
            ms.Position = 0;
            var sr = new StreamReader(ms);
            return sr.ReadToEnd();
        }
    }

    [DataContract]
    public class TotalJsonReport
    {
        [DataMember]
        public string msg { get; set; }
        //total count at the finish
        [DataMember]
        public int warnings { get; set; }
        [DataMember]
        public int errors { get; set; }

        public TotalJsonReport() {
            errors = 0;
            warnings = 0;
        }
        public TotalJsonReport(string msg, string errs, string warnings) : this()
        {
            this.msg = msg;
            int errsCount = int.Parse(errs);
            int warnCount = int.Parse(warnings);
            if (errsCount > 0)
                errors = errsCount;
            if (warnCount > 0)
                this.warnings = warnCount;
        }

        public string PrintJson()
        {
            var ms = new MemoryStream();
            var ser = new DataContractJsonSerializer(typeof(TotalJsonReport));
            ser.WriteObject(ms, this);
            ms.Position = 0;
            var sr = new StreamReader(ms);
            return sr.ReadToEnd();
        }
    }
}
