/********************************************************************
Copyright (c) 2017, Check Point Software Technologies Ltd.
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
********************************************************************/
using CommonUtils;

namespace NetScreenMigration
{
    public interface IServiceProtocolObject
    {
        string Name();

        int Parse(ScreenOSCommand command, int baseParamIndex);
    }

    /// <summary>
    /// Represents a basic ScreenOS SSG service unique type object.
    /// An extension to the service object.
    /// </summary>
    public class ServiceProtocolObject : IServiceProtocolObject
    {
        public enum ProtocolTypeEnum { NA, Ip, Udp, Tcp, Icmp, Ms_rpc, Sun_rpc };

        public ProtocolTypeEnum ProtocolType { get; set; }
        public string Protocol { get; set; }
        public ConversionIncidentType ConversionIncidentType { get; set; }
        public string ConversionIncidentMessage { get; set; }
        public ScreenOSCommand_Service OrigService { get; set; }

        public override string ToString() { return ""; }

        public ServiceProtocolObject()
        {
            ProtocolType = ProtocolTypeEnum.NA;
        }

        public virtual string Name() { return ""; }

        public virtual string ToCheckPointPortInfo() { return ""; }

        public virtual int Parse(ScreenOSCommand command, int baseParamIndex)
        {
            return baseParamIndex;
        }
    }

    public class ServiceProtocolObject_Ip : ServiceProtocolObject
    {
        protected int _srcPortStart;
        protected int _srcPortEnd;
        protected int _destPortStart;
        protected int _destPortEnd;

        protected int SrcPortStart
        {
            get
            {
                if (_srcPortStart == 0)
                {
                    return 1;
                }

                return _srcPortStart;
            }
            set
            {
                _srcPortStart = value;
            }
        }

        protected int SrcPortEnd
        {
            get
            {
                if (_srcPortEnd == 0)
                {
                    return 1;
                }

                return _srcPortEnd;
            }
            set
            {
                _srcPortEnd = value;
            }
        }

        protected int DestPortStart
        {
            get
            {
                if (_destPortStart == 0)
                {
                    return 1;
                }

                return _destPortStart;
            }
            set
            {
                _destPortStart = value;
            }
        }

        protected int DestPortEnd
        {
            get
            {
                if (_destPortEnd == 0)
                {
                    return 1;
                }

                return _destPortEnd;
            }
            set
            {
                _destPortEnd = value;
            }
        }

        public ServiceProtocolObject_Ip()
        {
            SrcPortStart = 0;
            SrcPortEnd = 65535;
            DestPortStart = 0;
            DestPortEnd = 65535;
        }

        public override string Name() { return "ip"; }

        public override string ToString()
        {
            if (Name() != Protocol)
            {
                return Name() + "_" + Protocol;
            }

            return Name() + "_" + PortToString();
        }

        protected string PortToString()
        {
            return SrcPort + "_" + DstPort;
        }

        public string SrcPort
        {
            get
            {
                if (SrcPortStart == 1 && SrcPortEnd == 65535)
                {
                    return "any";
                }

                if (SrcPortStart == SrcPortEnd)
                {
                    return SrcPortStart.ToString();
                }

                return SrcPortStart.ToString() + "-" + SrcPortEnd.ToString();
            }
        }

        public string DstPort
        {
            get
            {
                if (DestPortStart == DestPortEnd)
                {
                    return DestPortStart.ToString();
                }

                return DestPortStart.ToString() + "-" + DestPortEnd.ToString();
            }
            set
            {
                string[] ports = value.Split('-');
                if (ports[0] == "Any")
                {
                    DestPortStart = 1;
                    DestPortEnd = 65535;
                }
                else
                {
                    DestPortStart = int.Parse(ports[0]);
                    if (ports.Length == 1)
                    {
                        DestPortEnd = DestPortStart;
                    }
                    else
                    {
                        DestPortEnd = int.Parse(ports[1]);
                    }
                }
            }
        }

        public override int Parse(ScreenOSCommand command, int baseParamIndex)
        {   
            base.Parse(command, baseParamIndex);

            /* Get Ip protocol id if exist*/
            ProtocolType = ProtocolTypeEnum.Ip;
            Protocol = command.GetParam(baseParamIndex);
            baseParamIndex++;

            /* Source port range*/
            if (command.GetParam(baseParamIndex) == "src-port")
            {
                string[] stringCommand = command.GetParam(baseParamIndex + 1).Split('-');
                SrcPortStart = int.Parse(stringCommand[0]);
                SrcPortEnd = int.Parse(stringCommand[1]);
            }

            /* Destination port range*/
            if (command.GetParam(baseParamIndex + 2) == "dst-port")
            {
                string[] stringCommand = command.GetParam(baseParamIndex + 3).Split('-');
                DestPortStart = int.Parse(stringCommand[0]);
                DestPortEnd = int.Parse(stringCommand[1]);
            }

            return baseParamIndex + 4;
        }

        public override string ToCheckPointPortInfo() { return Name().ToUpper() + "_" + DstPort; }

    }

    public class ServiceProtocolObject_Udp : ServiceProtocolObject_Ip
    {
        public override string Name() { return "udp"; }

        public override int Parse(ScreenOSCommand command, int baseParamIndex)
        {
            int index =  base.Parse(command, baseParamIndex);
            ProtocolType = ProtocolTypeEnum.Udp;

            if (SrcPort != "any")
            {
                ConversionIncidentMessage = "ScreenOS service object with source port other then Any will not be considered during migration. Check Point service object is not supporting source port";
            }

            if (_destPortStart == 0)
            {
                string errorString = "ScreenOS service object with destination port 0 is not valid in Check Point. Modifying port to 1";
                ConversionIncidentMessage += string.IsNullOrEmpty(ConversionIncidentMessage) == false ?
                        "\n" + errorString :
                        errorString;
            }

            return index;
        }
    }

    public class ServiceProtocolObject_Tcp : ServiceProtocolObject_Ip
    {
        public override string Name() { return "tcp"; }

        public override int Parse(ScreenOSCommand command, int baseParamIndex)
        {
            int index = base.Parse(command, baseParamIndex);
            ProtocolType = ProtocolTypeEnum.Tcp;

            if (SrcPort != "any")
            {
                ConversionIncidentMessage = "ScreenOS service object with source port other then Any will not be considered during migration. Check Point service object is not supporting source port";
            }

            if (_destPortStart == 0)
            {
                string errorString = "ScreenOS service object with destination port 0 is not valid in Check Point. Modifying port to 1";
                ConversionIncidentMessage += string.IsNullOrEmpty(ConversionIncidentMessage) == false ?
                        "\n" + errorString :
                        errorString;
            }

            return index;
        }
    }

    public class ServiceProtocolObject_Icmp : ServiceProtocolObject
    {
        public byte IcmpType { get; set; }
        public byte IcmpCode { get; set; }

        public ServiceProtocolObject_Icmp()
        {
            IcmpType = 0;
            IcmpCode = 0;
        }

        public override string Name() { return "icmp"; }

        public override string ToString()
        {
            return Name() + "_T" + IcmpType.ToString() + "_C" + IcmpCode.ToString();
        }

        public override int Parse(ScreenOSCommand command, int baseParamIndex)
        {
            base.Parse(command, baseParamIndex);

            ProtocolType = ProtocolTypeEnum.Icmp;
            Protocol = command.GetParam(baseParamIndex);
            baseParamIndex++;

            /* Type*/
            if (command.GetParam(baseParamIndex) == "type")
            {
                IcmpType = byte.Parse(command.GetParam(baseParamIndex + 1));
            }
            
            /* Code*/
            if (command.GetParam(baseParamIndex + 2) == "code")
            {
                IcmpCode = byte.Parse(command.GetParam(baseParamIndex + 3));
            }

            return baseParamIndex + 4;
        }

        public override string ToCheckPointPortInfo()
        {
            if (IcmpCode != 0)
            {
                return ToString();
            }

            return Name().ToUpper() + "_" + IcmpType.ToString() + "_" + IcmpCode.ToString();
        }
    }

    public class ServiceProtocolObject_MsRPC : ServiceProtocolObject
    {
        public string Uuid { get; set; }

        public ServiceProtocolObject_MsRPC()
        {
            Uuid = "";
        }

        public override string Name() { return "ms-rpc"; }

        public override string ToString()
        {
            return Name() + "_U" + Uuid;
        }

        public override int Parse(ScreenOSCommand command, int baseParamIndex)
        {
            base.Parse(command, baseParamIndex);

            Protocol = command.GetParam(baseParamIndex);
            ProtocolType = ProtocolTypeEnum.Ms_rpc;
            baseParamIndex++;

            if (command.GetParam(baseParamIndex) == "uuid")
            {
                Uuid = command.GetParam(baseParamIndex + 1);
            }

            return baseParamIndex + 2;
        }

        public override string ToCheckPointPortInfo(){ return Name().ToUpper() + "_" + Uuid;}
    }

    public class ServiceProtocolObject_SunRPC : ServiceProtocolObject
    {
        public string ProgramStart { get; set; }
        public string ProgramEnd { get; set; }

        private readonly int _minProgram = 100000;
        private readonly int _maxProgram = 1410065407;

        public ServiceProtocolObject_SunRPC()
        {
            ProgramStart = "";
            ProgramEnd = "";
        }

        public override string Name() { return "sun-rpc"; }

        public override string ToString()
        {
            return Name() + "_P" + Program;
        }

        public string Program
        {
            get
            {
                return ProgramStart;
            }
            set
            {
                string []programValue = value.Split('-');
                ProgramStart = programValue[0];
                if (programValue.Length == 1)
                {
                    ProgramEnd = ProgramStart;
                }
                else
                {
                    ProgramEnd = programValue[1];
                }
            }
        }

        public override int Parse(ScreenOSCommand command, int baseParamIndex)
        {
            base.Parse(command, baseParamIndex);

            Protocol = command.GetParam(baseParamIndex);
            ProtocolType = ProtocolTypeEnum.Sun_rpc;
            baseParamIndex++;

            if (command.GetParam(baseParamIndex) == "program")
            {
                string[] commandString = command.GetParam(baseParamIndex + 1).Split('-');
                if (commandString.Length == 2)
                {
                    ProgramStart = commandString[0];
                    if (int.Parse(ProgramStart) < _minProgram)
                    {
                        ProgramStart = _minProgram.ToString();
                    }
                    ProgramEnd = commandString[1];
                    if (int.Parse(ProgramEnd) > _maxProgram)
                    {
                        ProgramEnd = _maxProgram.ToString();
                    }

                    if(ProgramStart != ProgramEnd)
                    {
                        ConversionIncidentMessage = "ScreenOS SUN-RPC service object with program range is not supported in Check Point. Using only first program number in range";
                    }
                }
            }

            return baseParamIndex + 2;
        }

        public override string ToCheckPointPortInfo() { return Name().ToUpper() + "_" + Program; }
    }
}
