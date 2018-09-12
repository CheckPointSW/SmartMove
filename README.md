# SmartMove
Check Point SmartMove tool enables you to convert 3rd party database with firewall security policy and NAT to Check Point database.

At the moment, the tool parses Cisco ASA, Juniper JunosOS/ScreenOS, and Fortinet FortiOS configurations and converts its objects, NAT and firewall policy to a Check Point R80.10 compliant policy. The tool is planned to support additional vendors and security configurations in the future.

The tool generates bash scripts by utilizing Check Point Management API's command line interface, to migrate the converted policy into a R80.10 Management (or Multi-Domain) server.

For SmartMove tool release notes and latest updates, please refer to Check Point sk115416 at:
https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk115416

## Development Environment
The tool is developed using Microsoft C# language and .Net framework version 4.5 (WPF application). The project solution file is configured for Microsoft Visual Studio 2012 and above.
