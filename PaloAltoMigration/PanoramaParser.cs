using MigrationBase;
using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Serialization;

namespace PanoramaPaloAltoMigration

{
    public class PanoramaParser : VendorParser
    {
        private static string _archiveName;
        public string _ArchiveName
        {
            get { return _archiveName; }
            set { _archiveName = value; }
        }

        public Panorama_Config Config { get; set; }

        public override void Export(string filename)
        {            
        }

        public override void Parse(string filename)
        {

        }
        
        public void ParseWithTargetFolder(string filename, string targetFolder)
        {
            if (!targetFolder.EndsWith("\\"))
                targetFolder += "\\";
            UncompressArchive(filename,targetFolder);            
            
            string outConfigsFolder = targetFolder + "configs";
            _ArchiveName = outConfigsFolder;
            string panoramaConfig = GetPanoramaConfFile(outConfigsFolder);
           
            XmlSerializer serializer = new XmlSerializer(typeof(Panorama_Config));

            using (FileStream fileStream = new FileStream(panoramaConfig, FileMode.Open))
            {
                Config = (Panorama_Config)serializer.Deserialize(fileStream);

                ParseVersion(null);
            }
        }

        protected override void ParseVersion(object versionProvider)
        {
            VendorVersion = Config.Version;
        }

        public string GetPanoramaConfFile(string outConfigsFolder)
        {            
            string panoramaConfig = null;            

            string[] configsFolder = Directory.GetDirectories(outConfigsFolder);//get uncompressed folder name 
            string[] configFilesArray = Directory.GetFiles(configsFolder[0]);//get list of panorama and firewalls config files

            foreach (string confFile in configFilesArray)
            {
                if (DetectPanoramaConfFile(confFile))
                {
                    panoramaConfig = confFile;                    
                    break;
                }
            }
            return panoramaConfig;
        }

        public bool DetectPanoramaConfFile(string fileName)
        {
            bool is_panorama = false;
            XmlDocument xDoc = new XmlDocument();
            try
            {
                xDoc.Load(fileName);
                XmlElement xRoot = xDoc.DocumentElement;
                XmlNode panoramaNode = xRoot.SelectSingleNode("panorama");
                if (panoramaNode != null)
                    is_panorama = true;
            }
            catch { }
            return is_panorama;
        }

        /// <summary>
        /// //checks if Panorama or standalone PA firewall configuration is converted
        /// </summary>        
        public bool CheckPaloAltoConfiguartion(String filename)
        {
            bool is_panorama = false;            
            List<string> archiveExt = new List<string> { ".tgz" };

            string extension = Path.GetExtension(filename);
            
            if (archiveExt.Contains(extension))
            {
                is_panorama = true;
            }
            else
            {
                Console.WriteLine("Configs archive must be in .tgz format!");                
            }            
            return is_panorama;
        }

        public void UncompressArchive(string archiveName, string targetFolder)
        {
            string compressorsDirPath = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar + "compressors";            
            string archiveCopyName = targetFolder + archiveName.Substring(archiveName.LastIndexOf("\\") + 1);
            archiveCopyName = archiveCopyName.Substring(0, archiveCopyName.IndexOf(".tgz")) + "_copy" + ".tgz";            
            File.Copy(archiveName, archiveCopyName, true);            

            #region uncompress .TGZ archive 
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            Process uncompressProc = null;
            startInfo.FileName = Path.Combine(compressorsDirPath, "gzip.exe");            
            startInfo.WorkingDirectory = archiveCopyName.Substring(0, archiveCopyName.LastIndexOf("\\"));
            startInfo.Arguments = "-d" + " \"" + archiveCopyName + "\"";
            startInfo.RedirectStandardOutput = true;
            uncompressProc = Process.Start(startInfo);
            startInfo.RedirectStandardError = true;            

            string output = uncompressProc.StandardOutput.ReadToEnd();
            uncompressProc.WaitForExit();            
            #endregion

            #region uncompress .TAR archive
            startInfo = new ProcessStartInfo();
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            Process uncompressTarProc = null;
            startInfo = new ProcessStartInfo();
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;

            string tarArchiveName = archiveCopyName.Substring(0, archiveCopyName.LastIndexOf(".tgz")) + ".tar";
            
            startInfo.FileName = Path.Combine(compressorsDirPath, "gtar.exe");
            
            string outConfigsFolder = tarArchiveName.Substring(0, tarArchiveName.LastIndexOf("\\")) + "\\configs";
            Directory.CreateDirectory(outConfigsFolder);
            startInfo.WorkingDirectory = outConfigsFolder;                     
            startInfo.Arguments = "-xvf \"" + tarArchiveName + "\" --force-local";
            startInfo.RedirectStandardOutput = true;
            uncompressTarProc = Process.Start(startInfo);
            startInfo.RedirectStandardError = true;

            output = uncompressTarProc.StandardOutput.ReadToEnd();
            uncompressTarProc.WaitForExit();

            if (File.Exists(tarArchiveName))
                File.Delete(tarArchiveName);            
            #endregion
        }
    }
}
