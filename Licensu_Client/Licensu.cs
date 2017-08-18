using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace Licensu
{

    class HWID
    {
        bool IsServer { get; set; }
        string BIOS { get; set; }
        string CPU { get; set; }
        string HDD { get; set; }
        string GPU { get; set; }
        string MAC { get; set; }
        string HardwareID { get; set; }
        string OS { get; set; }
        string SCSI { get; set; }

        public HWID()
        {
            BIOS = GetWMIIdent("Win32_BIOS", "Manufacturer", "SMBIOSBIOSVersion", "IdentificationCode");
            CPU = GetWMIIdent("Win32_Processor", "ProcessorId", "UniqueId", "Name");
            HDD = GetWMIIdent("Win32_DiskDrive", "Model", "TotalHeads");
            GPU = GetWMIIdent("Win32_VideoController", "DriverVersion", "Name");
            MAC = GetWMIIdent("Win32_NetworkAdapterConfiguration", "MACAddress");
            OS = GetWMIIdent("Win32_OperatingSystem", "SerialNumber", "Name");
            SCSI = GetWMIIdent("Win32_SCSIController", "DeviceID", "Name");

            // checking if system is a server. scsi indicates a server system
            IsServer = HDD.Contains("SCSI");

            HardwareID = Build();
        }

        private string Build()
        {
            string tmp = string.Concat(BIOS, CPU, HDD, GPU, MAC, SCSI);

            if (tmp == null)
                Debugger.WriteLog("Could not resolve hardware informations...");

            return Convert.ToBase64String(new SHA1CryptoServiceProvider().ComputeHash(Encoding.Default.GetBytes(tmp)));
        }

        private bool IsWinServer()
            => OS.Contains("Microsoft Windows Server");

        public string GetHWID()
        {
            return (HardwareID == null ? Build() : HardwareID);
        }

        private static string GetWMIIdent(string Class, string Property)
        {
            string ident = "";
            var objCol = new ManagementClass(Class).GetInstances();
            foreach (var obj in objCol)
            {
                if ((ident = obj.GetPropertyValue(Property) as string) != "")
                    break;
            }
            return ident;
        }

        private static string GetWMIIdent(string Class, params string[] Propertys)
        {
            string ident = "";
            Array.ForEach(Propertys, prop => ident += GetWMIIdent(Class, prop) + " ");
            return ident;
        }

        public static string Get()
            => new HWID().HardwareID;
    }
    public static class Debugger
    {
        public static bool traceAll = false;
        public static bool consoleDebug = true;
        public static string miscPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\licensu\\";
        private static string logFile = "trace.log";
        public static void WriteLog(string log)
        {
            if (consoleDebug)
                Console.WriteLine(log);
            if (!traceAll) return;
            if (!Directory.Exists(miscPath))
                Directory.CreateDirectory(miscPath);
            if (!File.Exists(miscPath + logFile))
                File.WriteAllText(miscPath + logFile, "");
            File.AppendAllText(miscPath + logFile, log + Environment.NewLine);
        }
    }
    abstract class iNotifAuth
    {
        public static Action<byte[]> remoteVariable { get; set; }
        public static event EventHandler<PropertyChangedEventArgs> StaticPropertyChanged = delegate { };
        private static void NotifyStaticPropertyChanged(string propertyName)
        {
            StaticPropertyChanged(null, new PropertyChangedEventArgs(propertyName));
        }
        private static string status;
        public static string Status
        {
            get { return status; }
            set
            {
                status = value;
                NotifyStaticPropertyChanged("Status");
            }
        }
    }
    class Crypto
    {
        //cert paths
        public static string ClientCertificateFile { get; set; }
        public static string CACertificateFile { get; set; }

        private readonly string ClientCertificatePassword = "testclient"; //"test2";
        private TcpClient client { get; set; }
        private SslStream sslStream { get; set; }
        private enum EnumAnswers
        {
            KEY_UPDATE = 232,
            NOT_FOUD = 321,
            EXPIRED_LICENSE = 144,
            BANNED = 242,
            UPDATE = 69,
            PLUGIN_LIST = 3141,
            PLUGIN_DATA = 3562,
            PLUGIN_NO_ACCESS = 48879,
            DATA_EOF = 195894762,
            DONE_PROCESSING = 57005,
            INTERNAL_ERROR = 194,
        }


        public X509CertificateCollection clientCertificateCollection { get; set; }
        public string hwid { get; set; }
        public string key { get; set; }

        public Crypto()
        {


        }
        private void importCertificate()
        {
            foreach (X509Certificate2 cert in clientCertificateCollection)
            {
                if (cert.Thumbprint != "03A52E361DDEB731C3955EC926F459501CE665ED")
                    clientCertificateCollection.Remove(cert);
            }
        }
        public bool addCertificates()
        {
            try
            {
                X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                clientCertificateCollection = store.Certificates.Find(X509FindType.FindByIssuerName, "127.0.0.1", false);
                if (clientCertificateCollection.Count >= 2)
                {
                    bool[] found = { false, false };
                    foreach (X509Certificate2 cert in clientCertificateCollection)
                    {
                        if (cert.Thumbprint == "03A52E361DDEB731C3955EC926F459501CE665ED")
                            found[0] = true;
                        if (cert.Thumbprint == "A068FD4C9523DDDEE87F5B3985DE69FB63FB186E")
                            found[1] = true;
                    }
                    if (found[0] && found[1])
                    {
                        importCertificate();
                        return true;
                    }

                }
                clientCertificateCollection.Add(new X509Certificate2(CACertificateFile));
                clientCertificateCollection.Add(new X509Certificate2(ClientCertificateFile, ClientCertificatePassword));
                foreach (X509Certificate2 cer in clientCertificateCollection)
                {
                    //add to the appropriate store
                    store.Add(cer);
                }
                store.Close();
                importCertificate();
                return true;
            }
            catch (Exception ex)
            {
                Debugger.WriteLog(ex.Message);
                return false;
            }

        }
        public string getHWID()
        {
            return (hwid == null) ? hwid = new HWID().GetHWID() : hwid;
        }
        public void sslClient(string ServerHostName, int ServerPort, string programID, Task currentTask, CancellationTokenSource cts)
        {
            if (client == null) client = new TcpClient();
            client.Connect(ServerHostName, ServerPort);
            if (sslStream == null) sslStream = new SslStream(client.GetStream(), false, App_CertificateValidation, SelectLocalCertificate);
            sslStream.AuthenticateAsClient(ServerHostName, clientCertificateCollection, SslProtocols.Tls12, true);

            Debugger.WriteLog("SSL authentication completed.");
            Debugger.WriteLog(string.Format("SSL using local certificate {0}.", sslStream.LocalCertificate.Subject));
            Debugger.WriteLog(string.Format("SSL using remote certificate {0}.", sslStream.RemoteCertificate.Subject));

            // Send handshake
            byte[] outputBuffer = buildClientPacket(programID);
            sslStream.Write(outputBuffer);
            sslStream.Flush();

            // Task of loop
            List<byte> messageBytes = new List<byte>();

            currentTask = Task.Run(async () =>
            {
                int inputBytes = -1;
                byte[] inputBuffer = new byte[2048];
                while (inputBytes != 0)
                {
                    inputBytes = await sslStream.ReadAsync(inputBuffer, 0, inputBuffer.Length);
                    ArraySegment<byte> incomingBuffer = new ArraySegment<byte>(inputBuffer, 0, inputBytes);
                    if (!Enumerable.SequenceEqual(incomingBuffer, outputBuffer))
                        messageBytes.AddRange(incomingBuffer);
                }
            }, cts.Token).ContinueWith(task =>
            {
                // do treat the data
                processMessage(Encoding.UTF8.GetString(messageBytes.ToArray()));

                switch (task.Status)
                {
                    // Handle any exceptions to prevent UnobservedTaskException.
                    case TaskStatus.Canceled:
                        Debugger.WriteLog("TASK GOT CANCELLED");
                        break;
                    case TaskStatus.Faulted:
                        Debugger.WriteLog(task.Exception.Message);
                        break;
                    case TaskStatus.RanToCompletion:
                        Debugger.WriteLog("TASK FINISHED ?!");
                        break;
                }
            });
        }
        // This can be emulated.
        private string computeMD5()
        {
            FileStream buffer = File.Open(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            using (var cryptoProvider = new SHA1CryptoServiceProvider())
                return BitConverter
                        .ToString(cryptoProvider.ComputeHash(buffer));
        }
        private byte[] buildClientPacket(string programID)
        {
            string md5 = computeMD5();
            string version = ((AssemblyFileVersionAttribute)Attribute.GetCustomAttribute(Assembly.GetExecutingAssembly(), typeof(AssemblyFileVersionAttribute), false)).Version;
            string shwid = getHWID();
            string paramJson = string.Format("{{\"MD5\":\"{0}\",\"VERSION\":\"{1}\",\"HWID\":\"{2}\",\"PID\":\"{3}\"}}", md5, version, shwid, programID);
            string clientPacket = string.Format("{{\"key\":\"{0}\", \"value\":{1}}}", key, paramJson);
            return Encoding.UTF8.GetBytes(clientPacket);
        }
        private static X509Certificate SelectLocalCertificate(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
        {
            Debugger.WriteLog("Client is selecting a local certificate.");
            if (acceptableIssuers != null &&
                acceptableIssuers.Length > 0 &&
                localCertificates != null &&
                localCertificates.Count > 0)
            {
                foreach (X509Certificate certificate in localCertificates)
                {
                    string issuer = certificate.Issuer;
                    if (Array.IndexOf(acceptableIssuers, issuer) != -1)
                        return certificate;
                }
            }
            if (localCertificates != null &&
                localCertificates.Count > 0)
                return localCertificates[0];

            return null;
        }
        private static bool App_CertificateValidation(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {

            if (sslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
                return true;

            // If there are errors in the certificate chain, look at each error to determine the cause.
            if ((sslPolicyErrors & System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            {
                if (chain != null && chain.ChainStatus != null)
                {
                    foreach (System.Security.Cryptography.X509Certificates.X509ChainStatus status in chain.ChainStatus)
                    {
                        if ((certificate.Subject == certificate.Issuer) &&
                           (status.Status == System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.UntrustedRoot))
                        {
                            // Self-signed certificates with an untrusted root are valid. 
                            continue;
                        }
                        else
                        {
                            if (status.Status != System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.NoError)
                            {
                                // If there are any other errors in the certificate chain, the certificate is invalid,
                                // so the method returns false.
                                return false;
                            }
                        }
                    }
                }
                // When processing reaches this line, the only errors in the certificate chain are 
                // untrusted root errors for self-signed certificates. These certificates are valid
                // for default Exchange server installations, so return true.
                return true;
            }
            else
            {
                // In all other cases, return false.
                return false;
            }
        }
        private void processMessage(string message)
        {

            JavaScriptSerializer js = new JavaScriptSerializer();
            Regex regex = new Regex("{.*?}");
            MatchCollection matches = regex.Matches(message);
            foreach (Match match in matches)
            {
                dynamic serverPacket = (js.Deserialize<dynamic>(match.Value));
                int status = int.Parse(serverPacket["status"], System.Globalization.NumberStyles.HexNumber);
                switch (status)
                {
                    case (int)EnumAnswers.NOT_FOUD:
                        iNotifAuth.Status = "Username not found !";
                        break;
                    case (int)EnumAnswers.EXPIRED_LICENSE:
                        iNotifAuth.Status = "License expired !";
                        break;
                    case (int)EnumAnswers.BANNED:
                        iNotifAuth.Status = "License banned !";
                        break;
                    case (int)EnumAnswers.INTERNAL_ERROR:
                        iNotifAuth.Status = "Internal Error !";
                        break;
                    case (int)EnumAnswers.KEY_UPDATE:
                        File.WriteAllText("key.bin", serverPacket["data"]);
                        iNotifAuth.Status = "Processing key update ..";
                        break;
                    case (int)EnumAnswers.PLUGIN_DATA:
                        if (iNotifAuth.remoteVariable == null)
                            throw new Exception("You have remote variable data but haven't set your call back !");
                        iNotifAuth.remoteVariable(Convert.FromBase64String(serverPacket["data"]));
                        iNotifAuth.Status = "Downloading data ..";
                        break;
                    case (int)EnumAnswers.UPDATE:
                        iNotifAuth.Status = "Update avaible, this isn't implemented !";
                        break;
                }
            }
        }

    }
    class Core
    {
        public Action<byte[]> remoteVariable { get; set; }
        public string programID { get; set; }

        private Crypto crypto { get; set; }
        private Task currentTask { get; set; }
        private CancellationTokenSource cts { get; set; }
        // can be bound from wpf


        public Core(string key, string clientCertPath, string caCertPath, string ProgramID)
        {
            // Checks
            if (!File.Exists(clientCertPath))
                throw new Exception("Invalid client certificate path !");
            if (!File.Exists(caCertPath))
                throw new Exception("Invalid ca certificate path !");
            if (key == null || key == string.Empty)
                throw new Exception("Key cannot be null !");
            
            if (cts == null)
                cts = new CancellationTokenSource();

            programID = ProgramID;

            Crypto.ClientCertificateFile = clientCertPath;
            Crypto.CACertificateFile = caCertPath;

            if (crypto == null)
                crypto = new Crypto();
            if (!crypto.addCertificates())
            {
                Debugger.WriteLog("Failed to add certificates into trusted, Please run this application as administrator.");
                return;
            }

        }
        public void Authenticate()
        {
            if (remoteVariable != null)
                iNotifAuth.remoteVariable = remoteVariable;
            // init ssl client
            if (currentTask != null && currentTask.Status == TaskStatus.Running)
                return;
            //client.Connect(ServerHostName, ServerPort);
            crypto.sslClient("127.0.0.1", 8000, programID, currentTask, cts);
        }
        public void Abort()
        {
            cts.Cancel();
        }
    }
}
