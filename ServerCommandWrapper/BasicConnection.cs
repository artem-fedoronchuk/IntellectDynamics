using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using System.Threading;
using System.Xml;
using ServerCommandService_CServer;
using ServerCommandService_EServer;

namespace ServerCommandWrapper.Basic
{
    /// <summary>
    /// Class to control a connection for basic authentications.
    /// Note that the E servers doesn't support SSL and the data will be exchanges in clear text!!!
    /// </summary>
    public class BasicConnection
    {
        public ServerCommandServiceClient CServer { get; }
        private readonly ServerCommandService _eServer;

        private ServerCommandService_CServer.LoginInfo _loginInfo_CServer;
        private ServerCommandService_EServer.LoginInfo _loginInfo_EServer;

        private readonly Uri _uri;
        private readonly Guid _thisInstance = Guid.NewGuid();
        private Timer _tokenExpireTimer;

        private readonly String _serverUrl;
        private readonly int _port;
        private readonly String _username;
        private readonly String _password;

        /// <summary>
        /// Subscribe to this to be notified when token changes
        /// </summary>
        public event EventHandler<string> OnTokenRefreshed = delegate { };

        /// <summary>
        /// Configuration if the server is a C server.
        /// Please collect the configuration first, using <see cref="GetConfiguration"/>
        /// </summary>
        public ServerCommandService_CServer.ConfigurationInfo ConfigurationInfo_CServer;

        /// <summary>
        /// Configuration if the server is an E server.
        /// Please collect the configuration first, using <see cref="GetConfiguration"/>
        /// </summary>
        public XmlDocument Configuration_EServer;

        /// <summary>
        /// If the server is a C server (Corporate).
        /// The alternative is an E server (Enterprise)
        /// </summary>
        public bool IsCServer { get; }
       
        /// <summary>
        /// Constructor for the BasicConnection, which performs and sets some start-up routines
        /// </summary>
        /// <param name="isCServer">If the server is a C server</param>
        /// <param name="username">Username to use</param>
        /// <param name="password">Password to use</param>
        /// <param name="hostname">The hostname</param>
        /// <param name="port">Which port to use</param>
        public BasicConnection(bool isCServer, String username, String password, String hostname, int port)
        {
            //Precondition
            if (hostname.StartsWith("http://"))
                hostname = hostname.Substring("http://".Length);

            IsCServer = isCServer;
            _serverUrl = hostname;            
            _username = username;
            _password = password;
            _port = port;

            if (IsCServer)
            {
                // SSL
                _uri = new Uri($"https://{_serverUrl}:{_port}/ManagementServer/ServerCommandService.svc");

                // Create Soap class from interface
                CServer = new ServerCommandServiceClient(GetBinding(),
                    new EndpointAddress(_uri, EndpointIdentity.CreateSpnIdentity(SpnFactory.GetSpn(_uri))));

                // Set basic credentials
                CServer.ClientCredentials.UserName.UserName = username;
                CServer.ClientCredentials.UserName.Password = password;
                // TODO Any certificate is accepted as OK !!
                CServer.ClientCredentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication()
                {
                    CertificateValidationMode = X509CertificateValidationMode.None,
                };

                // Open service (internally)
                CServer.Open();

                // Give OS a few milliseconds to get ready
                long tickStop = DateTime.Now.Ticks + 1000000; // 1.000.000 ticks == 100 ms
                while (DateTime.Now.Ticks < tickStop && CServer.State == CommunicationState.Opening)
                {
                    Thread.Sleep(5);
                }
            }
            else
            {
                _eServer = new ServerCommandService($"http://{_serverUrl}:{_port}/ServerCommandService/servercommandservice.asmx");

                String uri = $"http://{_serverUrl}";
                _uri = new Uri(uri);


                CredentialCache credCache = new CredentialCache();
                NetworkCredential credentials = new NetworkCredential(_username, _password);              
                credCache.Add(new Uri(uri), "Basic", credentials);
                _eServer.Credentials = credCache;              
            }            
        }

        /// <summary>
        /// The current login information
        /// </summary>
        public LoginInfo LoginInfo
        {
            get
            {
                if (IsCServer)
                    return LoginInfo.CreateFrom(_loginInfo_CServer);
                return LoginInfo.CreateFrom(_loginInfo_EServer);
            }
        }

        /// <summary>
        /// Login to the server       
        /// </summary>      
        /// <returns>Info of valid log in</returns>
        public LoginInfo Login()
        {
            string currentToken = "";
            if (LoginInfo != null)
                currentToken = LoginInfo.Token;

            if (IsCServer)
            {
                // Now call the login method on the server, and get the loginInfo class (provide old token for next re-login)
                _loginInfo_CServer = CServer.Login(_thisInstance, currentToken);
            }
            else
            {
                // Now call the login method on the server, and get the loginInfo class (provide old token for next re-login)
                _loginInfo_EServer = _eServer.Login(_thisInstance, currentToken);
            }

            // React 30 seconds before token expires. (Never faster than 30 seconds after last renewal, but that ought not occur).
            // E-code's default timeout is 4 minutes, C-code's is 1 hour.
            double ms = LoginInfo.TimeToLive.TotalMilliseconds;
            ms = ms > 60000 ? ms - 30000 : ms;

            _tokenExpireTimer = new Timer(TokenExpireTimer_Callback, null, (int)ms, Timeout.Infinite);

            return LoginInfo;
        }
    

        /// <summary>
        /// Logout from the server
        /// </summary>
        public void Logout()
        {
            if (IsCServer)            
                CServer.Logout(_thisInstance, LoginInfo.Token);
            else
             _eServer.Logout(_thisInstance, LoginInfo.Token);


            _loginInfo_CServer = null;
            _loginInfo_EServer = null;

            CancelCallbackTimer();
        }

        /// <summary>
        /// Gets the version of the server
        /// </summary>
        /// <returns>The version as an int</returns>
        public int GetVersion()
        {
            if (IsCServer)
                return CServer.GetVersion();

            return _eServer.GetVersion();
        }

        /// <summary>
        /// Gets the configuration from the server.
        /// Automatically determines if the SOAP interface or the XML file should be used
        /// </summary>
        /// <param name="token">Valid token (only used with C servers)</param>
        public void GetConfiguration(String token = "")
        {

            if (IsCServer)
                ConfigurationInfo_CServer = CServer.GetConfiguration(token);
            else            
                Configuration_EServer = GetConfigurationFromXmlFile(false);
            
        }

        /// <summary>
        /// Collect the configuration from the XML file.
        /// Please note that this should only be done for E servers! C servers should use the SOAP interface
        /// </summary>
        /// <param name="isCCode">If the server is a C server</param>
        /// <exception cref="TypeAccessException">If attempted to be used on a C server</exception>
        /// <returns></returns>
        public XmlDocument GetConfigurationFromXmlFile(bool isCCode)
        {
            if (isCCode)
                throw new TypeAccessException(
                    "Configuration from a C server should be access through the SOAP interface - not the XML file");

            String url = _serverUrl;
            
            if (!url.StartsWith("http://"))
                url = "http://" + url;

            String auName = "Basic";
            CredentialCache credCache = new CredentialCache();
            credCache.Add(new Uri(url), auName, new NetworkCredential(_username, _password));

            XmlDocument xml = GetXmlFile(_serverUrl + "/systeminfo.xml", credCache);

            return xml;
        }

        /// <summary>
        /// Get the XML file from the provided path
        /// </summary>
        /// <param name="url">Absolute path of the XML file</param>
        /// <param name="credentials">Credentials to use for getting access</param>
        /// <returns>The XMl file</returns>
        private static XmlDocument GetXmlFile(String url, ICredentials credentials)
        {
            // Precondition
            if (!url.StartsWith("http://"))
                url = "http://" + url;

            try
            {
                HttpWebRequest req = (HttpWebRequest) WebRequest.Create(url);
                // TODO Accepts any certificate - change before moving to production!!
                req.ServerCertificateValidationCallback = (sender, certificate, chain, sslpolicyerrors) => true;
                req.Credentials = credentials;
                req.PreAuthenticate = true;
                req.Method = "GET";
                req.Accept = "text/xml";
                req.AllowWriteStreamBuffering = true;
                req.Timeout = 20000;

                HttpWebResponse response = (HttpWebResponse) req.GetResponse();
                long respLen = response.ContentLength;
                Stream stream = response.GetResponseStream();

                int got = 0;
                int bytes = 0;
                int get = 1;
                int maxb = (int) respLen;
                int miss = maxb;
                byte[] buffer = new byte[respLen];
                int retry = 3;

                do
                {
                    get = miss > maxb ? maxb : miss;
                    bytes = stream.Read(buffer, got, get);
                    if (bytes == 0)
                    {
                        retry--;
                    }

                    got += bytes;
                    miss -= bytes;
                } while (got < maxb && retry > 0);

                int off = (buffer[3] == 60) ? 3 : 0; // Skip XML indicator bytes
                string page = Encoding.UTF8.GetString(buffer, off, got - off);
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(page);

                return doc;
            }
            catch (WebException we)
            {
                HttpWebResponse r = (HttpWebResponse) we.Response;
                string s = we.Message;
                return new XmlDocument();
            }
            catch (Exception e)
            {
                string s = e.Message;
                return new XmlDocument();
            }
        }

        /// <summary>
        /// Callback method to perform a login and thereby refresh the token.
        /// </summary>
        /// <param name="state">Not used</param>
        private void TokenExpireTimer_Callback(Object state)
        {
            try
            {
                var loginInfo = Login();

                if (String.IsNullOrEmpty(loginInfo.Token))
                    throw new Exception("Got blank token when trying to refresh");

                OnTokenRefreshed.Invoke(this, loginInfo.Token);
            }
            catch (Exception e)
            {
                CancelCallbackTimer();
                throw new Exception("Error refreshing token: " + e.Message);
            }
        }

        /// <summary>
        /// Cancels the callback timer and thereby stops refreshing the token before it expires
        /// </summary>
        private void CancelCallbackTimer()
        {
            _tokenExpireTimer.Dispose();
            _tokenExpireTimer = null;
        }

        /// <summary>
        /// Gets the binding to use for a Basic authentication model
        /// </summary>
        /// <returns>The binding to use</returns>
        private static System.ServiceModel.Channels.Binding GetBinding()
        {
            BasicHttpBinding binding = new BasicHttpBinding();
            binding.Security.Mode = BasicHttpSecurityMode.Transport;
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Basic;
            binding.MaxBufferPoolSize = Int32.MaxValue;
            binding.MaxReceivedMessageSize = Int32.MaxValue;
            //binding.ReaderQuotas = XmlDictionaryReaderQuotas.Max;     // can be set when GetCameraInfoFromConfiguration is needed (and is big)
            return binding;
        }

        /// <summary>
        /// The SpnFactory is a helper class to get the right SPN for a connection
        /// </summary>
        public static class SpnFactory
        {
            private const string SpnTemplate = "VideoOS/{0}:{1}";
            private static string _localHostFqdn = null;

            /// <summary>
            /// GetSpn returns the right SPN for a connection on the specified URI
            /// </summary>
            /// <param name="serverUri">The URI of the service to be connected</param>
            /// <returns>A valid SPN for the service</returns>
            public static string GetSpn(Uri serverUri)
            {
                if (serverUri == null)
                {
                    throw new ArgumentNullException("serverUri");
                }

                string host = serverUri.Host;
                if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                {
                    if (String.IsNullOrEmpty(_localHostFqdn))
                    {
                        _localHostFqdn = Dns.GetHostEntry("localhost").HostName;
                    }

                    host = _localHostFqdn;
                }

                var spn = String.Format(CultureInfo.InvariantCulture, SpnTemplate, host, serverUri.Port);
                return spn;
            }
        }
    }
}