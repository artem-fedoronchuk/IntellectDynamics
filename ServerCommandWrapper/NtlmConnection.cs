using System;
using System.IO;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using System.Threading;
using System.Xml;
using ServerCommandService_CServer;
using ServerCommandService_EServer;


namespace ServerCommandWrapper.Ntlm
{
    /// <summary>
    /// A class to represent the NTLM connection between the client a server.
    /// It will determine the correct logic based on which type of server that is used (E or C server)
    /// </summary>
    public class NtlmConnection
    {
        public ServerCommandServiceClient CServer
        {
            get;
        } 

        private readonly ServerCommandService _eServer;

        
        private readonly Guid _thisInstance = Guid.NewGuid();
        private Timer _tokenExpireTimer;

        private readonly String _serverUrl;
        private readonly int _port;
        private readonly AuthenticationType _authType;
        private readonly String _username;
        private readonly String _password;
        private readonly String _domain;

        private ServerCommandService_CServer.LoginInfo _loginInfo_CServer;
        private ServerCommandService_EServer.LoginInfo _loginInfo_EServer;

        /// <summary>
        /// Subscribe to this to be notified when token changes
        /// </summary>
        public event EventHandler<string> OnTokenRefreshed = delegate { };

        /// <summary>
        /// If the server is a Corporate (C server)
        /// The alternative is an Enterprise (E server)
        /// </summary>
        public bool IsCCode { get;}

        /// <summary>
        /// The configuration information if the server is a C server.
        /// Please perform a call to <see cref="GetConfiguration"/> before using it.
        /// </summary>
        public ServerCommandService_CServer.ConfigurationInfo ConfigurationInfo_CServer;

        /// <summary>
        /// The configuration information if the server is a E server.
        /// Please perform a call to <see cref="GetConfiguration"/> before using it
        /// </summary>
        public XmlDocument Configuration_EServer;


        /// <summary>
        /// Information about the login
        /// </summary>
        public LoginInfo LoginInfo
        {
            get
            {
                if (IsCCode)
                   return LoginInfo.CreateFrom(_loginInfo_CServer);

                return LoginInfo.CreateFrom(_loginInfo_EServer);
            }
        }


        /// <summary>
        /// Constructor of the NtlmConnection class. Will perform and set the needed start-up routines
        /// </summary>
        /// <param name="domain">The domain (may be empty)</param>
        /// <param name="authType">Authentication type</param>
        /// <param name="username">The username</param>
        /// <param name="password">The password related to the username</param>
        /// <param name="isCCode">If the server is a C server</param>
        /// <param name="hostname">The hostname</param>
        /// <param name="port">The used port</param>
         public NtlmConnection(String domain, AuthenticationType authType, String username, String password,
            bool isCCode, String hostname, int port = 80)
        {
            //Precondition
            if (hostname.StartsWith("http://"))
                hostname = hostname.Substring("http://".Length);

            _serverUrl = hostname;
            _port = port;
            _authType = authType;
            _username = username;
            _password = password;
            _domain = domain;
            IsCCode = isCCode;

            String url;
            String prefix = "http";

            if (_port == 443) //Note: E servers doesn't support SSL
                prefix += "s";


            if (IsCCode)
            {
                url = $"{prefix}://{hostname}:{_port}/ManagementServer/ServerCommandService.svc";
                WSHttpBinding binding = new WSHttpBinding()
                {
                    MaxReceivedMessageSize = 1000000
                };
                EndpointAddress remoteAddress = new EndpointAddress(url);

                CServer = new ServerCommandServiceClient(binding, remoteAddress);
                CServer.ClientCredentials.Windows.ClientCredential.UserName = username;
                CServer.ClientCredentials.Windows.ClientCredential.Password = password;
                if (!String.IsNullOrEmpty(_domain))
                   CServer.ClientCredentials.Windows.ClientCredential.Domain = _domain;

                // TODO Any certificate is accepted as OK !!
                CServer.ClientCredentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication()
                {
                    CertificateValidationMode = X509CertificateValidationMode.None,
                };
            }
            else
            {
                url = $"{prefix}://{hostname}";                                                                   

                _eServer = new ServerCommandService($"http://{_serverUrl}/ServerCommandService/servercommandservice.asmx");
                
                CredentialCache credCache = new CredentialCache();
                NetworkCredential credentials;
                if (String.IsNullOrEmpty(_domain))                    
                    credentials = new NetworkCredential(_username, _password);
                else
                    credentials = new NetworkCredential(_username, _password, _domain);

                credCache.Add(new Uri(url), "NTLM", credentials);
                _eServer.Credentials = credCache;
            }
        }



        /// <summary>
        /// Login to the server
        /// </summary>        
        public LoginInfo Login()
        {
            string currentToken = "";
            
            if (IsCCode)
            {
                if (_loginInfo_CServer != null)
                    currentToken = _loginInfo_CServer.Token;
                // Now call the login method on the server, and get the loginInfo class (provide old token for next re-login)
                _loginInfo_CServer = CServer.Login(_thisInstance, currentToken);            
            }
            else
            {
                if (_loginInfo_EServer != null)
                    currentToken = _loginInfo_EServer.Token;

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
            if (IsCCode)
              CServer.Logout(_thisInstance, _loginInfo_CServer.Token);
            else
            _eServer.Logout(_thisInstance, _loginInfo_EServer.Token);

            _loginInfo_CServer = null;
            _loginInfo_EServer = null;
            

            CancelCallbackTimer();
        }

        /// <summary>
        /// Get version of the host server
        /// </summary>
        /// <returns>Version of the server</returns>
        public int GetVersion()
        {
            if (IsCCode)
                return CServer.GetVersion();
            
            return _eServer.GetVersion();
        }

        /// <summary>
        /// Get the configuration and store it in the property of this class
        /// </summary>        
        /// <param name="token">The valid token, received when logged in</param>        
        public void GetConfiguration(String token)
        {
            if (IsCCode)
                ConfigurationInfo_CServer = CServer.GetConfiguration(token);
            else
                Configuration_EServer = GetConfigurationFromXmlFile(); 
        }


        /// <summary>
        /// The configuration of the server, that is available as an XML file.
        /// Please note that this should only be used on E servers.
        /// For C servers, please use the SOAP interface 
        /// </summary>
        /// <exception cref="TypeAccessException">If the server is a C server.</exception>
        /// <returns>The configuration as the collected XML</returns>
        public XmlDocument GetConfigurationFromXmlFile()
        {           
            if(IsCCode)
                throw new TypeAccessException("Configuration from a C server should be access through the SOAP interface - not the XML file");

            String url = _serverUrl;
            //E-servers never use SSL
            if (!url.StartsWith("http://"))
                url = "http://" + url;

            ICredentials credentials;
            CredentialCache credCache = new CredentialCache();
            String auName = "NTLM";


            if (_authType == AuthenticationType.WindowsDefault)
            {
                credentials = CredentialCache.DefaultNetworkCredentials;
            }
            else
            {
                if (String.IsNullOrEmpty(_domain))
                {
                    credCache.Add(new Uri(url), auName, new NetworkCredential(_username, _password));
                }
                else
                {
                    credCache.Add(new Uri(url), auName, new NetworkCredential(_username, _password, _domain));
                }

                credentials = credCache;
            }

            XmlDocument xml = GetXmlFile(_serverUrl + "/systeminfo.xml", credentials);

            return xml;
        }

        /// <summary>
        /// Collects the XML file from the given URL
        /// </summary>
        /// <param name="url">The absolute URL of the XML file</param>
        /// <param name="credentials">User credentials to gain access to the file</param>
        /// <returns>The XML file</returns>
        private static XmlDocument GetXmlFile(String url, ICredentials credentials)
        {
            // Precondition
            if (!url.StartsWith("http://"))
                url = "http://" + url;

            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                // TODO Accepts any certificate - change before moving to production!!
                req.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
                req.Credentials = credentials;
                req.PreAuthenticate = true;
                req.Method = "GET";
                req.Accept = "text/xml";
                req.AllowWriteStreamBuffering = true;
                req.Timeout = 20000;

                HttpWebResponse response = (HttpWebResponse)req.GetResponse();
                long respLen = response.ContentLength;
                Stream stream = response.GetResponseStream();

                int got = 0;
                int bytes = 0;
                int get = 1;
                int maxb = (int)respLen;
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
                }
                while (got < maxb && retry > 0);

                int off = (buffer[3] == 60) ? 3 : 0; // Skip XML indicator bytes
                string page = Encoding.UTF8.GetString(buffer, off, got - off);
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(page);

                return doc;
            }
            catch (WebException we)
            {
                HttpWebResponse r = (HttpWebResponse)we.Response;
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
        /// Callback method which will perform a new login to refresh the token
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
        /// Stop the <see cref="TokenExpireTimer_Callback"/> from being called anymore, which refreshes the token in time
        /// </summary>
        private void CancelCallbackTimer()
        {
            _tokenExpireTimer.Dispose();
            _tokenExpireTimer = null;            
        }
    }
}
