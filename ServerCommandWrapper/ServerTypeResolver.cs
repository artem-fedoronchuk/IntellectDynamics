using System;
using System.Net;

namespace ServerCommandWrapper.Resolver
{
    /// <summary>
    /// Class to automatically determine which type of server that is used.
    /// Please note that it is always preferred to code towards a specific type of server!
    /// </summary>
    public class ServerTypeResolver
    {
        private readonly String _url;
        private readonly String _domain;
        private readonly String _username;
        private readonly String _password;

        /// <summary>
        /// Constructor for the ServerTypeResolver, which stored the often used information
        /// </summary>
        /// <param name="url">The url of the server</param>
        /// <param name="domain">Domain</param>
        /// <param name="username">Username</param>
        /// <param name="password">Password related to the username</param>
        public ServerTypeResolver(String url, String domain, String username, String password)
        {
            _url = url;
            _domain = domain;
            _username = username;
            _password = password;
        }

        /// <summary>
        /// Determines which type of server it is
        /// </summary>
        /// <param name="autype">Authentication type to use</param>
        /// <param name="port">Port to use</param>
        /// <returns></returns>
        public ServerType GetServerType(AuthenticationType autype, int port)
        {
            switch (autype)
            {
                case AuthenticationType.Basic:
                    try
                    {
                        Basic.BasicConnection basicLogin = new Basic.BasicConnection(true, _username, _password, _url, port);                        
                        int version = basicLogin.GetVersion();

                        return ServerType.C_Code;                       
                    }
                    catch (Exception)
                    {
                        try
                        {
                            Ntlm.NtlmConnection ntlmLogin = new Ntlm.NtlmConnection(_domain, autype, _username, _password, true, _url, port);
                            int version = ntlmLogin.GetVersion();

                            return ServerType.E_Code;
                        }
                        catch (Exception)
                        {
                            //Empty
                        }

                    }

                    break;


                case AuthenticationType.Windows:
                case AuthenticationType.WindowsDefault:
                    try
                    {
                        Ntlm.NtlmConnection ntlmLogin = new Ntlm.NtlmConnection(_domain, autype, _username, _password, true, _url, port);
                        int version = ntlmLogin.GetVersion();
          
                        return ServerType.C_Code;

                    }
                    catch (Exception)
                    {
                        try
                        {
                            Ntlm.NtlmConnection ntlmLogin = new Ntlm.NtlmConnection(_domain, autype, _username, _password, false, _url, port);
                            int version = ntlmLogin.GetVersion();

                            return ServerType.E_Code;
                        }
                        catch (WebException)
                        {
                            //Empty
                        }
                    }
                    break;
            }
            
            return ServerType.None;            
        }
    }
}
