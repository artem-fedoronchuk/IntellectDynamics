using System;
using System.ServiceModel;

namespace ServerCommandWrapper
{
    /// <summary>
    /// Destribes which kind of server it is.
    /// </summary>
    public enum ServerType
    {
        C_Code,
        E_Code,
        None
    }

    /// <summary>
    /// Authentication types: Basic, Windows, or Windows default
    /// </summary>
    public enum AuthenticationType
    {
        Basic,
        Windows,
        WindowsDefault
    }

    /// <summary>
    /// A shared simple representation of the LoginInfo classes in ServerCommandService_CServer and ServerCommandService_EServer
    /// </summary>
    public class LoginInfo
    {
        public DateTime RegistrationTimeField;
        public TimeSpan TimeToLive;
        public String Token;

        /// <summary>
        /// Converts a ServerCommandService_CServer.LoginInfo into a the shared type of LoginInfo
        /// </summary>
        /// <param name="loginInfo">LoginInfo from the C server</param>
        /// <returns>A shared type of LoginInfo</returns>
        public static LoginInfo CreateFrom(ServerCommandService_CServer.LoginInfo loginInfo)
        {
            if (loginInfo == null)
                return null;

            LoginInfo lInfo = new LoginInfo()
            {
                RegistrationTimeField = loginInfo.RegistrationTime,
                TimeToLive = TimeSpan.FromMilliseconds(loginInfo.TimeToLive.MicroSeconds/1000),
                Token = loginInfo.Token
            };
            return lInfo;

        }

        /// <summary>
        /// Converts a ServerCommandService_EServer.LoginInfo into a the shared type of LoginInfo
        /// </summary>
        /// <param name="loginInfo">LoginInfo from the E server</param>
        /// <returns>A shared type of LoginInfo</returns>
        public static LoginInfo CreateFrom(ServerCommandService_EServer.LoginInfo loginInfo)
        {
            if (loginInfo == null)
                return null;

            LoginInfo lInfo = new LoginInfo()
            {
                RegistrationTimeField = loginInfo.RegistrationTime,
                TimeToLive = TimeSpan.FromMilliseconds(loginInfo.TimeToLive.MicroSeconds / 1000),
                Token = loginInfo.Token
            };
            return lInfo;
        }
    }
}
