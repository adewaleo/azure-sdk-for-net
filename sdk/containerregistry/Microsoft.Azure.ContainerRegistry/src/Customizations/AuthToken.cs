using Microsoft.Rest;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Azure.ContainerRegistry
{
    /// <summary>
    /// Simple authentication class for use with Token related api calls for determining scopes and other such things
    /// </summary>
    public class TokenCredentials : ServiceClientCredentials
    {
        private string _authHeader { get; set; }

        /*To be used for General Login Scheme*/
        public TokenCredentials(string username, string password)
        {
            _authHeader = Helpers.EncodeTo64($"{username}:{password}");
        }

        /*To be used for exchanging AAD Tokens for ACR Tokens*/
        public TokenCredentials()
        {
            _authHeader = null;
        }

        public override async Task ProcessHttpRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }
            if (_authHeader != null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", _authHeader);
            }
            await base.ProcessHttpRequestAsync(request, cancellationToken);
        }

    }

    /// <summary>
    /// AuthToken allows for chaining token refreshes. It abstracts away checking and refresh logic.
    /// This allows us to have refresh token chains.
    /// </summary>
    public class AuthToken
    {

        public delegate string AcquireCallback();
        protected static readonly JwtSecurityTokenHandler JwtSecurityClient = new JwtSecurityTokenHandler();

        // Constant to refresh tokens slightly before they are to expire guarding against possible latency related crashes
        private readonly TimeSpan LatencySafety = TimeSpan.FromMinutes(2);

        public string Value { get; set; }
        public DateTime Expiration { get; set; }
        protected AcquireCallback RefreshFunction;

        public AuthToken(string token)
        {
            Value = token;
            Expiration = JwtSecurityClient.ReadToken(Value).ValidTo;
        }

        public AuthToken(string token, AcquireCallback refreshFunction) : this(token)
        {
            RefreshFunction = refreshFunction;
        }

        //Extensibility purposes
        protected AuthToken() { }


        /* Returns true if refresh was successful. */
        public bool Refresh()
        {
            if (RefreshFunction == null)
            {
                return false;
            }
            Value = RefreshFunction();
            Expiration = JwtSecurityClient.ReadToken(Value).ValidTo;

            return true;
        }

        public bool NeedsRefresh()
        {
            return Expiration < DateTime.UtcNow.Add(LatencySafety);
        }

        // Returns true if token is ready for use or false if token was expired and unable to refresh
        public bool CheckAndRefresh()
        {
            if (NeedsRefresh())
                return Refresh();
            return true;
        }

        protected void InitializeToken(AcquireCallback refreshFunction)
        {
            Value = refreshFunction();
            Expiration = JwtSecurityClient.ReadToken(Value).ValidTo;
            RefreshFunction = refreshFunction;
        }
    }

    /// <summary>
    /// An ACR refresh token that refreshes from an AAD access token. Provides built in token exchange functionality.
    /// </summary>
    public class AcrRefreshToken : AuthToken
    {
        private AzureContainerRegistryClient authClient;
        public AcrRefreshToken(AuthToken aadToken, string loginUrl)
        {
            // setup refresh function to retrieve acrtoken with aadtoken
            authClient = new AzureContainerRegistryClient(new TokenCredentials())
            {
                LoginUri = $"https://{loginUrl}"
            };

            string tempRefreshFunction()
            {
                // Note: should be using real new access token
                aadToken.CheckAndRefresh();
                return authClient.RefreshTokens.GetFromExchangeAsync("access_token", loginUrl, "", null, aadToken.Value).GetAwaiter().GetResult().RefreshTokenProperty;
            }

            // initialize token and refresh function
            InitializeToken(tempRefreshFunction);
        }
    }
    /// <summary>
    /// An ACR access token that refreshes from an ACR refresh token or username and password.
    /// </summary>
    public class AcrAccessToken : AuthToken
    {
        private AzureContainerRegistryClient authClient;
        public string Scope { get; set; }
        /// <summary>
        /// Construct an ACR access token that refreshes from an ACR refresh token.
        /// </summary>
        /// <param name="acrRefresh"></param>
        /// <param name="scope"></param>
        /// <param name="loginUrl"></param>
        public AcrAccessToken(AcrRefreshToken acrRefresh, string scope, string loginUrl)
        {
            Scope = scope;
            authClient = new AzureContainerRegistryClient(new TokenCredentials())
            {
                LoginUri = $"https://{loginUrl}"
            };
            string tempRefreshFunction()
            {
                acrRefresh.CheckAndRefresh();
                return authClient.AccessTokens.GetAsync(loginUrl, scope, acrRefresh.Value).GetAwaiter().GetResult().AccessTokenProperty;
            };

            // initialize token and refresh function
            InitializeToken(tempRefreshFunction);
        }
        /// <summary>
        /// Construct an ACR access token that refreshes from an ACR refresh token. 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="scope"></param>
        /// <param name="loginUrl"></param>
        public AcrAccessToken(string username, string password, string scope, string loginUrl)
        {
            Scope = scope;
            authClient = new AzureContainerRegistryClient(new TokenCredentials(username, password))
            {
                LoginUri = $"https://{loginUrl}"
            };
            string tempRefreshFunction()
            {
                return authClient.AccessTokens.GetFromLoginAsync(loginUrl, scope).GetAwaiter().GetResult().AccessTokenProperty;
            };

            // initialize token and refresh function
            InitializeToken(tempRefreshFunction);
        }
    }
}


