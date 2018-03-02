//  Copyright 2018 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.BlueJeans
{
    // see https://bluejeans.github.io/api-rest-meetings/site/index.html for docs 
    public class BlueJeansAuthenticationHandler : AuthenticationHandler<BlueJeansAuthenticationOptions>
    {
        private const string AuthorizeEndpoint =      "https://bluejeans.com/oauth2/authorize/"; 
        private const string TokenEndpoint =          "https://api.bluejeans.com/oauth2/token?Code";
        private const string UserInfoEndpointFormat = "https://api.bluejeans.com/v1/user/{0}?access_token={1}";

        private const string DefaultScope =      "user_info";
        private const string XmlSchemaString =   "http://www.w3.org/2001/XMLSchema#string";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public BlueJeansAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }


        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string state = null;
                string code = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values;
                
                values = query.GetValues("state");
                if (values != null && values.Count == 1) 
                {
                    state = values[0];
                }
                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null) 
                {
                    return null;
                }

                values = query.GetValues("error");
                if (values != null && values.Count == 1) 
                {
                    return new AuthenticationTicket(null, properties);
                }
                
                values = query.GetValues("code");
                if (values != null && values.Count == 1) 
                {
                    code = values[0];
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                var requestJson = new JObject 
                {
                    { "grant_type", "authorization_code" },
                    { "client_id", Options.ClientId },
                    { "client_secret", Options.ClientSecret },
                    { "code", code },
                    { "redirect_uri", redirectUri }
                };

                // Request the token
                var tokenResponse = await _httpClient.PostAsync(
                        TokenEndpoint, new StringContent(requestJson.ToString(), Encoding.UTF8, "application/json"));
                tokenResponse.EnsureSuccessStatusCode();
                string content = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                var response = JsonConvert.DeserializeObject<JObject>(content);
                string accessToken = response["access_token"].Value<string>();
                string accessTokenExpires = response["expires_in"].Value<string>();
                string refreshToken = response["refresh_token"].Value<string>();
                string[] scope = response["scope"]?["bearerPermissions"] != null ?
                    response["scope"]?["bearerPermissions"].Value<string>().Split(new char[] { ',' }) : 
                    new string[0];
                string userId = response["scope"]?["user"]?.Value<string>();

                var userResponse = await _httpClient.GetAsync(String.Format(UserInfoEndpointFormat, userId, accessToken));
                var userContent = await userResponse.Content.ReadAsStringAsync();
                JObject userJson = null;
                if (userResponse.IsSuccessStatusCode) {
                    userJson = JObject.Parse(userContent);
                }

                var context = new BlueJeansAuthenticatedContext(Context, 
                    accessToken, accessTokenExpires, refreshToken, scope, userId, userJson);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!String.IsNullOrEmpty(context.UserId)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.NameIdentifier, context.UserId, XmlSchemaString, Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.Username)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimsIdentity.DefaultNameClaimType, context.Username, XmlSchemaString, Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.Email)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.GivenName)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.GivenName, context.GivenName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Surname)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.Surname, context.Surname, XmlSchemaString, Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }


        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = 
                Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null) {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri)) 
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                queryStrings.Add("responseType", "code");
                queryStrings.Add("clientId", Options.ClientId);
                queryStrings.Add("redirectUri", redirectUri);

                // default scope
                if (Options.Scope.Count == 0) 
                {
                    Options.Scope.Add(DefaultScope);
                }
                AddQueryString(queryStrings, properties, "scope", string.Join(",", Options.Scope));

                if (!String.IsNullOrEmpty(Options.AppName)) 
                {
                    AddQueryString(queryStrings, properties, "appName", Options.AppName);
                }
                if (!String.IsNullOrEmpty(Options.AppLogoUrl)) 
                {
                    AddQueryString(queryStrings, properties, "appLogoUrl", Options.AppLogoUrl);
                }

                string state = Options.StateDataFormat.Protect(properties);
                queryStrings.Add("state", state);

                string authorizationEndpoint = WebUtilities.AddQueryString(AuthorizeEndpoint, queryStrings);

                var redirectContext = new BlueJeansApplyRedirectContext(
                    Context, Options,
                    properties, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }


        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }


        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new BlueJeansReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(
                        grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(
                            grantIdentity.Claims, 
                            context.SignInAsAuthenticationType, 
                            grantIdentity.NameClaimType, 
                            grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }


        private static void AddQueryString(IDictionary<string, string> queryStrings, AuthenticationProperties properties,
            string name, string defaultValue = null) 
        {
            string value;
            if (!properties.Dictionary.TryGetValue(name, out value)) 
            {
                value = defaultValue;
            }
            else 
            {
                // Remove the parameter from AuthenticationProperties so it won't be serialized to state parameter
                properties.Dictionary.Remove(name);
            }

            if (value == null) 
            {
                return;
            }

            queryStrings[name] = value;
        }
    }
}