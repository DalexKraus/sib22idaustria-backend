using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Web;
using System.Text.Json;
using System.Text;
using IDAustriaDemo.Util;
using Microsoft.AspNetCore.Authorization;
using System.Linq;
using Microsoft.Extensions.ObjectPool;

namespace IDAustriaDemo.Controller.V1
{

    [ApiController]
    [Route("[controller]/v1")]
    public class APIController : ControllerBase
    {
        private readonly ILogger<APIController> _logger;
        private readonly string _frontendBaseUrl;

        public APIController(ILogger<APIController> logger)
        {
            _logger = logger;
            _frontendBaseUrl = EnvUtil.GetValueOrThrow("FRONTEND_BASE_URL");
        }

        /// <summary>
        /// Generate a secure random number
        /// (source: https://stackoverflow.com/a/71921401)
        /// </summary>
        /// <param name="fromInclusive">Random number interval (min, including this number)</param>
        /// <param name="toExclusive">Random number interval (max, excluding this number)</param>
        /// <returns></returns>
        private static int RandomNumber(int fromInclusive, int toExclusive)
            => System.Security.Cryptography.RandomNumberGenerator.GetInt32(fromInclusive, toExclusive);

        [HttpGet("login")]
        public IActionResult Login()
        {
            var clientId = EnvUtil.GetValueOrThrow("OIDC_CLIENT_ID");
            var redirectUri = EnvUtil.GetValueOrThrow("OIDC_REDIRECT_URI");

            // This state parameter is used to prevent CSRF attacks and must be unique for each
            // authentication request. It is recommended to use a cryptographically secure random value.
            var state = RandomNumber(100000, 999999).ToString();

            // In a practical production application, one should store the state parameter
            // in a secure cookie or session and validate it in the callback endpoint
            // in order to prevent CSRF attacks. This is not implemented here for simplicity.

            var queryParams = HttpUtility.ParseQueryString(string.Empty);
            queryParams["response_type"] = "code";
            queryParams["client_id"] = clientId;
            queryParams["redirect_uri"] = redirectUri;
            queryParams["scope"] = "openid profile";
            // queryParams["state"] = state;

            var authorizationUrl = $"https://eid2.oesterreich.gv.at/auth/idp/profile/oidc/authorize?{queryParams}";
            return Redirect(authorizationUrl);
        }

        /// <summary>
        /// The OIDC provider will redirect the user after a successful authentication
        /// to this endpoint with an authorization code.
        /// 
        /// This endpoint will exchange the authorization code for an ID token
        /// and redirect the user to the frontend with the ID token.
        /// </summary>
        /// <param name="code">The authorization code</param>
        /// <param name="state">The state parameter, used to prevent CSRF attacks</param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        [HttpGet("callback")]
        public async Task<IActionResult> Callback([FromQuery] string code, [FromQuery] string? state)
        {
            if (string.IsNullOrEmpty(code))
            {
                _logger.LogInformation("Authorization code is missing");
                return BadRequest("Authorization code is missing");
            }

            // In a practical production application, one should validate the state parameter
            // in order to prevent CSRF attacks. This is not implemented here for simplicity.

            // Exchange the authorization code for an ID token
            var httpClient = new HttpClient();
            var queryParams = HttpUtility.ParseQueryString(string.Empty)
                ?? throw new Exception("Failed to create query parameters");

            queryParams["code"] = code;
            queryParams["grant_type"] = "authorization_code";
            queryParams["client_id"] = EnvUtil.GetValueOrThrow("OIDC_CLIENT_ID");
            queryParams["client_secret"] = EnvUtil.GetValueOrThrow("OIDC_CLIENT_SECRET");
            queryParams["redirect_uri"] = EnvUtil.GetValueOrThrow("OIDC_REDIRECT_URI");

            _logger.LogInformation("client_id: {}\nclient_secret: {}\nredirect_uri: {}\n", queryParams["client_id"], queryParams["client_secret"], queryParams["redirect_uri"]);

            var requestBody = new StringContent(
                queryParams.ToString()!,
                Encoding.UTF8,
                "application/x-www-form-urlencoded"
            );

            // Send the request to the token endpoint
            var response = await httpClient.PostAsync(
                "https://eid2.oesterreich.gv.at/auth/idp/profile/oidc/token",
                requestBody
            );

            var responseContent = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Token exchange failed: {}", responseContent);
                return BadRequest($"Token exchange failed: {responseContent}");
            }

            // Parse the ID token from the response
            var tokenResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);
            var idToken = tokenResponse.GetProperty("id_token").GetString();

            // Redirect to the frontend with the ID token
            var tokenUrlEncoded = HttpUtility.UrlEncode(idToken);
            return Redirect($"{_frontendBaseUrl}/login/redirect?token={tokenUrlEncoded}");
        }


        /// <summary>
        /// This is a protected resource that requires the user to be authenticated.
        /// The user must have a valid ID token in the Authorization header.
        /// </summary>
        [HttpGet("protected-resource")]
        [Authorize]
        public ActionResult<string> ProtectedResource()
        {
            var resource = $"Geheime Zahlen: {String.Join(", ", Enumerable.Range(1, 10))}";
            return resource;
        }
    }
}
