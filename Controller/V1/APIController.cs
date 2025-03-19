using Microsoft.AspNetCore.Mvc;
using System.Web;
using System.Text.Json;
using System.Text;
using IDAustriaDemo.Util;
using Microsoft.AspNetCore.Authorization;

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

        [HttpGet("login")]
        public IActionResult Login()
        {
            var clientId = EnvUtil.GetValueOrThrow("OIDC_CLIENT_ID");
            var redirectUri = EnvUtil.GetValueOrThrow("OIDC_REDIRECT_URI");

            var queryParams = HttpUtility.ParseQueryString(string.Empty);
            queryParams["response_type"] = "code";
            queryParams["client_id"] = clientId;
            queryParams["redirect_uri"] = redirectUri;
            queryParams["scope"] = "openid profile";
            // In a practical production application, one should use the state parameter
            // in order to prevent CSRF attacks. This is not implemented here for simplicity.
            // queryParams["state"] = state;

            var authorizeUrl = $"https://eid.oesterreich.gv.at/auth/idp/profile/oidc/authorize?{queryParams}";
            return Redirect(authorizeUrl);
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
