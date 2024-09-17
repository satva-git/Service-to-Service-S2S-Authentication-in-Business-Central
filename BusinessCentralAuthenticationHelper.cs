
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace BusinessCentral.Authentication
{
    internal class BusinessCentralIntegration
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string TenantId { get; set; }
        public string Scope { get; set; }
        public string LoginUrl { get; set; }

    }

    internal class BusinessCentralToken
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("expires_in")]
        public string ExpiresAfterSeconds { get; set; }
    }

    internal class BusinessCentralAuthenticationHelper
    {
        private readonly BusinessCentralIntegration bcCredentials;
        private readonly string tokenEndPointUrl;
        private readonly HttpClient httpClient;

        public BusinessCentralAuthenticationHelper(BusinessCentralIntegration bcCredentials, HttpClient httpClient)
        {
            this.bcCredentials = bcCredentials;
            tokenEndPointUrl = $"{bcCredentials.LoginUrl}{bcCredentials.TenantId}/oauth2/v2.0/token";
            this.httpClient = httpClient;
        }

        public async Task<BusinessCentralToken> GetAccessToken()
        {
            var requestParams = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", bcCredentials.ClientId),
                new KeyValuePair<string, string>("client_secret", bcCredentials.ClientSecret),
                new KeyValuePair<string, string>("scope", bcCredentials.Scope)
            };

            var httpRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndPointUrl)
            {
                Content = new FormUrlEncodedContent(requestParams)
            };

            var httpResponse = await httpClient.SendAsync(httpRequest);

            var responseJson = await httpResponse.Content.ReadAsStringAsync();
            if (!httpResponse.IsSuccessStatusCode)
            {
                throw new Exception($"Authentication failed for the following reason: {responseJson}");
            }

            BusinessCentralToken token = JsonConvert.DeserializeObject<BusinessCentralToken>(responseJson);

            if (token == null)
            {
                throw new Exception($"Authentication failed. Can't deserialize response: {responseJson}");
            }

            return token;
        }
    }
}
