using System.Net.Http.Headers;
using Microsoft.Identity.Client;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.Services.AppAuthentication;
using System.Net.Http;


namespace ClientAppCertificateFlow
{
    // For more information see https://aka.ms/msal-net-client-credentials
    public class Program
    {
        static void Main(string[] args)
        {
            try
            { RunAsync().GetAwaiter().GetResult(); }
            catch (Exception ex)
            { Console.WriteLine(ex.Message); }
        }

        //private static string certificateFullPath = "C:\\Users\\rupam\\OneDrive\\WORK\\RAC\\ClientCredentialsFlows\\kv-rac-rac-cert-pricing-api-20220721.pfx"; // Replace with your certificate path
        //private static string applicationID = "cd622244-e630-4eb7-a7ca-2332b40800c2"; // replace with your application ID
        //private static string authority = "https://login.microsoftonline.com/9bc41626-92e4-441b-8c33-b77e812d26da"; // replace with your AAD authority

        private static async Task RunAsync()
        {
            //ICertificateLoader certificateLoader = new DefaultCertificateLoader();

            //// full path Certificate File
            //var myCertificate = X509Certificate2.CreateFromCertFile(certificateFullPath);
            //X509Certificate2 myCertificate2 = new X509Certificate2(myCertificate);

            //var app = ConfidentialClientApplicationBuilder.Create(applicationID)
            //    .WithCertificate(myCertificate2)
            //    .WithAuthority(new Uri(authority)) // Tenant ID
            //    .Build();

            ////app.AddInMemoryTokenCache();

            //// With client credentials flows the scopes is ALWAYS of the shape "resource/.default", as the 
            //// application permissions need to be set statically (in the portal or by PowerShell), and then granted by
            //// a tenant administrator. 
            //string[] scopes = new string[] { "api://a1ecdd8a-cb9d-41e1-99a4-5f99c6225e32/.default" }; // Generates a scope -> "https://graph.microsoft.com/.default"
            //                                                                           //string[] scopes = new string[] { "api://ace7a10d-aaaa-4a01-8663-1440b6b78cb9/.default" }; // custom API on same tenant

            IConfigurationRoot _configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetParent(AppContext.BaseDirectory).FullName)
                .AddJsonFile("appsettings.json", false)
                .Build();


            // Use Key Vault to get certificate
            var azureServiceTokenProvider = new AzureServiceTokenProvider();

            // Get the certificate from Key Vault
            var identifier = _configuration["CallApi:ClientCertificates:0:KeyVaultCertificateName"];
            var cert = await GetCertificateAsync(identifier);

            //var client = _clientFactory.CreateClient();

            var scope = _configuration["CallApi:ScopeForAccessToken"];
            var authority = $"{_configuration["CallApi:Instance"]}{_configuration["CallApi:TenantId"]}";

            // client credentials flows, get access token
            IConfidentialClientApplication app = ConfidentialClientApplicationBuilder.Create(_configuration["CallApi:ClientId"])
                .WithAuthority(new Uri(authority))
                .WithCertificate(cert)
                .Build();

            var accessToken = await app.AcquireTokenForClient(new[] { scope }).ExecuteAsync();

            //client.BaseAddress = new Uri(_configuration["CallApi:ApiBaseAddress"]);
            //client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken.AccessToken);
            //client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            //// use access token and get payload
            //var response = await client.GetAsync("weatherforecast");
            //if (response.IsSuccessStatusCode)
            //{
            //    var responseContent = await response.Content.ReadAsStringAsync();
            //    var data = System.Text.Json.JsonSerializer.Deserialize<IEnumerable<WeatherForecast>>(responseContent);

            //    return data;
            //}

            //throw new ApplicationException($"Status code: {response.StatusCode}, Error: {response.ReasonPhrase}");

            //AuthenticationResult result = null;
            //try
            //{
            //    result = await app.AcquireTokenForClient(scopes).ExecuteAsync();
            //    Console.WriteLine("Token acquired");
            //    Console.WriteLine("Token: " + result.AccessToken);
            //}
            //catch (MsalServiceException ex) when (ex.Message.Contains("AADSTS70011"))
            //{
            //    // Invalid scope. The scope has to be of the form "https://resourceurl/.default"
            //    // Mitigation: change the scope to be as expected
            //    Console.WriteLine("Scope provided is not supported");
            //}
        }

       
        private static async Task<X509Certificate2> GetCertificateAsync(string identitifier)
        {
            var vaultBaseUrl = _configuration["CallApi:ClientCertificates:0:KeyVaultUrl"];
            var secretClient = new SecretClient(vaultUri: new Uri(vaultBaseUrl), credential: new DefaultAzureCredential());

            // Create a new secret using the secret client.
            var secretName = identitifier;
            //var secretVersion = "";
            KeyVaultSecret secret = await secretClient.GetSecretAsync(secretName);

            var privateKeyBytes = Convert.FromBase64String(secret.Value);

            var certificateWithPrivateKey = new X509Certificate2(privateKeyBytes,
                string.Empty, X509KeyStorageFlags.MachineKeySet);

            return certificateWithPrivateKey;
        }

        void MyLoggingMethod(Microsoft.Identity.Client.LogLevel level, string message, bool containsPii)
        {
            _logger.LogInformation("MSAL {level} {containsPii} {message}", level, containsPii, message);
        }
    }

}
