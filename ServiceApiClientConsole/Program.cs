using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using Azure.Identity;

// Read appsettings to build Configuration
IConfigurationRoot _configuration = new ConfigurationBuilder()
    .SetBasePath(Directory.GetParent(AppContext.BaseDirectory).FullName)
    .AddJsonFile("appsettings.json", false)
    .Build();

// Get the certificate
var cert = await GetCertificateAsync();

// 1. Get Scope and Authority from appsettings
var scope = new[] {_configuration["CallApi:ScopeForAccessToken"]};
var authority = $"{_configuration["CallApi:Instance"]}{_configuration["CallApi:TenantId"]}";

// Build the ConfidentialClientApplicationBuilder
IConfidentialClientApplication app = ConfidentialClientApplicationBuilder.Create(_configuration["CallApi:ClientId"])
    .WithAuthority(new Uri(authority))
    .WithCertificate(cert)
    .Build();

// Get Access token
var authResult = await app.AcquireTokenForClient(scope) 
    .ExecuteAsync();

if(authResult == null)
{
    Console.WriteLine("no auth result... ");
}
else
{
    Console.WriteLine(authResult.AccessToken);

    // 3. Use access token to access token
    var client = new HttpClient
    {
        BaseAddress = new Uri(_configuration["AzureADServiceApi:ApiBaseAddress"])
    };

    client.DefaultRequestHeaders.Authorization 
        = new AuthenticationHeaderValue("Bearer", authResult.AccessToken);
    client.DefaultRequestHeaders.Accept
        .Add(new MediaTypeWithQualityHeaderValue("application/json"));

    var response = await client.GetAsync("ApiForServiceData");

    if (response.IsSuccessStatusCode)
    {
        Console.WriteLine(await response.Content.ReadAsStringAsync());
    }

   
}

async Task<X509Certificate2> GetCertificateAsync()
{
    // Get KV Url 
    var vaultBaseUrl = _configuration["CallApi:ClientCertificates:0:KeyVaultUrl"];

    // Get the name of the certificate from appsettings
    var certName = _configuration["CallApi:ClientCertificates:0:KeyVaultCertificateName"];


    // Create the secret client object (in this case using AzureCliCredential)
    var secretClient = new SecretClient(vaultUri: new Uri(vaultBaseUrl), credential: new AzureCliCredential());



    // Retrieve the secret from KV using the secret client. (This is the private key)
    KeyVaultSecret secret = await secretClient.GetSecretAsync(certName);

    // Private Key to Base 64
    var privateKeyBytes = Convert.FromBase64String(secret.Value);

    // New X509 Certificate object
    var certificateWithPrivateKey = new X509Certificate2(privateKeyBytes);

    return certificateWithPrivateKey;
}


