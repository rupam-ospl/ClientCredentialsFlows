using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using ServiceApi.Policies;

namespace ServiceApi;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        IdentityModelEventSource.ShowPII = true;
        JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
        services.AddSingleton<IAuthorizationHandler, HasCharityAccountsReadAllRoleHandler>();
        services.AddMicrosoftIdentityWebApiAuthentication(Configuration);
        services.AddAuthorization(options =>
        {
            options.AddPolicy("ValidateAccessTokenPolicy", validateAccessTokenPolicy =>
            {
                validateAccessTokenPolicy.Requirements.Add(new HasCharityAccountsReadAllRoleRequirement());

                // Validate id of application for which the token was created
                // In this case the CC client application 
                validateAccessTokenPolicy.RequireClaim("aud", "api://a1ecdd8a-cb9d-41e1-99a4-5f99c6225e32");

                // only allow tokens which used "Private key JWT Client authentication"
                // // https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens
                // Indicates how the client was authenticated. For a public client, the value is "0". 
                // If client ID and client secret are used, the value is "1". 
                // If a client certificate was used for authentication, the value is "2".
                validateAccessTokenPolicy.RequireClaim("appidacr", "2");
            });
        });

        services.AddControllers();


        services
            .AddControllers(options =>
            {
                options.Filters.Add(new AuthorizeFilter());
            });

        services.AddSwaggerGen(c =>
        {
            c.EnableAnnotations();

            // add JWT Authentication
            var securityScheme = new OpenApiSecurityScheme
            {
                Name = "JWT Authentication",
                Description = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJhcGk6Ly8wOWMyNjYzNi01ZTBjLTRmZjYtYjU1MS1lMjRkNDg5MDQ2YzkiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC85YmM0MTYyNi05MmU0LTQ0MWItOGMzMy1iNzdlODEyZDI2ZGEvIiwiaWF0IjoxNjU4MjM2MzIyLCJuYmYiOjE2NTgyMzYzMjIsImV4cCI6MTY1ODI0MDIyMiwiYWlvIjoiRTJaZ1lQaW1sZjBzcWZsYThvK2JGbytmaFlmZUJRQT0iLCJhcHBpZCI6IjA5YzI2NjM2LTVlMGMtNGZmNi1iNTUxLWUyNGQ0ODkwNDZjOSIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzliYzQxNjI2LTkyZTQtNDQxYi04YzMzLWI3N2U4MTJkMjZkYS8iLCJvaWQiOiIyNGUwMGQ2YS1iNTZhLTQxYmUtYmE5ZC1hZTYzMTU1ZWVhZTAiLCJyaCI6IjAuQVM4QUpoYkVtLVNTRzBTTU03ZC1nUzBtMmpabXdna01YdlpQdFZIaVRVaVFSc2t2QUFBLiIsInN1YiI6IjI0ZTAwZDZhLWI1NmEtNDFiZS1iYTlkLWFlNjMxNTVlZWFlMCIsInRpZCI6IjliYzQxNjI2LTkyZTQtNDQxYi04YzMzLWI3N2U4MTJkMjZkYSIsInV0aSI6ImFhLTN2WjVRNDBxb1ZsalZWUzhxQUEiLCJ2ZXIiOiIxLjAifQ.ucAd4v2BU5Y3khMxSjUZnkIRgR7ePiAunSsInXSsJvTfhKsWCYx4Ot1JlcwrjsEIS_ewzqtD77OYCHYTL18BBDXCYzFkhENtdnqs51SiBJqyegfnBF3eAAeU-A8QaAq-cbiBxWpYOmpUtQenToQzfYOAGFvXGiAM3yWvaQhvPRWDRjByHiIP73YlnDaQkq6UH3ec_L-I5SuZ_VZaIdpWFYoa1-3JCtAyiATmCfZSA4JYtyvt1zJ7ez1RZtRKN82ePCEfhB7g--_mfEVXMABkaprELN4KMMrDzJigKAIYHqnZ2IJW9TXUcSFF7RRxOHVBLfXDmOtZKkiSX1-DQOZBQA",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = "bearer", // must be lower case
                BearerFormat = "JWT",
                Reference = new OpenApiReference
                {
                    Id = JwtBearerDefaults.AuthenticationScheme,
                    Type = ReferenceType.SecurityScheme
                }
            };
            c.AddSecurityDefinition(securityScheme.Reference.Id, securityScheme);
            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {securityScheme, Array.Empty<string>()}
            });

            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Service API One",
                Version = "v1",
                Description = "Service API One",
                Contact = new OpenApiContact
                {
                    Name = "Rupam Srivastava",
                    Email = string.Empty,
                    Url = new Uri("https://opaltechsolutions.uk/"),
                },
            });
        });

    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseSwagger();
        app.UseSwaggerUI(c =>
        {
            c.SwaggerEndpoint("/swagger/v1/swagger.json", "Service API One");
            c.RoutePrefix = string.Empty;
        });
        
        app.UseSerilogRequestLogging();

        app.UseHttpsRedirection();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });

       

    }
}