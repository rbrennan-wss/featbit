using System.Text;
using Api.Authentication;
using Api.Authorization;
using Api.Swagger;
using Domain.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Swashbuckle.AspNetCore.Filters;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.Configuration;
using System.Security.AccessControl;
using IdentityModel.Client;
using Microsoft.Extensions.DependencyInjection;

//using Microsoft.Extensions.Options;
//using Microsoft.OpenApi.Models;
//using Swashbuckle.AspNetCore.SwaggerGen;
using System;
using System.Collections.Generic;
using System.Net.Http;
using static IdentityModel.ClaimComparer;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Api.Setup;

public static class ServicesRegister
{
    public static WebApplicationBuilder RegisterServices(this WebApplicationBuilder builder)
    {
        // add services for controllers
        builder.Services.AddTransient<IConfigureOptions<MvcOptions>, ConfigureMvcOptions>();
        builder.Services.AddControllers();

        // make all generated paths URLs are lowercase
        builder.Services.Configure<RouteOptions>(options => options.LowercaseUrls = true);

        // api versioning
        builder.Services
            .AddApiVersioning(options => options.ReportApiVersions = true)
            .AddMvc()
            .AddApiExplorer(options =>
            {
                // add the versioned api explorer, which also adds IApiVersionDescriptionProvider service
                // note: the specified format code will format the version as "'v'major[.minor][-status]"
                options.GroupNameFormat = "'v'VVV";

                // note: this option is only necessary when versioning by url segment. the SubstitutionFormat
                // can also be used to control the format of the API version in route templates
                options.SubstituteApiVersionInUrl = true;
            });

        // cors
        builder.Services.AddCors(options => options.AddDefaultPolicy(policyBuilder =>
        {
            policyBuilder
                .AllowAnyOrigin()
                .AllowAnyHeader()
                .AllowAnyMethod();
        }));

        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddTransient<IConfigureOptions<SwaggerGenOptions>, ConfigureSwaggerOptions>();
        builder.Services.AddSwaggerGen(opts =>
        {
            var scheme = new OpenApiSecurityScheme
            {
                In = ParameterLocation.Header,
                Name = "Authorization",
                Flows = new OpenApiOAuthFlows
                {
                    AuthorizationCode = new OpenApiOAuthFlow
                    {
                        AuthorizationUrl = new Uri(builder.Configuration.GetSection("ExternalAuth:Auth_Endpoint").Get<string>()),
                        TokenUrl = new Uri(builder.Configuration.GetSection("ExternalAuth:Token_Endpoint").Get<string>())
                    }
                },
                Type = SecuritySchemeType.OAuth2
            };

            opts.AddSecurityDefinition("OAuth", scheme);

            opts.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference { Id = "OAuth", Type = ReferenceType.SecurityScheme }
                    },
                    new List<string> { }
                }
            });
        });
        builder.Services.AddSwaggerExamplesFromAssemblyOf<Program>();

        // health check dependencies
        builder.Services.AddHealthChecks();

        // add infrastructure & application services
        builder.Services.AddInfrastructureServices(builder.Configuration);
        builder.Services.AddApplicationServices();

        // authentication
        var jwtOption = builder.Configuration.GetSection(JwtOptions.Jwt);
        builder.Services.Configure<JwtOptions>(jwtOption);
        builder.Services
            .AddAuthentication(options =>
            {
                //options.DefaultScheme = Schemes.SchemeSelector;
                //options.DefaultChallengeScheme = Schemes.SchemeSelector;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddPolicyScheme(Schemes.SchemeSelector, Schemes.SchemeSelector, options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    if (Convert.ToBoolean(builder.Configuration["ExternalAuth:Enabled"]))
                    {
                        return Schemes.External;
                    }
                    string authorization = context.Request.Headers[HeaderNames.Authorization];
                    if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
                    {
                        return Schemes.JwtBearer;
                    }

                    return Schemes.OpenApi;
                };
            })
            //.AddJwtBearer(Schemes.JwtBearer, options =>
            //{
            //    options.TokenValidationParameters = new TokenValidationParameters
            //    {
            //        AuthenticationType = Schemes.JwtBearer,

            //        ValidateIssuer = true,
            //        ValidIssuer = jwtOption["Issuer"],

            //        ValidateAudience = true,
            //        ValidAudience = jwtOption["Audience"],

            //        ValidateIssuerSigningKey = false,
            //        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOption["Key"]))
            //    };
            //})
            .AddJwtBearer(Schemes.JwtBearer, o =>
            {
                var stsDiscoveryEndpoint = $"{builder.Configuration["ExternalAuth:Authority"]}/.well-known/openid-configuration";
                var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());
                var config = Task.Run(configManager.GetConfigurationAsync).Result;

                var mySigningKey = "OD0RpLEYpqU6CmvzisHvUv4XK015gcdn";

                var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(mySigningKey));
                var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

                var jwks = config.JsonWebKeySet;
                var jwk = jwks.Keys.First();

                var tokenHandler = new JwtSecurityTokenHandler();

                var validationParameters = new TokenValidationParameters()
                {
                    AuthenticationType = Schemes.External,

                    ValidateIssuer = true,
                    //ValidIssuer = jwtOption["Issuer"],
                    ValidIssuer = config.Issuer,
                    IssuerSigningKeys = config.SigningKeys,

                    ValidateAudience = true,
                    //ValidAudience = jwtOption["Audience"],
                    ValidAudience = "featbit",

                    ValidateIssuerSigningKey = true,
                    //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOption["Key"]))
                    //IssuerSigningKey = signingCredentials.Key
                    IssuerSigningKey = jwk
                };

                o.MetadataAddress = $"{builder.Configuration["ExternalAuth:Authority"]}/.well-known/openid-configuration";
                o.Authority = builder.Configuration["ExternalAuth:Authority"];
                o.Audience = "featbit";
            })
            .AddOpenApi(Schemes.OpenApi);

        // authorization
        builder.Services.AddSingleton<IPermissionChecker, DefaultPermissionChecker>();
        builder.Services.AddSingleton<IAuthorizationHandler, PermissionRequirementHandler>();
        builder.Services.AddAuthorization(options =>
        {
            foreach (var permission in Permissions.All)
            {
                options.AddPolicy(
                    permission,
                    policyBuilder => policyBuilder.AddRequirements(new PermissionRequirement(permission))
                );
            }
        });

        // replace default authorization result handler
        //var authorizationResultHandler =
        //    ServiceDescriptor.Singleton<IAuthorizationMiddlewareResultHandler>(new ApiAuthorizationResultHandler());
        //builder.Services.Replace(authorizationResultHandler);

        return builder;
    }
}