using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace ServiceApi.Policies;
    
public class HasCharityAccountsReadAllRoleHandler : AuthorizationHandler<HasCharityAccountsReadAllRoleRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, HasCharityAccountsReadAllRoleRequirement requirement)
    {
        if (context == null)
            throw new ArgumentNullException(nameof(context));
        if (requirement == null)
            throw new ArgumentNullException(nameof(requirement));

        var roleClaims = context.User.Claims.Where(t => t.Type == "roles");

        //Check whatever claims need to be checked
        if (roleClaims != null && HasServiceApiRole(roleClaims))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }

    private static bool HasServiceApiRole(IEnumerable<Claim> roleClaims)
    {
        
        return roleClaims.Any(role => "AppRole.CharityAccounts.Read.All" == role.Value);
    }
}