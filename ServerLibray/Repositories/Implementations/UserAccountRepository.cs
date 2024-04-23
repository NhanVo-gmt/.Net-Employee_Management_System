using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ServerLibray.Data;
using ServerLibray.Helpers;
using ServerLibray.Repositories.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerLibray.Repositories.Implementations
{
    public class UserAccountRepository(IOptions<JwtSection> config, AppDbContext context) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user is null) return new GeneralResponse(false, "Model is empty");

            var checkUser = await FindUserByEmail(user.Email!);
            if (checkUser != null) return new GeneralResponse(false, "User already registered");

            // Save User 
            var applicationUser = await AddToDatabase(new ApplicationUser()
            {
                FullName = user.FullName,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            // Check and assign rules
            var checkAdminRole = await context.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin });
                await AddToDatabase(new UserRole() { RoleId = createAdminRole.Id, UserID = applicationUser.Id });
                return new GeneralResponse(true, "Accounts created !");
            }

            var checkUserRole = await context.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));
            SystemRole response = new SystemRole();
            if (checkUserRole is null)
            {
                response = await AddToDatabase(new SystemRole() { Name = Constants.User });
                await AddToDatabase(new UserRole() { RoleId = response.Id, UserID = applicationUser.Id });
            }
            else
            {
                await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserID = applicationUser.Id });

            }
            return new GeneralResponse(true, "Accounts created !");
        }

        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = context.Add(model!);
            await context.SaveChangesAsync();
            return (T)result.Entity;
        }

        private async Task<ApplicationUser> FindUserByEmail(string email)
        {
            return await context.ApplicationUsers.FirstOrDefaultAsync(_ => _.Email!.ToLower()!.Equals(email!.ToLower()));
        }

        public Task<LoginResponse> SignInAsync(Login user)
        {
            throw new NotImplementedException();
        }
    }
}
