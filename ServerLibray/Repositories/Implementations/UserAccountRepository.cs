using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using ServerLibray.Repositories.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerLibray.Repositories.Implementations
{
    public class UserAccountRepository : IUserAccount
    {
        public Task<GeneralResponse> CreateAsync(Register user)
        {
            throw new NotImplementedException();
        }

        public Task<LoginResponse> SignInAsync(Login user)
        {
            throw new NotImplementedException();
        }
    }
}
