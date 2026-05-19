using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;

namespace api.Controllers {
    [ApiController]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly ILogger<UserController> _logger;

        public UserController(ILogger<UserController> logger)
        {
            _logger = logger;
        }

        [HttpGet("/users")]
        public IEnumerable<UserDTO> GetUsers()
        {
            _logger.LogDebug(User.Identity.Name);

            return Enumerable.Range(1, 5).Select(i => new UserDTO
            {
                Name = $"User {i:000}",
                CreatedOnUtc = DateTime.UtcNow,
            })
            .ToArray();
        }
    }

    public class UserDTO
    {
        public string Name { get; set; }
        public DateTime CreatedOnUtc { get; set; }
    }
}
