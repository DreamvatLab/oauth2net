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

        // Diagnostic endpoint — always 200 (just [Authorize]); shows whether the "role" claim is
        // readable by its short literal type. This is the lookup production code does
        // (claim.Type == "role"). If inbound claim mapping is broken, RoleFoundByShortName is false
        // and you'll see the legacy WS-* URI (.../claims/role) in Claims instead of a plain "role".
        [HttpGet("/roleinfo")]
        public IActionResult RoleInfo()
        {
            var shortRole = User.FindFirst("role");

            return new JsonResult(new
            {
                RoleFoundByShortName = shortRole != null,
                RoleValue = shortRole?.Value,
                IsInRole_4 = User.IsInRole("4"), // interactive login issues role "4" (see auth/MyTokenClaimBuilder)
                Claims = User.Claims.Select(c => new { c.Type, c.Value }),
            });
        }

        // Role-based authorization end to end — mirrors the production scenario.
        // 200 means roles are read correctly; 403 reproduces the post-upgrade bug.
        [Authorize(Roles = "4")]
        [HttpGet("/roleprotected")]
        public IActionResult RoleProtected()
            => Content("OK: role-based authorization passed (token role contains 4).");
    }

    public class UserDTO
    {
        public string Name { get; set; }
        public DateTime CreatedOnUtc { get; set; }
    }
}
