using AuthAPI.Dtos;
using AuthAPI.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Controllers
{
    [Authorize(Roles = "admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<AppUser> _userManager;
        public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser>
       userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }
        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto createRoleDto)
        {
            if (string.IsNullOrEmpty(createRoleDto.RoleName))
            {
                return BadRequest("Role name is Required");
            }
            var roleExist = await _roleManager.RoleExistsAsync(createRoleDto.RoleName);
            if (roleExist)
            {
                return BadRequest("Role already exist");
            }
            var roleResult = await _roleManager.CreateAsync(new
           IdentityRole(createRoleDto.RoleName));
            if (roleResult.Succeeded)
            {
                return Ok(new { message = "Role Created successfully" });
            }
            return BadRequest("Role creation failed");
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<RoleResponseDto>>> GetRoles()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            var roleDtos = new List<RoleResponseDto>();

            foreach (var role in roles)
            {
                var users = await _userManager.GetUsersInRoleAsync(role.Name!);
                roleDtos.Add(new RoleResponseDto
                {
                    Id = role.Id,
                    Name = role.Name,
                    TotalUsers = users.Count
                });
            }

            return Ok(roleDtos);
        }


        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            //delete role by their id
            var role = await _roleManager.FindByIdAsync(id);
            if (role is null)
            {
                return NotFound("Role not found.");
            }
            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
            {
                return Ok(new { message = "Role deleted successfully." });
            }
            return BadRequest("Role deletion failed.");
        }
        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignDto roleAssignDto)
        {
            var user = await _userManager.FindByIdAsync(roleAssignDto.UserId);
            if (user is null)
            {
                return NotFound("User not found");
            }
            var role = await _roleManager.FindByIdAsync(roleAssignDto.RoleId);
            if (role is null)
            {
                return NotFound("Role not found.");
            }
            var result = await _userManager.AddToRoleAsync(user, role.Name!);
            if (result.Succeeded)
            {
                return Ok(new { message = "Role assigned successfully" });
            }
            var error = result.Errors.FirstOrDefault();
            return BadRequest(error!.Description);
        }
    }
}
