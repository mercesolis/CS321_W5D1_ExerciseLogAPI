using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using CS321_W5D1_ExerciseLogAPI.Core.Models;
using System.Threading.Tasks;
using CS321_W5D1_ExerciseLogAPI.ApiModels;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace CS321_W5D1_ExerciseLogAPI.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly UserManager<User> _userManager;


        // TODO: Prep Part 1: add constructor and inject UserManager
        public AuthController(UserManager<User> userManager)
        {
            _userManager = userManager;
        }

        // TODO: Prep Part 2: inject IConfiguration in the constructor

        // TODO: Prep Part 1: Add a Registration Action (Part 1 of Prep exercise)
        //POST api/auth/register
        //[AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegistrationModel registration)
        {
            // map registration model into a new AppUser domain object
            var newUser = new User
            {
                UserName = registration.Email,
                Email = registration.Email,
                FirstName = registration.FirstName,
                LastName = registration.LastName
            };
            // call UserManager to create new user and hash password
            var result = await _userManager.CreateAsync(newUser, registration.Password);
            if (result.Succeeded)
            {
                return Ok();
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return BadRequest(ModelState);
        }
    }

    // TODO: Prep Part 2: Add a login action (Part 2 of Prep exercise)

}

