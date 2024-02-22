using ASPDotNetCRUDApp.Data;
using ASPDotNetCRUDApp.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ASPDotNetCRUDApp.Controllers
{
    [Authorize]
    //[Authorize(AuthenticationSchemes =JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")] //api/teams
    [ApiController]
    public class TeamsController : ControllerBase
    {

        private static AppDbContext _context;

        public TeamsController(AppDbContext context)
        { 
            _context = context;
        }
        //private static List<Team> teams = new List<Team>()
        //{
        //    new Team()
        //    {
        //        ID = 1,
        //        Country="Germany",
        //        Name="Mercedes AMG F1",
        //        TeamPrinciple="Toto Wolf"
        //    }, 
        //    new Team()
        //    {
        //        ID = 2,
        //        Country="Italy",
        //        Name="Ferrari",
        //        TeamPrinciple="Mattia Bonitto"
        //    },
        //    new Team()
        //    {
        //        ID = 3,
        //        Country="Swiss",
        //        Name="Alpha Romeo",
        //        TeamPrinciple="Romeos Paradise"
        //    }
        //};

        [HttpGet]
        //[HttpGet("GetBestTeam")]
        //[Route("GetBestTeam")]
        [Authorize]
        public async Task<IActionResult> Get()
        {
            var teams = await _context.Teams.ToListAsync(); 
            return Ok(teams);
        }
        //[HttpGet("GetTeamByID/{id:int}")]
        [HttpGet("{id:int}")]
        [Authorize]
        public async Task<IActionResult> Get(int id)
        {
            var team = await _context.Teams.FirstOrDefaultAsync(x => x.ID == id);
            if(team == null)
            {
                return BadRequest("No data found for this ID");
            }
            return Ok(team);
        }

        [HttpPost]
        [Authorize]

        public async Task<IActionResult> Post(Team team)
        {
            await _context.Teams.AddAsync(team);
            await _context.SaveChangesAsync();
            return CreatedAtAction($"Get", new { id = team.ID }, team);//actionName,routeValue,object
        }

        [HttpPatch]
        [Authorize]

        public async Task<IActionResult> Patch(int id, string Country)
        {
            var team = await _context.Teams.FirstOrDefaultAsync(x => x.ID == id);
         
            if (team == null)
            {
                return BadRequest("No data found for this ID");
            }
            team.Country = Country;
            await _context.SaveChangesAsync();
            return NoContent();
        }
        [HttpDelete]
        [Authorize]
        public async Task<IActionResult> Delete(int id)
        {
            var team = await _context.Teams.FirstOrDefaultAsync(x => x.ID == id);
            if (team == null)
            {
                return BadRequest("No data found for this ID");
            }
            _context.Teams.Remove(team);
            await _context.SaveChangesAsync();
            return NoContent();
        }
    }
}
