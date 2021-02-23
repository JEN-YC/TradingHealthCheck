using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using System.Net.Http.Headers;
using System.Security.Claims;
using TradingHealthCheck.Helper;

namespace TradingHealthCheck.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TradingInfoController : ControllerBase
    {


        private readonly ILogger<TradingInfoController> _logger;

        public TradingInfoController(ILogger<TradingInfoController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Get()
        {

            var authorization = Request.Headers[HeaderNames.Authorization];

            if (AuthenticationHeaderValue.TryParse(authorization, out var headerValue))
            {
                var token = headerValue.Parameter;
                if (JwtHelper.ValidateToken(token, out ClaimsPrincipal principal))
                {
                    string userID = principal.FindFirstValue("UserID");

                    // TODO: Get user's trading records from Fubon API
                    return Content(userID);
                }
            }
            Response.StatusCode = 400;
            return Content("Unauthentication");
        }
    }
}
