using Microsoft.AspNetCore.Mvc;

namespace IDAustriaDemo.Controller.V1;

[ApiController]
[Route("[controller]/v1")]
public class ApiController : ControllerBase
{
    private readonly ILogger<ApiController> _logger;

    public ApiController(
        ILogger<ApiController> logger
    )
    {
        _logger = logger;
    }

    [HttpGet]
    [Route(nameof(Test))]
    public IEnumerable<int> Test()
    {
        return Enumerable.Range(1, 10);
    }
}
