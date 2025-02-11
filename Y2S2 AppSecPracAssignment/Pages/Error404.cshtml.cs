using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Y2S2_AppSecPracAssignment.Pages
{
    public class Error404Model : PageModel
    {
        [BindProperty(SupportsGet = true)]
        public int Code { get; set; }

        public void OnGet()
        {
            // Optional: Log the error or set a message
        }
    }
}
