#pragma checksum "C:\Users\sasmita\source\repos\SecurityDemo\SecurityDemo\Views\Home\Manage.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "5237fb1ea4e98ecd28495bc905d3cfcee1967bdc"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Home_Manage), @"mvc.1.0.view", @"/Views/Home/Manage.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Home/Manage.cshtml", typeof(AspNetCore.Views_Home_Manage))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 1 "C:\Users\sasmita\source\repos\SecurityDemo\SecurityDemo\Views\_ViewImports.cshtml"
using SecurityDemo;

#line default
#line hidden
#line 2 "C:\Users\sasmita\source\repos\SecurityDemo\SecurityDemo\Views\_ViewImports.cshtml"
using SecurityDemo.Models;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"5237fb1ea4e98ecd28495bc905d3cfcee1967bdc", @"/Views/Home/Manage.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"300fc8b18d60f9f70a82cdbe8213e978607e4c4f", @"/Views/_ViewImports.cshtml")]
    public class Views_Home_Manage : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 40, true);
            WriteLiteral("<h2>Manage your account</h2>\r\n<p>Name : ");
            EndContext();
            BeginContext(41, 18, false);
#line 2 "C:\Users\sasmita\source\repos\SecurityDemo\SecurityDemo\Views\Home\Manage.cshtml"
     Write(User.Identity.Name);

#line default
#line hidden
            EndContext();
            BeginContext(59, 15, true);
            WriteLiteral("</p>\r\n<p>Role: ");
            EndContext();
            BeginContext(75, 84, false);
#line 3 "C:\Users\sasmita\source\repos\SecurityDemo\SecurityDemo\Views\Home\Manage.cshtml"
    Write(User.FindFirst(claim => claim.Type == System.Security.Claims.ClaimTypes.Role)?.Value);

#line default
#line hidden
            EndContext();
            BeginContext(159, 8, true);
            WriteLiteral("</p>\r\n\r\n");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591