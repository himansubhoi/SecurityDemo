#pragma checksum "C:\Users\sasmita\source\repos\SecurityDemo\SecurityDemo\Views\Home\ErrorNotLoggedIn.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "e923224c62aa4febd5a57248d70cdc77fb7274e8"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Home_ErrorNotLoggedIn), @"mvc.1.0.view", @"/Views/Home/ErrorNotLoggedIn.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Home/ErrorNotLoggedIn.cshtml", typeof(AspNetCore.Views_Home_ErrorNotLoggedIn))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"e923224c62aa4febd5a57248d70cdc77fb7274e8", @"/Views/Home/ErrorNotLoggedIn.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"300fc8b18d60f9f70a82cdbe8213e978607e4c4f", @"/Views/_ViewImports.cshtml")]
    public class Views_Home_ErrorNotLoggedIn : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 84, true);
            WriteLiteral("<h2>Error</h2>\r\n<div>\r\n    <p>You must be logged in to view this page.</p>\r\n</div>\r\n");
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