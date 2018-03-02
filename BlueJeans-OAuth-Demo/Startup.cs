using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(BlueJeans_OAuth_Demo.Startup))]
namespace BlueJeans_OAuth_Demo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
