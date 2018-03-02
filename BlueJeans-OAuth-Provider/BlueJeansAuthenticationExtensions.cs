//  Copyright 2018 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;

namespace Owin.Security.Providers.BlueJeans
{
    public static class BlueJeansAuthenticationExtensions
    {
        public static IAppBuilder UseBlueJeansAuthentication(this IAppBuilder app, BlueJeansAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(BlueJeansAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseBlueJeansAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseBlueJeansAuthentication(new BlueJeansAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}