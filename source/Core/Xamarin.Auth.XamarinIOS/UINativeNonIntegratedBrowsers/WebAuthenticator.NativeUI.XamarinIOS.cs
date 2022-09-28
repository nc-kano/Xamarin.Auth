using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using AuthenticationServices;
using Foundation;
using ObjCRuntime;
using Plugin.Threading;
using SafariServices;
using UIKit;
using AuthenticateUIType =
            SafariServices.SFSafariViewController
            //System.Object
            ;

namespace Xamarin.Auth
{
    #if XAMARIN_AUTH_INTERNAL
    internal partial class WebAuthenticator
    #else
    public partial class WebAuthenticator
    #endif
    {
#if __IOS__
        [DllImport(Constants.ObjectiveCLibrary, EntryPoint = "objc_msgSend")]
        [SuppressMessage("Style", "IDE1006:Naming Styles", Justification = "Required for iOS Export")]
        [SuppressMessage("StyleCop.CSharp.NamingRules", "SA1300:Element should begin with upper-case letter", Justification = "Required for iOS Export")]
        static extern void void_objc_msgSend_IntPtr(IntPtr receiver, IntPtr selector, IntPtr arg1);
        
        static ASWebAuthenticationSession was;
        static SFAuthenticationSession sf;
        
        [Adopts("ASWebAuthenticationPresentationContextProviding")]
        class ContextProvider : NSObject
        {
            public ContextProvider(UIWindow window) =>
                Window = window;

            public UIWindow Window { get; private set; }

            [Export("presentationAnchorForWebAuthenticationSession:")]
            public UIWindow GetPresentationAnchor(ASWebAuthenticationSession session)
                => Window;
        }
        internal static UIWindow GetCurrentWindow(bool throwIfNull = true)
        {
            var window = UIApplication.SharedApplication.KeyWindow;

            if (window != null && window.WindowLevel == UIWindowLevel.Normal)
                return window;

            if (window == null)
            {
                window = UIApplication.SharedApplication
                    .Windows
                    .OrderByDescending(w => w.WindowLevel)
                    .FirstOrDefault(w => w.RootViewController != null && w.WindowLevel == UIWindowLevel.Normal);
            }

            if (throwIfNull && window == null)
                throw new InvalidOperationException("Could not find current window.");

            return window;
        }
        
        internal static NSUrl GetNativeUrl(Uri uri)
        {
            try
            {
                return new NSUrl(uri.OriginalString);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Unable to create NSUrl from Original string, trying Absolute URI: {ex.Message}");
                return new NSUrl(uri.AbsoluteUri);
            }
        }
#endif
        /// <summary>
        /// Gets or sets the get platform UIMethod.
        /// Func (delegate) pointing to the method that generates authentication UI
        /// </summary>
        /// <value>The get platform UIM ethod.</value>
        public Func<AuthenticateUIType> PlatformUIMethod
        {
            get;
            set;
        }

        protected bool StartPrivateSession(Uri url, Uri redirectUri)
        {
            if (was != null)
            {
                was.Cancel();
            }
            if (UIDevice.CurrentDevice.CheckSystemVersion(13, 0))
            {
                was = new ASWebAuthenticationSession(
                    GetNativeUrl(url),
                    redirectUri.Scheme,
                    (callbackUrl, error) =>
                    {
                        if (error != null)
                        {
                            OnCancelled();
                        }
                    });
                var ctx = new ContextProvider(GetCurrentWindow());
                void_objc_msgSend_IntPtr(
                    was.Handle,
                    Selector.GetHandle("setPresentationContextProvider:"),
                    ctx.Handle);
                was.PrefersEphemeralWebBrowserSession = true;
                was.Start();
                return true;
            }

            return false;
        }
        
        protected AuthenticateUIType GetPlatformUINative()
        {
            Uri uri_netfx = GetInitialUrlAsync().Result;
            NSUrl url_ios = new NSUrl(uri_netfx.AbsoluteUri);

            Uri redirectUri = null;
            if (this is OAuth2Authenticator auth)
            {
                redirectUri = auth.redirectUrl;
            }
            var startPrivateSession = StartPrivateSession(uri_netfx, redirectUri);
            if (startPrivateSession)
            {
                return null;
            }
            // SafariServices.SFSafariViewController 
            AuthenticateUIType ui = null;

            SFSafariViewController sfvc = null;

            if 
                ( 
                    // double check (trying to lookup class and check iOS version)
                    Class.GetHandle("SFSafariViewController") != IntPtr.Zero
                    &&
                    UIDevice.CurrentDevice.CheckSystemVersion (9, 0)
                )
            {
                
                sfvc = new SFSafariViewController(url_ios, false);

                #if DEBUG
                Title = "Auth " + sfvc.GetType();
                Debug.WriteLine($"SFSafariViewController.Title = {Title}");
                #endif

                sfvc.Delegate = new NativeAuthSafariViewControllerDelegate(this);
                sfvc.Title = Title;

                ui = sfvc;
            }
            else
            {
                // Fallback to Embedded WebView
                StringBuilder msg = new StringBuilder();
                msg.AppendLine("SafariViewController not available!");
                msg.AppendLine("Fallback to embbeded web view ");
                ShowErrorForNativeUIAlert(msg.ToString());

                GetPlatformUIEmbeddedBrowser();
            }

            return ui;
        }

        protected void ShowErrorForNativeUIAlert(string v)
        {
            new UIThreadRunInvoker()
                .BeginInvokeOnUIThread
                (
                    () =>
                    {
                        var alert = new UIAlertView
                        (
                            "WARNING",
                            v,
                            null,
                            "Ok",
                            null
                        );
                        alert.Show();
                    }
                );
        }
    }
}

