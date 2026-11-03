// keyhop-hello.exe: Windows Hello-gated secret and access dialog for keyhop.
//
//   keyhop-hello probe                      -> {"helloSupported": bool}
//   keyhop-hello create [--replace]         -> {"peer": b64}
//   keyhop-hello derive <unlock|change|grant>  stdin {"peer"} -> b64 secret
//   keyhop-hello ask                        $KEYHOP_ASK_MESSAGE -> deny | once | always
//   keyhop-hello pipe <name>                stdin b64 value -> "ready", then serves
//                                           \\.\pipe\<name> to the current user until killed
//
// create makes a Windows Hello key (TPM-backed where available) named "keyhop".
// derive asks Windows Hello to sign the stored challenge; RSA PKCS#1 v1.5
// signatures are deterministic, so the signature is a stable secret that only
// this user's Hello key can produce. Windows Hello's prompt can't show custom
// text, so unlock, change and grant prompts look the same.
//
// Exit codes: 0 ok, 1 error, 2 cancelled, 3 key exists (create without --replace).

using System;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Windows.Security.Credentials;

namespace Keyhop
{
    internal static class Program
    {
        private const string KeyName = "keyhop";

        private sealed class ExitException : Exception
        {
            public int Code { get; }
            public ExitException(string message, int code = 1) : base(message) { Code = code; }
        }

        [STAThread]
        private static int Main(string[] args)
        {
            try
            {
                var command = args.Length > 0 ? args[0] : "";
                switch (command)
                {
                    case "probe":
                        Console.WriteLine("{\"helloSupported\": " + (Supported() ? "true" : "false") + "}");
                        return 0;
                    case "create":
                        RequireHello();
                        Console.WriteLine(Create(Array.IndexOf(args, "--replace") >= 0));
                        return 0;
                    case "derive":
                        if (args.Length < 2 || !Regex.IsMatch(args[1], "^(unlock|change|grant)$"))
                            throw new ExitException("Usage: keyhop-hello derive <unlock|change|grant>");
                        RequireHello();
                        Console.WriteLine(Derive(Console.In.ReadToEnd()));
                        return 0;
                    case "ask":
                        Console.WriteLine(Ask(Environment.GetEnvironmentVariable("KEYHOP_ASK_MESSAGE") ?? ""));
                        return 0;
                    case "pipe":
                        if (args.Length < 2 || !Regex.IsMatch(args[1], "^keyhop-[0-9a-f]{32}$"))
                            throw new ExitException("Usage: keyhop-hello pipe keyhop-<32 hex>");
                        ServePipe(args[1], Convert.FromBase64String(Console.In.ReadToEnd().Trim()));
                        return 0;
                    default:
                        throw new ExitException("Usage: keyhop-hello probe | create [--replace] | derive <unlock|change|grant> | ask | pipe <name>");
                }
            }
            catch (ExitException error)
            {
                Console.Error.WriteLine(error.Message);
                return error.Code;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine(error.Message);
                return 1;
            }
        }

        private static bool Supported() => KeyCredentialManager.IsSupportedAsync().AsTask().GetAwaiter().GetResult();

        private static void RequireHello()
        {
            if (!Supported())
                throw new ExitException("Windows Hello is not set up. Turn it on in Settings > Accounts > Sign-in options.");
        }

        private static void AssertStatus(string status)
        {
            if (status == "UserCanceled") throw new ExitException("Authentication was cancelled.", 2);
            if (status == "NotFound") throw new ExitException("No keyhop Windows Hello key; run: keyhop setup");
            if (status != "Success") throw new ExitException("Windows Hello returned " + status + ".");
        }

        private static string Create(bool replace)
        {
            // Never clobber an existing key unless asked: it may still guard a vault.
            var option = replace ? KeyCredentialCreationOption.ReplaceExisting : KeyCredentialCreationOption.FailIfExists;
            var created = KeyCredentialManager.RequestCreateAsync(KeyName, option).AsTask().GetAwaiter().GetResult();
            if (created.Status == KeyCredentialStatus.CredentialAlreadyExists)
                throw new ExitException("A keyhop Windows Hello key already exists.", 3);
            AssertStatus(created.Status.ToString());
            var peer = new byte[32];
            using (var random = RandomNumberGenerator.Create()) random.GetBytes(peer);
            return "{\"peer\":\"" + Convert.ToBase64String(peer) + "\"}";
        }

        private static string Derive(string input)
        {
            var match = Regex.Match(input, "\"peer\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"");
            if (!match.Success) throw new ExitException("Input needs peer.");
            var challenge = Convert.FromBase64String(match.Groups[1].Value);
            var opened = KeyCredentialManager.OpenAsync(KeyName).AsTask().GetAwaiter().GetResult();
            AssertStatus(opened.Status.ToString());
            var signed = opened.Credential.RequestSignAsync(challenge.AsBuffer()).AsTask().GetAwaiter().GetResult();
            AssertStatus(signed.Status.ToString());
            return Convert.ToBase64String(signed.Result.ToArray());
        }

        /// <summary>
        /// Serves the value to every client that opens the pipe, until the process is killed.
        /// Only the current user may connect, and never over the network.
        /// </summary>
        private static void ServePipe(string name, byte[] value)
        {
            var security = new PipeSecurity();
            security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User!, PipeAccessRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
            NamedPipeServerStream NewInstance() => new NamedPipeServerStream(name, PipeDirection.Out,
                NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.None, 0, value.Length, security);

            var waiting = NewInstance();
            Console.WriteLine("ready");
            Console.Out.Flush();
            while (true)
            {
                waiting.WaitForConnection();
                var connected = waiting;
                // Open the next instance first, so a second reader never finds the pipe missing.
                waiting = NewInstance();
                new System.Threading.Thread(() => Serve(connected, value)) { IsBackground = true }.Start();
            }
        }

        private static void Serve(NamedPipeServerStream server, byte[] value)
        {
            using (server)
            {
                try
                {
                    server.Write(value, 0, value.Length);
                    server.Flush();
                    server.WaitForPipeDrain();
                }
                catch (IOException)
                {
                    // The reader went away early.
                }
            }
        }

        /// <summary>Deny is the default and the cancel button; closing or 2 minutes without an answer denies.</summary>
        private static string Ask(string message)
        {
            Application.EnableVisualStyles();
            var choice = "deny";
            using (var form = new Form
            {
                Text = "keyhop: allow access?",
                TopMost = true,
                StartPosition = FormStartPosition.CenterScreen,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false,
                ShowInTaskbar = true,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(12),
            })
            {
                var layout = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true };
                layout.Controls.Add(new Label
                {
                    Text = message,
                    AutoSize = true,
                    MaximumSize = new Size(560, 0),
                    UseMnemonic = false,
                });
                var buttons = new FlowLayoutPanel { AutoSize = true };
                foreach (var (label, value) in new[] { ("Deny", "deny"), ("Allow once", "once"), ("Always allow", "always") })
                {
                    var button = new Button { Text = label, AutoSize = true };
                    button.Click += (_, _) => { choice = value; form.Close(); };
                    buttons.Controls.Add(button);
                    if (value == "deny") { form.AcceptButton = button; form.CancelButton = button; }
                }
                layout.Controls.Add(buttons);
                form.Controls.Add(layout);
                using (var timer = new Timer { Interval = 120_000 })
                {
                    timer.Tick += (_, _) => { choice = "deny"; form.Close(); };
                    timer.Start();
                    form.Shown += (_, _) => form.Activate();
                    form.ShowDialog();
                }
            }
            return choice;
        }
    }
}
