// keyhop-hello.exe: the Windows side of keyhop's biometric unlock.
//
//   keyhop-hello create [--replace]          -> {"peer": b64}
//   keyhop-hello derive <unlock|change|grant>  stdin {"peer": b64} -> b64 secret
//   keyhop-hello ask                         stdin message -> deny | once | always
//   keyhop-hello selftest                    -> checks the WinRT calls work (CI)
//
// create makes a Windows Hello key (TPM-backed where available) named
// "keyhop". derive asks Windows Hello to sign the stored challenge; RSA
// PKCS#1 v1.5 signatures are deterministic, so the signature is a stable
// secret that only this user's Hello key can produce.
//
// Exit codes: 0 ok, 1 error, 2 cancelled, 3 key exists (create without --replace).
//
// Windows Hello's signing prompt can't show custom text, so unlock and change
// prompts look the same; only approve a prompt you expected.

using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace KeyhopHello
{
    internal sealed class ExitException : Exception
    {
        public ExitException(string message, int code) : base(message) { Code = code; }
        public int Code { get; }
    }

    internal static class Program
    {
        private const int Failed = 1;
        private const int Cancelled = 2;
        private const int KeyExists = 3;
        private const string KeyName = "keyhop";
        private const string Usage = "Usage: keyhop-hello create [--replace] | derive <unlock|change|grant> | ask | selftest";

        [STAThread]
        private static int Main(string[] args)
        {
            try
            {
                switch (args.Length > 0 ? args[0] : "")
                {
                    case "create":
                        Create(args.Contains("--replace"));
                        return 0;
                    case "derive":
                        Derive(ReadStdin());
                        return 0;
                    case "ask":
                        Console.Out.WriteLine(Ask(ReadStdin()));
                        return 0;
                    case "selftest":
                        SelfTest();
                        return 0;
                    default:
                        throw new ExitException(Usage, Failed);
                }
            }
            catch (ExitException e)
            {
                Console.Error.WriteLine(e.Message);
                return e.Code;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.GetBaseException().Message);
                return Failed;
            }
        }

        private static string ReadStdin()
        {
            using (var reader = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false)))
                return reader.ReadToEnd();
        }

        private static void RequireHello()
        {
            if (!KeyCredentialManager.IsSupportedAsync().AsTask().GetAwaiter().GetResult())
                throw new ExitException("Windows Hello is not set up. Turn it on in Settings > Accounts > Sign-in options.", Failed);
        }

        private static void Check(KeyCredentialStatus status)
        {
            if (status == KeyCredentialStatus.Success) return;
            if (status == KeyCredentialStatus.UserCanceled) throw new ExitException("Authentication was cancelled.", Cancelled);
            if (status == KeyCredentialStatus.NotFound) throw new ExitException("No keyhop Windows Hello key; run: keyhop setup", Failed);
            throw new ExitException("Windows Hello returned " + status + ".", Failed);
        }

        private static void Create(bool replace)
        {
            RequireHello();
            // Never clobber an existing key unless asked: it may still guard a vault.
            var option = replace ? KeyCredentialCreationOption.ReplaceExisting : KeyCredentialCreationOption.FailIfExists;
            var created = KeyCredentialManager.RequestCreateAsync(KeyName, option).AsTask().GetAwaiter().GetResult();
            if (created.Status == KeyCredentialStatus.CredentialAlreadyExists)
                throw new ExitException("A keyhop Windows Hello key already exists.", KeyExists);
            Check(created.Status);
            var peer = new byte[32];
            using (var random = RandomNumberGenerator.Create()) random.GetBytes(peer);
            Console.Out.WriteLine("{\"peer\":\"" + Convert.ToBase64String(peer) + "\"}");
        }

        private static void Derive(string input)
        {
            // The input is keyhop's own {"peer": "<base64>", ...}; base64 needs no JSON unescaping.
            var match = Regex.Match(input, "\"peer\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"");
            if (!match.Success) throw new ExitException("Input needs peer.", Failed);
            var challenge = Convert.FromBase64String(match.Groups[1].Value);
            RequireHello();
            var opened = KeyCredentialManager.OpenAsync(KeyName).AsTask().GetAwaiter().GetResult();
            Check(opened.Status);
            var signed = opened.Credential.RequestSignAsync(challenge.AsBuffer()).AsTask().GetAwaiter().GetResult();
            Check(signed.Status);
            Console.Out.WriteLine(Convert.ToBase64String(signed.Result.ToArray()));
        }

        /// <summary>Deny / Allow once / Always allow. Closing the window or waiting 2 minutes denies.</summary>
        private static string Ask(string message)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var choice = "deny";
            using (var form = new Form())
            {
                form.Text = "keyhop: allow access?";
                form.TopMost = true;
                form.StartPosition = FormStartPosition.CenterScreen;
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.MinimizeBox = false;
                form.ShowInTaskbar = true;
                form.AutoSize = true;
                form.AutoSizeMode = AutoSizeMode.GrowAndShrink;
                form.Padding = new Padding(12);

                var layout = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true };
                // UseMnemonic off: an & in the message is shown, never turned into a shortcut.
                layout.Controls.Add(new Label
                {
                    Text = message.TrimEnd(),
                    AutoSize = true,
                    MaximumSize = new Size(560, 0),
                    UseMnemonic = false,
                });

                var buttons = new FlowLayoutPanel { AutoSize = true };
                foreach (var pair in new[] { new[] { "Deny", "deny" }, new[] { "Allow once", "once" }, new[] { "Always allow", "always" } })
                {
                    var button = new Button { Text = pair[0], AutoSize = true, Tag = pair[1] };
                    button.Click += (sender, e) =>
                    {
                        choice = (string)((Button)sender).Tag;
                        form.Close();
                    };
                    buttons.Controls.Add(button);
                    if (pair[1] == "deny")
                    {
                        form.AcceptButton = button;
                        form.CancelButton = button;
                    }
                }
                layout.Controls.Add(buttons);
                form.Controls.Add(layout);

                using (var timer = new Timer { Interval = 120000 })
                {
                    timer.Tick += (sender, e) =>
                    {
                        choice = "deny";
                        form.Close();
                    };
                    timer.Start();
                    form.ShowDialog();
                }
            }
            return choice;
        }

        /// <summary>Runs the WinRT calls Hello needs, minus the prompt: buffers both ways and the async bridge.</summary>
        private static void SelfTest()
        {
            var hex = CryptographicBuffer.EncodeToHexString(new byte[] { 1, 2, 255 }.AsBuffer());
            var random = CryptographicBuffer.GenerateRandom(16).ToArray();
            var supported = KeyCredentialManager.IsSupportedAsync().AsTask().GetAwaiter().GetResult();
            Console.Out.WriteLine("buffer " + hex + " " + random.Length + " hello " + (supported ? "supported" : "unavailable"));
        }
    }
}
