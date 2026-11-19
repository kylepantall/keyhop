// keyhop-hello.exe: Windows Hello-gated secret and access dialog for keyhop.
//
//   keyhop-hello probe                      -> {"helloSupported": bool}
//   keyhop-hello selftest                   -> checks the WinRT plumbing without a prompt (CI)
//   keyhop-hello create [--replace]         -> {"peer": b64}
//   keyhop-hello derive <unlock|change|grant|bypass>  stdin {"peer"} -> b64 secret
//   keyhop-hello ask [--once]               $KEYHOP_ASK_MESSAGE -> deny | once | always
//                                           (--once: only Deny / Allow)
//   keyhop-hello ask [--once] --prompt      stdin: prompt lines -> deny | once | always
//                                           (who is asking and why, the secrets, and the
//                                           script it will run, highlighted)
//   keyhop-hello pipe <name>                stdin: b64 value, then the reader's pid -> "ready";
//                                           serves \\.\pipe\<name> once to that process tree,
//                                           exits when stdin closes
//
// create makes a Windows Hello key (TPM-backed where available) named "keyhop".
// derive asks Windows Hello to sign the stored challenge; RSA PKCS#1 v1.5
// signatures are deterministic, so the signature is a stable secret that only
// this user's Hello key can produce. Windows Hello's prompt can't show custom
// text, so unlock, change and grant prompts look the same.
//
// Exit codes: 0 ok, 1 error, 2 cancelled, 3 key exists (create without --replace).

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

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
                    case "selftest":
                        SelfTest();
                        return 0;
                    case "create":
                        RequireHello();
                        Console.WriteLine(Create(Array.IndexOf(args, "--replace") >= 0));
                        return 0;
                    case "derive":
                        if (args.Length < 2 || !Regex.IsMatch(args[1], "^(unlock|change|grant|bypass)$"))
                            throw new ExitException("Usage: keyhop-hello derive <unlock|change|grant|bypass>");
                        RequireHello();
                        Console.WriteLine(Derive(Console.In.ReadToEnd()));
                        return 0;
                    case "protect-auto-key":
                    case "unprotect-auto-key":
                        Console.WriteLine(AutoKey(Console.In.ReadToEnd(), command == "protect-auto-key"));
                        return 0;
                    case "ask" when Array.IndexOf(args, "--prompt") >= 0:
                        Console.WriteLine(AskPrompt(ReadPrompt(Console.In.ReadToEnd()), Array.IndexOf(args, "--once") >= 0));
                        return 0;
                    case "ask-plan":
                        Console.WriteLine(AskPrompt(ReadPrompt(Console.In.ReadToEnd()), true, plan: true));
                        return 0;
                    case "ask":
                        Console.WriteLine(Ask(Environment.GetEnvironmentVariable("KEYHOP_ASK_MESSAGE") ?? "", Array.IndexOf(args, "--once") >= 0));
                        return 0;
                    case "pipe":
                        if (args.Length < 2 || !Regex.IsMatch(args[1], "^keyhop-[0-9a-f]{32}$"))
                            throw new ExitException("Usage: keyhop-hello pipe keyhop-<32 hex>");
                        ServePipe(args[1]);
                        return 0;
                    default:
                        throw new ExitException("Usage: keyhop-hello probe | selftest | create [--replace] | derive <unlock|change|grant|bypass> | protect-auto-key | unprotect-auto-key | ask [--once] [--prompt] | ask-plan | pipe <name>");
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

        private static byte[] ReadPeer(string input)
        {
            var match = Regex.Match(input, "\"peer\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"");
            if (!match.Success) throw new ExitException("Input needs peer.");
            return Convert.FromBase64String(match.Groups[1].Value);
        }

        private static string Derive(string input)
        {
            var challenge = ReadPeer(input);
            var opened = KeyCredentialManager.OpenAsync(KeyName).AsTask().GetAwaiter().GetResult();
            AssertStatus(opened.Status.ToString());
            var signed = opened.Credential.RequestSignAsync(challenge.AsBuffer()).AsTask().GetAwaiter().GetResult();
            AssertStatus(signed.Status.ToString());
            return Convert.ToBase64String(signed.Result.ToArray());
        }

        private static string AutoKey(string input, bool protect)
        {
            var key = ReadPeer(input);
            var entropy = Encoding.UTF8.GetBytes("keyhop-auto-v1");
            byte[]? result = null;
            try
            {
                if (protect && key.Length != 32) throw new ExitException("Auto auth requires a 32-byte key.");
                result = protect
                    ? ProtectedData.Protect(key, entropy, DataProtectionScope.CurrentUser)
                    : ProtectedData.Unprotect(key, entropy, DataProtectionScope.CurrentUser);
                if (!protect && result.Length != 32) throw new ExitException("Invalid automatic vault key.");
                return Convert.ToBase64String(result);
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                if (result != null) Array.Clear(result, 0, result.Length);
            }
        }

        /// <summary>
        /// Serves the value once, to the program keyhop started (or a process it started).
        /// stdin: line 1 the base64 value, line 2 that program's pid once it runs.
        /// Exits when stdin closes, so the pipe never outlives keyhop.
        /// Only the current user may connect, and never over the network; any other
        /// process (say a shell Claude runs) is disconnected without the value.
        /// </summary>
        private static void ServePipe(string name)
        {
            var value = Convert.FromBase64String((Console.In.ReadLine() ?? "").Trim());
            var allowedPid = 0;
            var allowedKnown = new ManualResetEventSlim();
            new Thread(() =>
            {
                if (int.TryParse(Console.In.ReadLine(), out var pid))
                {
                    allowedPid = pid;
                    allowedKnown.Set();
                }
                Console.In.ReadToEnd();
                Environment.Exit(0);
            }) { IsBackground = true }.Start();

            var security = new PipeSecurity();
            security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User!, PipeAccessRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
            NamedPipeServerStream NewInstance() => new NamedPipeServerStream(name, PipeDirection.Out,
                NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.None, 0, value.Length, security);

            var served = 0;
            var waiting = NewInstance();
            Console.WriteLine("ready");
            Console.Out.Flush();
            while (true)
            {
                waiting.WaitForConnection();
                var connected = waiting;
                // Keep an instance free, so a process holding a connection open can't
                // leave the real program with "pipe busy".
                waiting = NewInstance();
                new Thread(() =>
                {
                    using (connected)
                    {
                        // The program may connect before keyhop has sent its pid.
                        if (!allowedKnown.Wait(TimeSpan.FromSeconds(30))) return;
                        if (!GetNamedPipeClientProcessId(connected.SafePipeHandle, out var client) || !IsSelfOrDescendant((int)client, allowedPid))
                            return;
                        // Served once: any later reader, even the program itself, gets nothing.
                        if (Interlocked.Exchange(ref served, 1) == 1) return;
                        try
                        {
                            connected.Write(value, 0, value.Length);
                            connected.Flush();
                            connected.WaitForPipeDrain();
                        }
                        catch (IOException)
                        {
                            // The reader went away early.
                        }
                        Environment.Exit(0);
                    }
                }) { IsBackground = true }.Start();
            }
        }

        /// <summary>
        /// Every WinRT call the Hello path makes, minus the prompt: buffers both ways
        /// and the async bridge. Lets CI (which has no Hello) check the plumbing.
        /// </summary>
        private static void SelfTest()
        {
            var hex = CryptographicBuffer.EncodeToHexString(new byte[] { 1, 2, 255 }.AsBuffer());
            var random = CryptographicBuffer.GenerateRandom(16).ToArray();
            if (hex != "0102ff" || random.Length != 16) throw new ExitException("WinRT buffer conversion failed.");
            Console.WriteLine("{\"buffers\": \"ok\", \"helloSupported\": " + (Supported() ? "true" : "false") + "}");
        }

        /// <summary>True when pid is root or one of its descendants (walks parent links).</summary>
        private static bool IsSelfOrDescendant(int pid, int root)
        {
            var parents = new System.Collections.Generic.Dictionary<int, int>();
            var snapshot = CreateToolhelp32Snapshot(0x2 /* TH32CS_SNAPPROCESS */, 0);
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return false;
            try
            {
                var entry = new ProcessEntry { Size = (uint)Marshal.SizeOf(typeof(ProcessEntry)) };
                for (var ok = Process32FirstW(snapshot, ref entry); ok; ok = Process32NextW(snapshot, ref entry))
                    parents[(int)entry.ProcessId] = (int)entry.ParentProcessId;
            }
            finally
            {
                CloseHandle(snapshot);
            }
            for (int current = pid, hops = 0; hops < 64; hops++)
            {
                if (current == root) return true;
                if (!parents.TryGetValue(current, out var parent) || parent == current || parent == 0) return false;
                current = parent;
            }
            return false;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ProcessEntry
        {
            public uint Size;
            public uint Usage;
            public uint ProcessId;
            public IntPtr DefaultHeapId;
            public uint ModuleId;
            public uint Threads;
            public uint ParentProcessId;
            public int PriorityClassBase;
            public uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string ExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry entry);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry entry);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        /// <summary>
        /// What keyhop asks the user: lines of tab-separated fields, each value base64 UTF-8.
        /// Every string is fixed wording or already made inert by keyhop (no line breaks,
        /// bidi or invisible characters of the caller's).
        /// </summary>
        private sealed class PromptData
        {
            public string Title = "keyhop", Headline = "", Message = "", Footer = "", Buttons = "once";
            public string? Reason, NoScript, ScriptLabel;
            public readonly List<(string, string)> Details = new List<(string, string)>();
            public readonly List<(string, string)> Secrets = new List<(string, string)>();
            public readonly List<(string, string)> Tokens = new List<(string, string)>();
            public readonly List<string> Warnings = new List<string>();
        }

        private static PromptData ReadPrompt(string input)
        {
            var prompt = new PromptData();
            foreach (var line in input.Split('\n'))
            {
                var f = line.TrimEnd('\r').Split('\t');
                string V(int i)
                {
                    if (i >= f.Length) return "";
                    try { return Encoding.UTF8.GetString(Convert.FromBase64String(f[i])); }
                    catch (FormatException) { return ""; }
                }
                switch (f[0])
                {
                    case "title": prompt.Title = V(1); break;
                    case "headline": prompt.Headline = V(1); break;
                    case "message": prompt.Message = V(1); break;
                    case "reason": prompt.Reason = V(1); break;
                    case "detail": prompt.Details.Add((V(1), V(2))); break;
                    case "warning": prompt.Warnings.Add(V(1)); break;
                    case "secret": prompt.Secrets.Add((V(1), V(2))); break;
                    case "noscript": prompt.NoScript = V(1); break;
                    case "scriptlabel": prompt.ScriptLabel = V(1); break;
                    case "token": prompt.Tokens.Add((f.Length > 1 ? f[1] : "plain", V(2))); break;
                    case "footer": prompt.Footer = V(1); break;
                    case "buttons": prompt.Buttons = f.Length > 1 && f[1] == "grant" ? "grant" : "once"; break;
                }
            }
            return prompt;
        }

        /// <summary>The highlighted script as RTF (fast for long scripts, and every character escaped).</summary>
        private static string ScriptRtf(List<(string, string)> tokens)
        {
            var rtf = new StringBuilder();
            rtf.Append(@"{\rtf1\ansi\deff0{\fonttbl{\f0\fmodern Consolas;}}");
            // 1 text, 2 keyword, 3 string, 4 number, 5 comment, 6 gutter, 7 hidden background
            rtf.Append(@"{\colortbl ;\red30\green30\blue30;\red155\green35\blue175;\red196\green26\blue22;\red28\green0\blue207;\red110\green110\blue110;\red165\green165\blue165;\red255\green214\blue10;}");
            rtf.Append(@"\f0\fs19 ");
            foreach (var (kind, text) in tokens)
            {
                var color = kind switch { "keyword" => 2, "string" => 3, "number" => 4, "comment" => 5, "gutter" => 6, _ => 1 };
                var bold = kind == "keyword" || kind == "hidden";
                rtf.Append(@"{\cf").Append(color);
                if (kind == "hidden") rtf.Append(@"\highlight7");
                if (bold) rtf.Append(@"\b");
                rtf.Append(' ');
                foreach (var c in text)
                {
                    if (c == '\\' || c == '{' || c == '}') rtf.Append('\\').Append(c);
                    else if (c == '\n') rtf.Append(@"\par ");
                    else if (c == '\t') rtf.Append(@"\tab ");
                    else if (c < 0x20) rtf.Append(' ');
                    else if (c > 0x7e) rtf.Append(@"\u").Append((short)c).Append('?');
                    else rtf.Append(c);
                }
                rtf.Append('}');
            }
            rtf.Append('}');
            return rtf.ToString();
        }

        /// <summary>
        /// The access dialog: who is asking and why, then the secrets and the script in sections
        /// the user can open. Deny is the default and the cancel button; closing, Escape or
        /// 3 minutes without an answer denies, and Allow only works after a second.
        /// </summary>
        private static string AskPrompt(PromptData prompt, bool onceOnly, bool plan = false)
        {
            if (plan && (prompt.Tokens.Count == 0 || prompt.Buttons != "once")) return "deny";
            Application.EnableVisualStyles();
            const int width = 620;
            var choice = "deny";
            using (var form = new Form
            {
                Text = prompt.Title,
                TopMost = true,
                StartPosition = FormStartPosition.CenterScreen,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false,
                ShowInTaskbar = true,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(14),
            })
            {
                var layout = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true };
                Label MakeLabel(string text, Font? font = null, Color? color = null) => new Label
                {
                    Text = text,
                    AutoSize = true,
                    MaximumSize = new Size(width, 0),
                    UseMnemonic = false,
                    Font = font ?? SystemFonts.MessageBoxFont,
                    ForeColor = color ?? SystemColors.ControlText,
                    Margin = new Padding(0, 0, 0, 8),
                };
                var baseFont = SystemFonts.MessageBoxFont;
                var muted = SystemColors.GrayText;

                layout.Controls.Add(MakeLabel(prompt.Headline, new Font(baseFont.FontFamily, 11f, FontStyle.Bold)));
                layout.Controls.Add(MakeLabel(prompt.Message));
                if (prompt.Reason != null) layout.Controls.Add(MakeLabel(prompt.Reason, new Font(baseFont, FontStyle.Italic)));
                foreach (var (name, value) in prompt.Details) layout.Controls.Add(MakeLabel(name + ":  " + value, null, muted));

                void Section(string title, Control content)
                {
                    var link = new LinkLabel { Text = "▸  " + title, AutoSize = true, UseMnemonic = false, Margin = new Padding(0, 4, 0, 6) };
                    content.Visible = false;
                    link.LinkClicked += (_, _) =>
                    {
                        content.Visible = !content.Visible;
                        link.Text = (content.Visible ? "▾  " : "▸  ") + title;
                    };
                    layout.Controls.Add(link);
                    layout.Controls.Add(content);
                }

                if (!plan)
                {
                    var secrets = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Margin = new Padding(14, 0, 0, 6) };
                    var mono = new Font("Consolas", 9.5f, FontStyle.Bold);
                    foreach (var (name, how) in prompt.Secrets)
                    {
                        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 2) };
                        row.Controls.Add(new Label { Text = "•  " + name, AutoSize = true, UseMnemonic = false, Font = mono, Margin = new Padding(0, 1, 6, 0) });
                        row.Controls.Add(new Label { Text = how, AutoSize = true, UseMnemonic = false, ForeColor = muted, Margin = new Padding(0, 1, 0, 0) });
                        secrets.Controls.Add(row);
                    }
                    Section("Secrets requested (" + prompt.Secrets.Count + ")", secrets);
                }

                if (plan || prompt.ScriptLabel != null)
                {
                    var box = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Margin = new Padding(0, 0, 0, 8) };
                    if (prompt.ScriptLabel != null) box.Controls.Add(MakeLabel(prompt.ScriptLabel, null, muted));
                    var code = new RichTextBox
                    {
                        Width = width,
                        Height = plan ? 260 : 340,
                        ReadOnly = true,
                        BackColor = SystemColors.Window,
                        // Long lines wrap, so nothing can hide past the right edge.
                        WordWrap = true,
                        ScrollBars = RichTextBoxScrollBars.Vertical,
                        DetectUrls = false,
                        BorderStyle = BorderStyle.FixedSingle,
                    };
                    code.Rtf = ScriptRtf(prompt.Tokens);
                    box.Controls.Add(code);
                    if (plan) layout.Controls.Add(box);
                    else Section("View script", box);
                }
                else if (prompt.NoScript != null)
                {
                    layout.Controls.Add(MakeLabel("⚠  " + prompt.NoScript));
                }
                foreach (var warning in prompt.Warnings) layout.Controls.Add(MakeLabel("⚠  " + warning));
                layout.Controls.Add(MakeLabel(prompt.Footer, null, muted));

                var buttons = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 6, 0, 0) };
                var choices = onceOnly || prompt.Buttons != "grant"
                    ? new[] { ("Deny", "deny"), ("Allow", "once") }
                    : new[] { ("Deny", "deny"), ("Allow once", "once"), ("Always allow", "always") };
                var allow = new List<Button>();
                Button? deny = null;
                foreach (var (label, value) in choices)
                {
                    var button = new Button { Text = label, AutoSize = true, MinimumSize = new Size(90, 0) };
                    button.Click += (_, _) => { choice = value; form.Close(); };
                    buttons.Controls.Add(button);
                    if (value == "deny") { deny = button; form.AcceptButton = button; form.CancelButton = button; }
                    else { button.Enabled = false; allow.Add(button); }
                }
                layout.Controls.Add(buttons);
                form.Controls.Add(layout);
                using (var enable = new System.Windows.Forms.Timer { Interval = 1_000 })
                using (var giveUp = new System.Windows.Forms.Timer { Interval = 180_000 })
                {
                    enable.Tick += (_, _) => { enable.Stop(); allow.ForEach(b => b.Enabled = true); };
                    giveUp.Tick += (_, _) => { choice = "deny"; form.Close(); };
                    form.Shown += (_, _) =>
                    {
                        form.Activate();
                        form.ActiveControl = deny;
                        enable.Start();
                        giveUp.Start();
                    };
                    form.ShowDialog();
                }
            }
            return choice;
        }

        /// <summary>Deny is the default and the cancel button; closing or 2 minutes without an answer denies.</summary>
        private static string Ask(string message, bool onceOnly)
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
                var choices = onceOnly
                    ? new[] { ("Deny", "deny"), ("Allow", "once") }
                    : new[] { ("Deny", "deny"), ("Allow once", "once"), ("Always allow", "always") };
                foreach (var (label, value) in choices)
                {
                    var button = new Button { Text = label, AutoSize = true };
                    button.Click += (_, _) => { choice = value; form.Close(); };
                    buttons.Controls.Add(button);
                    if (value == "deny") { form.AcceptButton = button; form.CancelButton = button; }
                }
                layout.Controls.Add(buttons);
                form.Controls.Add(layout);
                using (var timer = new System.Windows.Forms.Timer { Interval = 120_000 })
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
