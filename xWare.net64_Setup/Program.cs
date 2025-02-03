using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using WixSharp;
using WixSharp.CommonTasks;
using WixSharp.Forms;
using WixToolset.Dtf.WindowsInstaller;
using File = WixSharp.File;

namespace xWare.net64_Setup
{
    public class Program
    {
        [CustomAction]
        public static ActionResult CheckPrerequisite(Session session)
        {
            try
            {
                if (session.IsUninstalling())
                    return ActionResult.Success;

                string userPath = session["INSTALLDIR"];
                string detectedPath = FindInstallPath(session);
                bool isValid = false;

                if (!string.IsNullOrEmpty(userPath))
                {
                    isValid = Directory.Exists(Path.Combine(userPath, "plugins"));
                    if (!isValid)
                    {
                        session.Message(InstallMessage.Error,
                            new Record("Selected directory must contain IDA with plugins folder"));
                    }
                }
                // Fallback to detected path
                else if (!string.IsNullOrEmpty(detectedPath))
                {
                    session["INSTALLDIR"] = detectedPath;
                    isValid = Directory.Exists(Path.Combine(detectedPath, "plugins"));
                }

                session["HAS_PREREQUISITE"] = isValid ? "1" : "0";

                if (!isValid && !session.IsUninstalling())
                {
                    session.Message(InstallMessage.Error,
                        new Record("Valid IDA installation with plugins directory not found"));
                    return ActionResult.Failure;
                }
            }
            catch (Exception ex)
            {
                session.Log($"ERROR: {ex}");
                return ActionResult.Failure;
            }
            return ActionResult.Success;
        }

        static string FindInstallPath(Session session)
        {
            const string RequiredRegKey = @"SOFTWARE\Hex-Rays SA\IDA Freeware 8.3";
            const string RequiredEnvVar = "IDADIR";

            try
            {
                // Check environment variables first
                foreach (var target in new[] { EnvironmentVariableTarget.Machine, EnvironmentVariableTarget.User })
                {
                    string path = Environment.GetEnvironmentVariable(RequiredEnvVar, target);
                    if (!string.IsNullOrEmpty(path) && Directory.Exists(Path.Combine(path, "plugins")))
                        return path;
                }

                // Check registry
                foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                {
                    using (var baseKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, view))
                    {
                        var key = baseKey.OpenSubKey(RequiredRegKey);
                        if (key != null)
                        {
                            string path = (key.GetValue("Location") ?? key.GetValue(""))?.ToString();
                            if (!string.IsNullOrEmpty(path) && Directory.Exists(Path.Combine(path, "plugins")))
                                return path;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                session.Log($"Prerequisite check error: {ex}");
            }
            return null;
        }

        //static string CheckRegistry(string regKey)
        //{
        //    try
        //    {
        //        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        //        {
        //            using (var baseKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, view))
        //            {
        //                var key = baseKey.OpenSubKey(regKey);
        //                if (key != null)
        //                {
        //                    return (key.GetValue("Location") ?? key.GetValue(""))?.ToString();
        //                }
        //            }
        //        }
        //    }
        //    catch { /* Ignore errors */ }
        //    return null;
        //}

        //static string CheckEnvironmentVariables(string varName)
        //{
        //    try
        //    {
        //        foreach (var target in new[] { EnvironmentVariableTarget.Machine, EnvironmentVariableTarget.User })
        //        {
        //            string path = Environment.GetEnvironmentVariable(varName, target);
        //            if (!string.IsNullOrEmpty(path)) return path;
        //        }
        //    }
        //    catch { /* Ignore errors */ }
        //    return null;
        //}

        static void Main()
        {
            var project = new ManagedProject("xWare.net64",
                new Dir(new Id("INSTALLDIR"), @"[INSTALLDIR]",
                    new Dir(new Id("IDAPLUGINS_DIR"), "plugins",
                         new File(@"c:\temp\xWare.net_act\x64\Release\IdaShim64.dll"),
                         new File(@"c:\temp\xWare.net_act\x64\Release\xWare.net64.dll"),
                         new File(@"c:\temp\xWare.net_act\x64\Release\xWare.net64.dll.manifest"),
                         new File(@"c:\temp\xWare.net_act\x64\Release\xWare.net64.deps.json"),
                         new File(@"c:\temp\xWare.net_act\x64\Release\xWare.net64.runtimeconfig.json"),
                         new Dir(new Id("IDAMIXEDMODEPLUGIN64_DIR"), "MixedModePlugin64",
                             new File(@"c:\temp\xWare.net_act\ManagedPlugin64\bin\x64\Release\net8.0-windows7.0\ManagedPlugin64.dll"),
                             new File(@"c:\temp\xWare.net_act\ManagedPlugin64\bin\x64\Release\net8.0-windows7.0\ManagedPlugin64.deps.json"),
                             new File(@"c:\temp\xWare.net_act\ManagedPlugin64\bin\x64\Release\net8.0-windows7.0\IdaPlusPlus64.dll"),
                             new File(@"c:\temp\xWare.net_act\ManagedPlugin64\bin\x64\Release\net8.0-windows7.0\Ijwhost.dll")
                         )
                     )
                 ))
            {
                GUID = new Guid("43340A4D-8815-4C48-A03B-7697BA94D959"),
                Properties = new[]
                {
                    new Property("INSTALLDIR", GetFallbackIdaPath()),
                    new Property("HAS_PREREQUISITE", "0")
                },
                LaunchConditions = new List<LaunchCondition>
                {
                    new LaunchCondition("HAS_PREREQUISITE = \"1\" OR Installed", "IDA (Freeware) version 8.3 or later must be installed.")
                },
                Actions = new WixSharp.Action[]
                {
                    new ManagedAction("CheckPrerequisite")
                    {
                        Execute = Execute.immediate,
                        Return = Return.check,
                        When = When.Before,
                        Step = Step.AppSearch,
                        Condition = "NOT Installed"  // Only run during installation
                    }
                },
                ManagedUI = new ManagedUI()
            };

            // Configure UI to use standard INSTALLDIR property
            project.ManagedUI.InstallDialogs.Add(Dialogs.Welcome)
                                            .Add(Dialogs.InstallDir)
                                            .Add(Dialogs.Progress)
                                            .Add(Dialogs.Exit);
            project.ManagedUI.ModifyDialogs.Add(Dialogs.MaintenanceType)
                                           .Add(Dialogs.Progress)
                                           .Add(Dialogs.Exit);
            project.ManagedUI.InstallDirId = "INSTALLDIR";

            project.BuildMsi();
        }

        static string GetFallbackIdaPath()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Hex-Rays SA\IDA Freeware 8.3"))
                {
                    return key?.GetValue("Location")?.ToString() ??
                           Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                        "IDA Freeware 8.3");
                }
            }
            catch
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                    "IDA Freeware 8.3");
            }
        }
    }
}