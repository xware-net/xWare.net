using Microsoft.Win32;
using System;
using System.IO;
using System.Windows.Forms;
using WixSharp;
using WixSharp.Forms;
using File = WixSharp.File;

namespace xWare.net64_Setup
{
    public class Program
    {
        static void Main()
        {
            var idaDir = GetIdaDirectory();
            if (string.IsNullOrEmpty(idaDir))
            {
                MessageBox.Show("IDA installation directory not found", "Error");
                return;
            }

            var idaPluginsDir = Path.Combine(idaDir, "plugins");
            var idaPluginsMixedModePlugin64Dir = Path.Combine(idaPluginsDir, "MixedModePlugin64");
            var project = new ManagedProject("xWare.net64",
                new Dir(new Id("IDADIR"), idaDir,
                    new Dir(new Id("IDAPLUGINSDIR"), "plugins",
                        new File(@"c:\temp\xWare.net_act\x64\Release\IdaShim64.dll"),
                        new File(@"c:\temp\xWare.net_act\x64\Release\xWare.net64.dll"),
                        new File(@"c:\temp\xWare.net_act\x64\Release\xWare.net64.dll.manifest"),
                        new File(@"c:\temp\xWare.net_act\x64\Release\xWare.net64.deps.json"),
                        new File(@"c:\temp\xWare.net_act\x64\Release\xWare.net64.runtimeconfig.json"),
                        new Dir(new Id("IDAPLUGINSMIXMODEPLUGIN64DIR"), "MixedModePlugin64",
                            new File(@"c:\temp\xWare.net_act\ManagedPlugin64\bin\x64\Release\net8.0-windows7.0\ManagedPlugin64.dll"),
                            new File(@"c:\temp\xWare.net_act\ManagedPlugin64\bin\x64\Release\net8.0-windows7.0\ManagedPlugin64.deps.json"),
                            new File(@"c:\temp\xWare.net_act\ManagedPlugin64\bin\x64\Release\net8.0-windows7.0\IdaPlusPlus64.dll"),
                            new File(@"c:\temp\xWare.net_act\ManagedPlugin64\bin\x64\Release\net8.0-windows7.0\Ijwhost.dll")
                            )
                        )
                    )
                );

            project.GUID = new Guid("ef5777c5-d0cc-4890-80c6-8e2f1641b796");
            project.ManagedUI = new ManagedUI();
            project.ManagedUI.InstallDialogs.Add(Dialogs.Welcome)
                                            .Add(Dialogs.InstallDir)
                                            .Add(Dialogs.Progress)
                                            .Add(Dialogs.Exit);
            project.ManagedUI.ModifyDialogs.Add(Dialogs.MaintenanceType)
                                           .Add(Dialogs.Progress)
                                           .Add(Dialogs.Exit);
            project.ManagedUI.InstallDirId = "IDADIR";
            project.BuildMsi();
        }

        private static string GetIdaDirectory()
        {
            // Get the IDA installation directory from the environment variable IDADIR
            var idaDir = System.Environment.GetEnvironmentVariable("IDADIR");
            if (!string.IsNullOrEmpty(idaDir))
            {
                return idaDir;
            }
            // 
            var idaKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Hex-Rays SA\IDA Freeware 8.3");
            if ((idaKey != null) && (!string.IsNullOrEmpty(idaKey.GetValue("Location") as string)))
            {
                return idaKey.GetValue("Location") as string;
            }
            return string.Empty;
        }
    }
}