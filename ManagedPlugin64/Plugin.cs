using ManagedPlugin.Source;
using System;

namespace ManagedPlugin
{
    public class Plugin : PluginBase
    {
        protected override void DoRun(string name)
        {
            try
            {
                switch (name)
                {
                    case "Test":
                        Test.Run();
                        break;
                    case "ClassInformer":
                        ClassInformer.Run();
                        break;
                }
            }
            catch (Exception ex)
            {
                WriteDebugMessage($"{ex.Message}\r\n{ex.StackTrace}");
            }
            finally
            {
            }

        }

        /*
        protected override void DoRun()
        {
            //IdaInfo idaInfo = IdaInfo.GetIdaInfo();
            //WriteDebugMessage(idaInfo.ToString());

            //WriteDebugMessage($"dllEntryPoint={Name.ida_get_name(idaInfo.start_ip, DefineConstants.GN_VISIBLE)}");

            //Interactivity.Info("a message");
            //Interactivity.Warning("a warning");
            //Interactivity.Message("first message\r\n");
            //Interactivity.Message("second message\r\n");
            //Interactivity.Message("...\r\n");
            //Interactivity.Message("last message\r\n");

            //var segments = Segments.EnumerateSegments();
            //foreach (var segment in segments)
            //{
            //    WriteDebugMessage(segment.ToString());
            //}

            //var enums = Enums.EnumerateEnums();
            //foreach(var e in enums)
            //{
            //    WriteDebugMessage(e.ToString());
            //}
            try
            {
                ClassInformer.Run();
            }
            catch (Exception ex)
            {
                WriteDebugMessage($"{ex.Message}\r\n{ex.StackTrace}");
            }
            finally
            {
            }

            //var entryPoints = EntryPoint.EnumerateEntryPoints();
            //foreach (var entryPoint in entryPoints)
            //{
            //    //WriteDebugMessage("EntryPoint {0} at 0x{1:X}", entryPoint.Name, entryPoint.Address);
            //    var demangledName = Name.ida_get_long_name(entryPoint.Address, DefineConstants.GN_LONG); // Name.ida_get_demangled_name(entryPoint.Address, DefineConstants.MNG_LONG_FORM, , DefineConstants.GN_LONG);
            //    //WriteDebugMessage($"{demangledName}");
            //    //IdaPlusPlus.IdaInterop.ida_decompile_func(entryPoint.Address);
            //}


        }
        */
    }
}
