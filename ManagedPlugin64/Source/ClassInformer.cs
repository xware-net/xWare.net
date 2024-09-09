using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using ea_t = System.UInt64;
using sel_t = System.UInt64;
using size_t = System.UInt64;
using asize_t = System.UInt64;
using adiff_t = System.Int64;
using uval_t = System.UInt64;
using bgcolor_t = System.UInt32;
using nodeidx_t = System.UInt64;

using IdaNet.IdaInterop;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

using static IdaPlusPlus.IdaInterop;

namespace ManagedPlugin.Source
{
    public class ClassInformer
    {
        private static string NETNODE_NAME = "$ClassInformer_node";
        private static byte NN_DATA_TAG = 0x41;
        private static byte NN_TABLE_TAG = 0x53;

        private static short MY_VERSION = 0x0207;

        public class ARG2PAT
        {
            public readonly string pattern;
            public ea_t start;
            public ea_t end;

            public ARG2PAT(string pattern, ea_t start, ea_t end)
            {
                this.pattern = pattern;
                this.start = start;
                this.end = end;
            }
        };

        // Our netnode value indexes
        enum NETINDX : byte
        {
            NIDX_VERSION,   // ClassInformer version
            NIDX_COUNT      // Table entry count
        };

        private static Netnode netNode;
        internal static bool InitResourcesOnce = false;
        public static bool OptionProcessStatic = true;
        public static bool OptionPlaceStructs = true;
        public static bool OptionAudioOnDone = true;
        internal static uint StaticCCtorCnt = 0;
        internal static uint StaticCppCtorCnt = 0;
        internal static uint StaticCDtorCnt = 0;
        internal static uint StartingFuncCount = 0;
        internal static uint StaticCtorDtorCnt = 0;
        //private static bool Scanned = false;
        //private static bool ForceScan = false;
        public static List<SegmentT> segList;
        //private List<VTableInfo> VtableInfoList = new List<VTableInfo>();
        //private List<string> VtableList = new List<string>();
        //private static List<ea_t> eaList = new List<ea_t>();
        private static List<ea_t> colList = new List<ea_t>();
        public static HashSet<ea_t> tdSet = new HashSet<ea_t>();
        public static HashSet<ea_t> chdSet = new HashSet<ea_t>();
        public static HashSet<ea_t> bcdSet = new HashSet<ea_t>();
        public static Dictionary<ea_t, string> stringCache = new Dictionary<ea_t, string>();
        private Dictionary<ea_t, uint> eaRefMap = new Dictionary<ea_t, uint>();
        private static int MissingColsFixed = 0;
        private static int VftablesFixed = 0;

        private static void FreeVTableLists()
        {
            colList.Clear();
        }

        public static bool Run()
        {
            string version = "2.7";
            Kernwin.ida_msg($"\n>> Class Informer x64: v: {version}, built: {DateTime.Now.Date}, By Sirmabus, VivyaCC, XWare.net\n");

            if (netNode != null)
            {
                Kernwin.ida_msg("* Already active. Please close the chooser window first to run it again.\n");
                return true;
            }

            //if (!InitResourcesOnce)
            //{
            //    InitResourcesOnce = true;
            //    Q_INIT_RESOURCE(ClassInformerRes);

            //    QFile file = new QFile(DefineConstants.STYLE_PATH "icon.png");
            //    if (file.open(QFile.ReadOnly))
            //    {
            //        QByteArray ba = file.readAll();
            //        chooserIcon = load_custom_icon(ba.constData(), (uint)ba.size(), "png");
            //    }
            //}

            if (!Auto.AutoIsOk())
            {
                Kernwin.ida_msg("** Class Informer: Must wait for IDA to finish processing before starting plug-in! **\n*** Aborted ***\n\n");
                return true;
            }

            OggPlay.EndPlay();
            FreeWorkingData();
            OptionAudioOnDone = true;
            OptionProcessStatic = true;
            OptionPlaceStructs = true;
            StartingFuncCount = (uint)ida_get_func_qty();
            colList.Clear();
            StaticCppCtorCnt = StaticCCtorCnt = StaticCtorDtorCnt = StaticCDtorCnt = 0;
            MissingColsFixed = VftablesFixed = 0;

            // Create storage netnode
            netNode = new Netnode(NETNODE_NAME, true);
            if (netNode == null)
            {
                Kernwin.ida_warning("** ClassInformer: Could not create netNode");
                return true;
            }

            var tableCount = GetTableCount();
            short storageVersion = GetStoreVersion();
            bool storageExists = (tableCount > 0);

            if (storageExists)
            {
                // Version 2.3 didn't change the format
                uint major = (uint)(storageVersion >> 8), minor = (uint)(storageVersion & 0xf);
                if ((major != 2) || (minor < 2))
                {
                    Kernwin.ida_msg("* Storage version mismatch, must rescan *\n");
                }
                else
                {
                    storageExists = (Kernwin.ida_ask_yn(1, "TITLE Class Informer \nHIDECANCEL\nUse previously stored result?        ") == 1);
                }
            }

            bool aborted = false;
            if (!storageExists)
            {
                newNetnodeStore();

                // Only MS Visual C++ targets are supported
                comp_t cmp = (comp_t)(ida_inf_get_cc_id());
                if (cmp != comp_t.COMP_MS)
                {
                    string compilerName = Marshal.PtrToStringAnsi(ida_get_compiler_name((byte)cmp));
                    Kernwin.ida_msg($"** IDA reports target compiler: \"{compilerName}\"\n");
                    string message = string.Format($"TITLE Class Informer\nHIDECANCEL\nIDA reports this IDB's compiler as: \"{compilerName}\" \n\nThis plug-in only understands MS Visual C++ targets.\nRunning it on other targets (like Borland© compiled, etc.) will have unpredicted results.   \n\nDo you want to continue anyhow?");
                    int iResult = Kernwin.ida_ask_buttons(string.Empty, string.Empty, string.Empty, 0, message);
                    if (iResult != 1)
                    {
                        Kernwin.ida_msg("- Aborted -\n\n");
                        return true;
                    }
                }

                // Do UI
                SegSelect.Free();
                if (MainDialog.ExecuteMainDialog(ref OptionPlaceStructs, ref OptionProcessStatic, ref OptionAudioOnDone))
                {
                    Kernwin.ida_msg("- Canceled -\n\n");
                    FreeWorkingData();
                    return true;
                }

                // get the selected segments
                segList = MainDialog.GetSelectedSegments();
                SegSelect.Free();

                Kernwin.ida_msg("Working..\n");
                WaitBox.ShowDefault();
                WaitBox.UpdateAndCancelCheck(-1);
                var watch = new Stopwatch();

                // Add structure definitions to IDA once per session
                bool createStructsOnce = false;
                if (OptionPlaceStructs && !createStructsOnce)
                {
                    createStructsOnce = true;
                    RTTI.AddDefinitionsToIda();
                }

                if (OptionProcessStatic)
                {
                    // Process global and static ctor sections
                    Kernwin.ida_msg("\nProcessing C/C++ ctor & dtor tables..\n");
                    Kernwin.ida_msg("-------------------------------------------------\n");
                    watch.Start();
                    if (!(aborted = ProcessStaticTables()))
                    {
                        watch.Stop();
                        Kernwin.ida_msg($"Processing time: {watch.ElapsedMilliseconds} ms.\n");
                    }
                }

                watch.Stop();

                if (!aborted)
                {
                    // Get RTTI data
                    if (!(aborted = GetRTTIData(segList)))
                    {
                        // Optionally play completion sound
                        if (OptionAudioOnDone)
                        {
                            OggPlay.Play();
                        }

                        ShowEndStats(watch);
                        Kernwin.ida_msg("Done.\n\n");
                    }
                }

                WaitBox.Hide();
                ida_refresh_idaview_anyway();
                if (aborted)
                {
                    Kernwin.ida_msg("- Aborted -\n\n");
                    return true;
                }
            }

            // Show list result window
            if (!aborted && (GetTableCount() > 0))
            {
                // The chooser allocation will free itself automatically
                RTTIChooser.New();
            }

            FreeVTableLists();
            netNode = null;
            return false;
        }

        // Pattern in style IDA binary search style "48 8D 15 ?? ?? ?? ?? 48 8D 0D"
        public static ea_t find_binary2(ea_t start_ea, ea_t end_ea, string pattern)
        {
            string errorStr = string.Empty;
            var ea = Bytes.FindBinary2(start_ea, end_ea, pattern, ref errorStr);
            if (ea != DefineConstants.BADADDR)
            {
                return ea;
            }
            else
            {
                Kernwin.ida_msg($"** parse_binpat_str() failed! Reason: \"{errorStr}\" **");
                return DefineConstants.BADADDR;
            }
        }

        public struct CREPAT
        {
            public string pattern;
            public uint start, end, call;
        };

        // Print out end stats
        public static bool ProcessStaticTables()
        {
            StaticCppCtorCnt = StaticCCtorCnt = StaticCtorDtorCnt = StaticCDtorCnt = 0;

            // x64 __tmainCRTStartup, _CRT_INIT

            try
            {
                // Locate _initterm() and _initterm_e() functions
                SortedDictionary<ea_t, string> inittermMap = new SortedDictionary<ea_t, string>();
                IntPtr cinitFunc = IntPtr.Zero;
                Func cinitFunction = null;
                uint funcCount = (uint)ida_get_func_qty();

                for (uint i = 0; i < funcCount; i++)
                {
                    IntPtr func = ida_getn_func(i);
                    Func function = new Func(func);
                    if (func != IntPtr.Zero)
                    {
                        string str = string.Empty;
                        var requiredSize = ida_get_long_name(IntPtr.Zero, function.start_ea, 0);
                        if (-1 == requiredSize)
                        {
                            str = string.Empty;
                        }
                        else
                        {
                            IntPtr nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                            requiredSize = ida_get_long_name(nativeBuffer, function.start_ea, 0);
                            if (0 <= requiredSize)
                            {
                                str = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                            }

                            Marshal.FreeCoTaskMem(nativeBuffer);
                        }

                        if (requiredSize > 0)
                        {
                            string name = str;

                            int len = name.Length;
                            if (len >= "_cinit".Length)
                            {
                                if (name.EndsWith("_cinit"))
                                {
                                    // Skip stub functions
                                    if (function.size() > 16)
                                    {
                                        Kernwin.ida_msg($"{function.start_ea:X16} C: \"{name}\", {function.size()} bytes.\n");
                                        if (cinitFunc != IntPtr.Zero)
                                            Debugger.Break();
                                        cinitFunc = func;
                                        cinitFunction = function;
                                    }
                                }
                                else
                                {
                                    if ((len >= "_initterm".Length) && (name.EndsWith("_initterm")))
                                    {
                                        Kernwin.ida_msg($"{function.start_ea:X16} I: \"{name}\", {function.size()} bytes.\n");
                                        inittermMap[function.start_ea] = name;
                                    }
                                    else
                                    {
                                        if ((len >= "_initterm_e".Length) && (name.EndsWith("_initterm_e")))
                                        {
                                            Kernwin.ida_msg($"{function.start_ea:X16} E: \"{name}\", {function.size()} bytes.\n");
                                            inittermMap[function.start_ea] = name;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (WaitBox.IsUpdateTime())
                {
                    if (WaitBox.UpdateAndCancelCheck(-1))
                    {
                        return (true);
                    }
                }

                // Look for import versions
                string[] imports = { "__imp__initterm", "__imp__initterm_e" };
                for (int i = 0; i < (imports.Length); i++)
                {
                    IntPtr ptr = Marshal.StringToHGlobalAnsi(imports[i]);
                    ea_t address = ida_get_name_ea(DefineConstants.BADADDR, ptr);
                    Marshal.FreeHGlobal(ptr);
                    if (address != DefineConstants.BADADDR)
                    {
                        if (!inittermMap.ContainsKey(address))
                        {
                            Kernwin.ida_msg($"{address:X16} import: \"{imports[i]}\".\n");
                            inittermMap[address] = imports[i];
                        }
                    }
                }

                // Process register based _initterm() calls inside _cint()
                if (cinitFunc != IntPtr.Zero)
                {
                    CREPAT[] pat =
                    {
                        new CREPAT() { pattern = "B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 59 8B F8 3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE 72 F1", start = 1, end = 6, call = 0x17 },
                        new CREPAT() { pattern = "BE ?? ?? ?? ?? 8B C6 BF ?? ?? ?? ?? 3B C7 59 73 0F 8B 06 85 C0 74 02 FF D0 83 C6 04 3B F7 72 F1", start = 1, end = 8, call = 0x17 }
                    };

                    for (int i = 0; i < (pat.Length); i++)
                    {
                        ea_t match = find_binary2(cinitFunction.start_ea, cinitFunction.end_ea, pat[i].pattern);
                        while (match != DefineConstants.BADADDR)
                        {
                            Kernwin.ida_msg($"   {match:X16}  Register _initterm(), pattern #{i}.\n");
                            ea_t start = Bytes.GetEa(match + pat[i].start);
                            ea_t end = Bytes.GetEa(match + pat[i].end);
                            ProcessRegisterInitterm(start, end, (match + pat[i].call));
                            match = find_binary2(match + 30, cinitFunction.end_ea, pat[i].pattern);
                        };
                    }
                }

                Kernwin.ida_msg(" \n");
                if (WaitBox.IsUpdateTime())
                {
                    if (WaitBox.UpdateAndCancelCheck(-1))
                    {
                        return (true);
                    }
                }

                // Process _initterm references
                for (SortedDictionary<ea_t, string>.Enumerator it = inittermMap.GetEnumerator(); it.MoveNext();)
                {
                    if (ProcessInitterm(it.Current.Key, it.Current.Value))
                    {
                        if (WaitBox.IsUpdateTime())
                        {
                            if (WaitBox.UpdateAndCancelCheck(-1))
                            {
                                return (true);
                            }
                        }
                    }
                }

                if (WaitBox.IsUpdateTime())
                {
                    if (WaitBox.UpdateAndCancelCheck(-1))
                    {
                        return (true);
                    }
                }
            }
            catch (Exception ex)
            {

            }

            return false;
        }

        private static void ProcessRegisterInitterm(ulong start, ulong end, ulong call)
        {
            if ((end != DefineConstants.BADADDR) && (start != DefineConstants.BADADDR))
            {
                // Should be in the same segment
                if (ida_getseg(start) == ida_getseg(end))
                {
                    if (start > end)
                    {
                        // swap them
                        var tmp = start;
                        start = end;
                        end = tmp;
                    }

                    Kernwin.ida_msg($"     {start:X16}  to  {end:X16} CTOR table.\n");
                    SetIntializerTable(start, end, true);
                    if (!Bytes.HasComment(call))
                    {
                        Bytes.SetComment(call, "_initterm", true);
                    }
                }
                else
                {
                    Kernwin.ida_msg($"  ** Bad address range of  {start:X16} ,  {end:X16}  for \"_initterm\" type ** <click address>.\n");
                }
            }
        }

        private static uint DoInittermTable(Func func, ea_t start, ea_t end, string name)
        {
            uint found = false ? 1 : 0;

            if ((start != DefineConstants.BADADDR) && (end != DefineConstants.BADADDR))
            {
                // Should be in the same segment
                if (ida_getseg(start) == ida_getseg(end))
                {
                    if (start > end)
                    {
                        // swap them
                        var tmp = start;
                        start = end;
                        end = tmp;
                    }

                    // Try to determine if we are in dtor or ctor section
                    //if (func != null)
                    //{
                    string str = string.Empty;
                    var requiredSize = ida_get_long_name(IntPtr.Zero, func.start_ea, 0);
                    if (-1 == requiredSize)
                    {
                        str = string.Empty;
                    }
                    else
                    {
                        IntPtr nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                        requiredSize = ida_get_long_name(nativeBuffer, func.start_ea, 0);
                        if (0 <= requiredSize)
                        {
                            str = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                        }

                        Marshal.FreeCoTaskMem(nativeBuffer);
                    }

                    if (requiredSize > 0)
                    {
                        string funcName = str.ToLower();
                        if (funcName.Length >= DefineConstants.MAXSTR)
                        {
                            funcName = funcName.Substring(0, DefineConstants.MAXSTR);
                        }

                        // Start/ctor?
                        if (funcName.Contains("cinit") || funcName.Contains("tmaincrtstartup") || funcName.Contains("start"))
                        {
                            Kernwin.ida_msg($"    {start:X16} to {end:X16} CTOR table.\n");
                            SetIntializerTable(start, end, true);
                            found = true ? 1 : 0;
                        }
                        else
                        {
                            // Exit/dtor function?
                            if (funcName.Contains("exit"))
                            {
                                Kernwin.ida_msg($"    {start:X16} to {end:X16} DTOR table.\n");
                                SetTerminatorTable(start, end);
                                found = true ? 1 : 0;
                            }
                        }
                    }
                    //}

                    if (found == 0)
                    {
                        // Fall back to generic assumption
                        Kernwin.ida_msg($"    {start:X16} to {end:X16} CTOR/DTOR table.\n");
                        SetCtorDtorTable(start, end);
                        found = true ? 1 : 0;
                    }
                }
                else
                {
                    Kernwin.ida_msg("    ** Miss matched segment table addresses {start:X16}, {end:X16} for \"{name}\" type **\n");
                }
            }
            else
            {
                Kernwin.ida_msg("    ** Bad input address range of {start:X16}, {end:X16} for \"{name}\" type **\n");
            }

            return (found);
        }

        private static void SetIntializerTable(ulong start, ulong end, bool isCpp)
        {
            try
            {
                uint count = (uint)((end - start) / GetPtrSize());
                if (count != 0)
                {
                    // Set table elements as pointers
                    ea_t ea = start;
                    while (ea <= end)
                    {
                        Bytes.FixEa(ea);

                        // Might fix missing/messed stubs
                        ea_t f = ida_get_32bit(ea);
                        Debugger.Break();
                        if (f != 0)
                        {
                            Bytes.FixFunction(f);
                        }

                        ea += GetPtrSize();
                    };

                    // Start label
                    if (!Bytes.HasName(start))
                    {
                        string name;
                        if (isCpp)
                        {
                            name = string.Format($"__xc_a_{StaticCppCtorCnt}");
                        }
                        else
                        {
                            name = string.Format($"__xi_a_{StaticCCtorCnt}");
                        }

                        name = name.Substring(0, DefineConstants.MAXSTR);
                        Bytes.SetName(start, name);
                    }

                    // End label
                    if (!Bytes.HasName(end))
                    {
                        string name;
                        if (isCpp)
                        {
                            name = string.Format($"__xc_z_{StaticCppCtorCnt}");
                        }
                        else
                        {
                            name = string.Format($"__xi_z_{StaticCCtorCnt}");
                        }

                        name = name.Substring(0, DefineConstants.MAXSTR);
                        Bytes.SetName(end, name);
                    }

                    // Comment
                    // Never overwrite, it might be the segment comment
                    if (!Bytes.HasAnteriorComment(start))
                    {
                        if (isCpp)
                        {
                            string comment = string.Format($"{count} C++ static ctors (#classinformer)");
                            Bytes.SetAnteriorComment(start, comment);
                        }
                        else
                        {
                            string comment = string.Format($"{count} C initializers (#classinformer)");
                            Bytes.SetAnteriorComment(start, comment);
                        }
                    }
                    else
                    {
                        // Place comment @ address instead
                        if (!Bytes.HasComment(start))
                        {
                            if (isCpp)
                            {
                                string comment;
                                comment = string.Format($"{count} C++ static ctors (#classinformer)");
                                comment = comment.Substring(0, DefineConstants.MAXSTR);
                                Bytes.SetComment(start, comment, true);
                            }
                            else
                            {
                                string comment;
                                comment = string.Format($"{count} C initializers (#classinformer)");
                                comment = comment.Substring(0, DefineConstants.MAXSTR);
                                Bytes.SetComment(start, comment, true);
                            }
                        }
                    }

                    if (isCpp)
                    {
                        StaticCppCtorCnt++;
                    }
                    else
                    {
                        StaticCCtorCnt++;
                    }
                }
            }
            catch (Exception ex)
            {
            }
        }

        private static void SetTerminatorTable(ea_t start, ea_t end)
        {
            try
            {
                ulong count = ((end - start) / GetPtrSize());
                if (count != 0)
                {
                    // Set table elements as pointers
                    ea_t ea = start;
                    while (ea <= end)
                    {
                        Bytes.FixEa(ea);

                        // Might fix missing/messed stubs
                        ea_t f = ida_get_32bit(ea);
                        Debugger.Break();
                        if (f != 0)
                        {
                            Bytes.FixFunction(f);
                        }

                        ea += GetPtrSize();
                    };

                    // Start label
                    if (!Bytes.HasName(start))
                    {
                        string name = string.Format($"__xt_a_{StaticCDtorCnt}").Substring(0, DefineConstants.MAXSTR);
                        Bytes.SetName(start, name);
                    }

                    // End label
                    if (!Bytes.HasName(end))
                    {
                        string name = string.Format($"__xt_z_{StaticCDtorCnt}").Substring(0, DefineConstants.MAXSTR);
                        Bytes.SetName(end, name);
                    }

                    // Comment
                    // Never overwrite, it might be the segment comment
                    if (!Bytes.HasAnteriorComment(start))
                    {
                        string comment = string.Format($"{count} C terminators (#classinformer)").Substring(0, DefineConstants.MAXSTR);
                        Bytes.SetAnteriorComment(start, comment);
                    }
                    else
                    {
                        // Place comment @ address instead
                        if (!Bytes.HasComment(start))
                        {
                            string comment = string.Format($"{count} C terminators (#classinformer)").Substring(0, DefineConstants.MAXSTR);
                            Bytes.SetComment(start, comment, true);
                        }
                    }

                    StaticCDtorCnt++;
                }
            }
            catch (Exception ex)
            {
            }
        }

        private static void SetCtorDtorTable(ea_t start, ea_t end)
        {
            try
            {
                ulong count = ((end - start) / GetPtrSize());
                if (count != 0)
                {
                    // Set table elements as pointers
                    ea_t ea = start;
                    while (ea <= end)
                    {
                        Bytes.FixEa(ea);

                        // Might fix missing/messed stubs
                        ea_t f = ida_get_32bit(ea);
                        //Debugger.Break();
                        if (f != 0)
                        {
                            Bytes.FixFunction(f);
                        }

                        ea += GetPtrSize();
                    };

                    // Start label
                    if (!Bytes.HasName(start))
                    {
                        string name = string.Format($"__x?_a_{StaticCtorDtorCnt}").Substring(0, DefineConstants.MAXSTR);
                        Bytes.SetName(start, name);
                    }

                    // End label
                    if (!Bytes.HasName(end))
                    {
                        string name = string.Format($"__x?_z_{StaticCtorDtorCnt}").Substring(0, DefineConstants.MAXSTR);
                        Bytes.SetName(end, name);
                    }

                    // Comment
                    // Never overwrite, it might be the segment comment
                    if (!Bytes.HasAnteriorComment(start))
                    {
                        string comment = string.Format($"{count} C initializers/terminators (#classinformer)").Substring(0, DefineConstants.MAXSTR);
                        Bytes.SetAnteriorComment(start, comment);
                    }
                    else
                    {
                        // Place comment @ address instead
                        if (!Bytes.HasComment(start))
                        {
                            string comment = string.Format($"{count} C initializers/terminators (#classinformer)").Substring(0, DefineConstants.MAXSTR);
                            Bytes.SetComment(start, comment, true);
                        }
                    }

                    StaticCtorDtorCnt++;
                }
            }
            catch (Exception ex)
            {

            }
        }

        private static bool ProcessInitterm(ea_t address, string name)
        {
            Kernwin.ida_msg(string.Format($"{address:X16} processInitterm: \"{name}\" \n"));
            uint count = 0;

            // Walk xrefs
            ea_t xref = ida_get_first_fcref_to(address);
            while (xref != 0 && (xref != DefineConstants.BADADDR))
            {
                Kernwin.ida_msg($"  {xref:X16} \"{name}\" xref.\n");

                // Should be code
                if (ida_is_code(ida_get_flags(xref)))
                {
                    do
                    {
                        // The most common are two instruction arguments
                        // Back up two instructions
                        ea_t instruction1 = ida_prev_head(xref, 0);
                        if (instruction1 == DefineConstants.BADADDR)
                        {
                            break;
                        }

                        ea_t instruction2 = ida_prev_head(instruction1, 0);
                        if (instruction2 == DefineConstants.BADADDR)
                        {
                            break;
                        }

                        // Bail instructions are past the function start now
                        IntPtr function = ida_get_func(xref);
                        Func func = new Func(function);
                        if (instruction2 < func.start_ea)
                        {
                            //msg("   " EAFORMAT " arg2 outside of contained function **\n", func->start_ea);
                            break;
                        }


                        List<ARG2PAT> arg2pat = new List<ARG2PAT>();
                        ARG2PAT item = new ARG2PAT("48 8D 15 ?? ?? ?? ?? 48 8D 0D", 3, 3);
                        arg2pat = new List<ARG2PAT>();
                        arg2pat.Add(item);

                        bool matched = false;
                        for (int i = 0; (i < arg2pat.Count) && !matched; i++)
                        {
                            ea_t match = Bytes.FindBinary2(instruction2, xref, arg2pat[i].pattern);
                            if (match != DefineConstants.BADADDR)
                            {
                                uint startOffset = ida_get_32bit(instruction1 + arg2pat[i].start);
                                uint endOffset = ida_get_32bit(instruction2 + arg2pat[i].end);
                                ea_t start = instruction1 + 7 + startOffset;
                                ea_t end = instruction2 + 7 + endOffset;

                                Kernwin.ida_msg(string.Format($"  {match:X16} Two instruction pattern match #{i}\n"));
                                count += DoInittermTable(func, start, end, name);
                                matched = true;
                                break;
                            }
                        }

                        // 3 instruction
                        /*
                        searchStart = prev_head(searchStart, DefineConstants.BADADDR);
                        if (searchStart == DefineConstants.BADADDR)
                            break;
                        if (func && (searchStart < func->start_ea))
                            break;

                            if (func && (searchStart < func->start_ea))
                            {
                                msg("  " EAFORMAT " arg3 outside of contained function **\n", func->start_ea);
                                break;
                            }

                        .text:10008F78                 push    offset unk_1000B1B8
                        .text:10008F7D                 push    offset unk_1000B1B0
                        .text:10008F82                 mov     dword_1000F83C, 1
                        "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ??"
                        */

                        if (!matched)
                        {
                            Kernwin.ida_msg("  ** arguments not located!\n");
                        }

                    } while (false);
                }
                else
                {
                    Kernwin.ida_msg(string.Format($"  {xref:X16} ** \"{name}\" xref is not code! **\n"));
                }

                xref = ida_get_next_fcref_to(address, xref);
            };

            Kernwin.ida_msg(" \n");
            return (count > 0);
        }

        static void ShowEndStats(Stopwatch watch)
        {
            try
            {
                Kernwin.ida_msg(" \n\n");
                Kernwin.ida_msg("=========== Stats ===========\n");

                ulong vftableCount = GetTableCount();
                if (VftablesFixed > 0)
                    Kernwin.ida_msg($"  RTTI vftables: {vftableCount}, fixed: {VftablesFixed} ({((double)VftablesFixed / (double)vftableCount) * 100.0} %)\n");
                else
                    Kernwin.ida_msg($"  RTTI vftables: {vftableCount}\n");

                // Amount of COLs fixed is usually about the same as vftables fixed, but the same COL can be used in multiple vftables
                //if(missingColsFixed)
                //msg("     COLs fixed: %u of %u (%.1f%%)\n", missingColsFixed, colCount,  ((double) missingColsFixed / (double) colCount)  * 100.0);

                uint functionsFixed = (uint)ida_get_func_qty() - StartingFuncCount;
                if (functionsFixed > 0)
                    Kernwin.ida_msg($"Functions fixed: {functionsFixed}\n");

                Kernwin.ida_msg($"Processing time: {watch.ElapsedMilliseconds} ms.\n");
            }
            catch (Exception ex)
            {

            }
        }

        private static void FreeWorkingData()
        {
            RTTI.FreeWorkingData();
            colList.Clear();

            if (netNode != null)
            {
                netNode = null;
            }
        }

        // Init new netnode storage
        public static void newNetnodeStore()
        {
            // Kill any existing store data first
            netNode.AltdelAll(NN_DATA_TAG);
            netNode.SupdelAll(NN_TABLE_TAG);

            // Init defaults
            netNode.AltsetIdx8((byte)NETINDX.NIDX_VERSION, (UInt64)MY_VERSION, NN_DATA_TAG);
            netNode.AltsetIdx8((byte)NETINDX.NIDX_COUNT, 0, NN_DATA_TAG);
        }

        public static short GetStoreVersion()
        {
            return (short)netNode.AltvalIdx8((byte)NETINDX.NIDX_VERSION, NN_DATA_TAG);
        }

        public static nodeidx_t GetTableCount()
        {
            return netNode.AltvalIdx8((byte)NETINDX.NIDX_COUNT, NN_DATA_TAG);
        }

        public static bool SetTableCount(UInt64 count)
        {
            return netNode.AltsetIdx8((byte)NETINDX.NIDX_COUNT, count, NN_DATA_TAG);
        }

        //public static bool GetTableEntry(ref TBLENTRY entry, nodeidx_t index)
        //{
        //    byte[] buffer = new byte[1024];
        //    if (netNode.GetSupplementaryValue(index, NN_TABLE_TAG, out buffer) > 0)
        //    {
        //        entry = buffer.CastToStruct<TBLENTRY>();
        //        return true;
        //    }
        //    else
        //    {
        //        return false;
        //    }
        //}

        //static unsafe bool SetTableEntry(TBLENTRY entry, nodeidx_t index)
        //{
        //    byte[] str = new byte[entry.strSize];
        //    for (int i = 0; i < entry.strSize; i++)
        //    {
        //        str[i] = entry.str[i];
        //    }
        //    return netNode.SetSupplementaryValue(index, str, entry.strSize, NN_TABLE_TAG);
        //}

        //public unsafe static void AddTableEntry(ushort flags, ea_t vft, int methodCount, string format, params object[] paramArray)
        //{
        //    TBLENTRY e = new TBLENTRY();
        //    e.vft = vft;
        //    e.methods = Convert.ToUInt16(methodCount);
        //    e.flags = Convert.ToUInt16(flags);

        //    int ParamCount = -1;
        //    string utf8string = string.Format(format, paramArray);
        //    var str = System.Text.UTF8Encoding.UTF8.GetBytes(utf8string);
        //    e.strSize += Convert.ToUInt16(str.Length);
        //    for (int i = 0; i < e.strSize; i++)
        //    {
        //        e.str[i] = str[i];
        //    }

        //    nodeidx_t count = GetTableCount();
        //    SetTableEntry(e, count);
        //    SetTableCount(++count);
        //}

        //private static bool ReadStorage()
        //{
        //    // Create storage netnode
        //    netNode = new Netnode(NETNODE_NAME, true);
        //    if ((netNode == null) || (netNode.UnmanagedPtr == IntPtr.Zero))
        //    {
        //        return true;
        //    }

        //    // Read existing storage if any
        //    nodeidx_t tableCount = GetTableCount();
        //    short storageVersion = GetStoreVersion();
        //    bool storageExists = tableCount > 0;

        //    ea_t largestAddres = 0;
        //    for (uint i = 0; i < tableCount; i++)
        //    {
        //        TBLENTRY e = new TBLENTRY();
        //        e.vft = 0;
        //        GetTableEntry(ref e, i);
        //        if (e.vft > largestAddres)
        //            largestAddres = e.vft;
        //    }

        //    return false;
        //}

        private static bool GetRTTIData(List<SegmentT> segments)
        {
            //var segments = Segments.EnumerateSegments();
            PluginBase.WriteDebugMessage("\nScanning for for RTTI Complete Object Locators..\n");
            PluginBase.WriteDebugMessage("-----------------------------------------------\n");
            if (FindCols(segments))
                return true;
            // typeDescList = TDs left that don't have a COL reference
            // colList = Located COLs
            PluginBase.WriteDebugMessage("\nScanning for Virtual Function Tables..\n");
            PluginBase.WriteDebugMessage("-------------------------------------\n");
            if (FindVTables(segments))
                return true;
            // colList = COLs left that don't have a vft reference
            // Could use the unlocated ref lists typeDescList & colList around for possible separate listing, etc.
            // They get cleaned up on return of this function anyhow.
            return false;
        }

        private static bool FindVTables(IEnumerable<SegmentT> segments)
        {
            try
            {
                var watch = new System.Diagnostics.Stopwatch();
                watch.Start();

                // COLs in a hash map for speed, plus add match counts
                Dictionary<ea_t, uint> colMap = new Dictionary<ea_t, uint>();
                foreach (var col in colList)
                    colMap.Add(col, 0);

                // Use user selected segments
                if (segments != null && segments.Any())
                {
                    foreach (var segment in segments)
                    {
                        scanSeg4Vftables(segment, ref colMap);
                    }
                }
                else
                {
                    for (int i = 0; i < ida_get_segm_qty(); i++)
                    {
                        var seg = ida_getnseg(i);
                        if (seg != IntPtr.Zero)
                        {
                            var Seg = new SegmentT(seg);
                            {
                                if (Seg.type == SegmentType.SEG_DATA)
                                {
                                    scanSeg4Vftables(Seg, ref colMap);
                                }
                            }
                        }
                    }
                }

                // Rebuild 'colList' with any that were not located
                colList.Clear();
                foreach (var c in colMap.Where(cm => cm.Value > 0))
                {
                    colList.Add(c.Key);
                }

                watch.Stop();
                PluginBase.WriteDebugMessage($"Vftable scan time: {watch.ElapsedMilliseconds} ms\n");
            }
            catch (Exception ex)
            {
                PluginBase.WriteDebugMessage($"{ex.Message}, {ex.StackTrace}");
            }

            return false;
        }

        private static bool FindCols(IEnumerable<SegmentT> segments)
        {
            var watch = new System.Diagnostics.Stopwatch();
            watch.Start();
            if (segments != null && segments.Any())
            {
                foreach (var segment in segments)
                {
                    ScanSeg4Cols(segment);
                }
            }
            else
            {
                for (int i = 0; i < ida_get_segm_qty(); i++)
                {
                    var seg = ida_getnseg(i);
                    if (seg != IntPtr.Zero)
                    {
                        var Seg = new SegmentT(seg);
                        {
                            if (Seg.type == SegmentType.SEG_DATA)
                            {
                                ScanSeg4Cols(Seg);
                            }
                        }
                    }
                }
            }

            watch.Stop();
            PluginBase.WriteDebugMessage($"    Total COL: {colList.Count}\n");
            PluginBase.WriteDebugMessage($"COL scan time: {watch.ElapsedMilliseconds} ms\n");
            return false;
        }

        private enum GMB
        {
            GMB_READALL = 1,
            GMB_WAITBOX = 2,
        };

        private static void ScanSeg4Cols(SegmentT segment)
        {
            PluginBase.WriteDebugMessage($" N: \"{segment.name}\", A: {segment.start_ea:X16} - {segment.end_ea:X16}, S: {byteSizeString(segment.Size())} for COLS\n");
            // read segment in memory
            byte[] bytes = new byte[segment.Size()];
            GCHandle pinnedArray = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            IntPtr pointer = pinnedArray.AddrOfPinnedObject();

            ida_get_bytes(pointer, bytes.Length, segment.end_ea, (int)GMB.GMB_READALL, IntPtr.Zero);
            using (Stream stream = System.IO.File.Open(segment.start_ea.ToString("X") + segment.name, FileMode.Create))
            {
                using (BinaryWriter bw = new BinaryWriter(stream))
                {
                    bw.Write(bytes);
                }
            }

            pinnedArray.Free();
            if (segment.Size() >= RTTICompleteObjectLocator.Size())
            {
                ea_t startEA = (segment.start_ea + sizeof(uint)) & ~(ea_t)(sizeof(uint) - 1);
                ea_t endEA = segment.end_ea - RTTICompleteObjectLocator.Size();

                for (ea_t ptr = startEA; ptr < endEA;)
                {
                    // Check for possible COL here
                    // Signature will be one
                    // TODO: Is this always 1 or can it be zero like 32bit?
                    if (ida_get_32bit(ptr + RTTICompleteObjectLocator.OffsetOfSignature()) == 1)
                    {
                        //PluginBase.WriteDebugMessage($" test RTTICompleteObjectLocator.IsValid(0x{ptr:X})");
                        if (RTTICompleteObjectLocator.IsValid(ptr))
                        {
                            // yes
                            //PluginBase.WriteDebugMessage($"  COL valid");
                            colList.Insert(0, ptr);
                            MissingColsFixed += (int)(RTTICompleteObjectLocator.TryStruct(ptr) ? 1 : 0);
                            ptr += RTTICompleteObjectLocator.Size();
                            continue;
                        }
                    }
                    else
                    {
                        // TODO: Should we check stray BCDs?
                        // Each value would have to be tested for a valid type_def and
                        // the pattern is pretty ambiguous.
                    }

                    ptr += sizeof(uint);
                }
            }
        }

        public static size_t GetPtrSize()
        {
            return 8;
        }

        private static string BYTESTR(UInt64 nbytes, UInt64 _Size, string _Suffix)
        {
            string buffer;
            double fSize = (double)nbytes / (double)_Size;
            buffer = string.Format($"{fSize:0.#} {_Suffix}");
            return buffer;
        }


        // Returns a pretty factional byte size string for given input size
        private static string byteSizeString(UInt64 nbytes)
        {
            const UInt64 KILLOBYTE = 1024;
            const UInt64 MEGABYTE = KILLOBYTE * 1024; // 1048576
            const UInt64 GIGABYTE = MEGABYTE * 1024; // 1073741824
            const UInt64 TERABYTE = GIGABYTE * 1024; // 1099511627776

            string buffer = string.Empty;
            if (nbytes >= TERABYTE)
                buffer = BYTESTR(nbytes, TERABYTE, "TB");
            else
            if (nbytes >= GIGABYTE)
                buffer = BYTESTR(nbytes, GIGABYTE, "GB");
            else
            if (nbytes >= MEGABYTE)
                buffer = BYTESTR(nbytes, MEGABYTE, "MB");
            else
            if (nbytes >= KILLOBYTE)
                buffer = BYTESTR(nbytes, KILLOBYTE, "KB");
            else
                buffer = string.Format("{0} byte{1}", (uint)nbytes, (nbytes == 1) ? "" : "s");

            return buffer;
        }

        private static ea_t getEa(ea_t ea)
        {
            return ida_get_64bit(ea);
        }

        // Locate vftables
        private static bool scanSeg4Vftables(SegmentT seg, ref Dictionary<ea_t, uint> colMap)
        {
            PluginBase.WriteDebugMessage($" N: \"{seg.name}\", A: {seg.start_ea:X16} - {seg.end_ea:X16}, S: {byteSizeString(seg.Size())}\n");

            uint foundCount = 0;
            if (seg.Size() >= GetPtrSize())
            {
                ea_t startEA = (seg.start_ea + GetPtrSize()) & ~(ea_t)(GetPtrSize() - 1);
                ea_t endEA = seg.end_ea - GetPtrSize();
                if (((startEA | endEA) & 3) != 0)
                    Debugger.Break();

                // Walk uint32 at the time, at align 4 (same for either 32bit or 64bit targets)
                for (ea_t ptr = startEA; ptr < endEA; ptr += sizeof(uint))
                {
                    // A COL here?
                    ea_t ea = getEa(ptr);
                    if (colMap.ContainsKey(ea))
                    {
                        // yes, look for vftable one ea_t below
                        ea_t vfptr = ptr + GetPtrSize();
                        ea_t method = getEa(vfptr);

                        IntPtr segP = ida_getseg(method);
                        if (segP != IntPtr.Zero)
                        {
                            var segment = new SegmentT(segP);
                            if (segment.type == SegmentType.SEG_CODE)
                            {
                                bool result = RTTI.processVftable(vfptr, ea);
                                //if(result)
                                //	msg(EAFORMAT " vft fix **\n", vfptr);
                                VftablesFixed += result ? 1 : 0;
                                colMap[ea]++;
                                foundCount++;
                            }
                        }
                    }
                }
            }

            if (foundCount > 0)
            {
                PluginBase.WriteDebugMessage($" Count: {foundCount}\n");
            }

            return false;
        }

        public static bool GetPlainTypeName(string mangled, ref string outStr)
        {
            outStr = string.Empty;

            if (string.IsNullOrEmpty(mangled))
            {
                Debugger.Break();
                return false;
            }

            // Use CRT function for type names
            if (mangled[0] == '.')
            {
                string mangledTypeName = mangled.Substring(1);
                // Should be valid if it properly demangles
                StringBuilder builder = new StringBuilder(255);
                if (RTTI.UnDecorateSymbolName(mangledTypeName, builder, builder.Capacity, (RTTI.UnDecorateFlags.UNDNAME_32_BIT_DECODE | RTTI.UnDecorateFlags.UNDNAME_TYPE_ONLY | RTTI.UnDecorateFlags.UNDNAME_NO_ECSU)) != 0)
                {
                    outStr = builder.ToString();
                    if ((outStr[0] == 0) || mangled.Substring(1) == outStr)
                    {
                        return (false);
                    }

                    return true;
                }
            }
            else
            {
                string qstr = string.Empty;
                IntPtr mangledPtr = Marshal.StringToHGlobalAnsi(mangled);
                IntPtr qstrPtr = Marshal.AllocHGlobal(DefineConstants.MAXSTR);
                // IDA demangler for everything else
                int result = ida_demangle_name(qstrPtr, mangledPtr, DefineConstants.M_COMPILER, (int)(demreq_type_t.DQT_FULL));
                if (result < 0)
                {
                    return (false);
                }

                // No inhibit flags will drop this
                outStr = qstr;
                int index = outStr.IndexOf("::`vftable'");
                if (index != -1)
                    outStr = outStr.Substring(0, index);
                Marshal.FreeHGlobal(qstrPtr);
                Marshal.FreeHGlobal(mangledPtr);
            }

            return (true);
        }
    }
}
