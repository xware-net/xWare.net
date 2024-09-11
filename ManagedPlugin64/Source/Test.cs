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
    public class Test
    {
        public static bool Run()
        {
            List<IntPtr> sdirsPtr = new List<IntPtr>();
            int num = ida_get_ida_subdirs(sdirsPtr, Marshal.StringToHGlobalAnsi("plugins"), 0x00000000);
            var dirs = MarshalingUtils.ListOfIntPtrToStringArray(sdirsPtr, num);
            return false;
        }
    }
}
