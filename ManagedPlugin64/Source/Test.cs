using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using EaT = System.UInt64;
using SelT = System.UInt64;
using SizeT = System.UInt64;
using AsizeT = System.UInt64;
using AdiffT = System.Int64;
using UvalT = System.UInt64;
using BgcolorT = System.UInt32;
using NodeidxT = System.UInt64;

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
            RangeT range = new RangeT(0x10000000, 0x20000000);
            IntPtr buf = Marshal.AllocHGlobal(0x100);
            range.Print(buf, 0x100);
            string buf1 = Marshal.PtrToStringAnsi(buf);
            Marshal.FreeHGlobal(buf);
            List<IntPtr> sdirsPtr = new List<IntPtr>();
            int num = ida_get_ida_subdirs(sdirsPtr, Marshal.StringToHGlobalAnsi("plugins"), 0x00000000);
            var dirs = MarshalingUtils.ListOfIntPtrToStringArray(sdirsPtr, num);
            return false;
        }
    }
}
