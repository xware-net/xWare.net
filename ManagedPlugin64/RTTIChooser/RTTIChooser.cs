using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using ea_t = System.UInt64;
using sel_t = System.UInt64;
using size_t = System.UInt64;
using asize_t = System.UInt64;
using adiff_t = System.Int64;
using uval_t = System.UInt64;
using bgcolor_t = System.UInt32;
using nodeidx_t = System.UInt64;

using System.Runtime.InteropServices;
using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public class RTTIChooser
    {
        public static void New()
        {
            RTTIChooser_New();
        }

        public static void AddTableEntry(ea_t vft, ushort methodCount, ushort flags, string entry)
        {
            IntPtr entryPtr = Marshal.StringToHGlobalAnsi(entry);
            RTTIChooser_AddTableEntry(vft, methodCount, flags, entryPtr);
            Marshal.FreeHGlobal(entryPtr);
        }
    }
}
