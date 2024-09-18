using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using ea_t = System.UInt64;
using tid_t = System.UInt64;
using sel_t = System.UInt64;
using size_t = System.UInt64;
using asize_t = System.UInt64;
using adiff_t = System.Int64;
using uval_t = System.UInt64;
using bgcolor_t = System.UInt32;
using flags_t = System.UInt32;

using static IdaPlusPlus.IdaInterop;
using System.Runtime.InteropServices;

namespace IdaNet.IdaInterop
{
    public enum GTNFlags : int
    {
        GN_VISIBLE = 0x0001, ///< replace forbidden characters by SUBSTCHAR
        GN_COLORED = 0x0002, ///< return colored name
        GN_DEMANGLED = 0x0004, ///< return demangled name
        GN_STRICT = 0x0008, ///< fail if cannot demangle
        GN_SHORT = 0x0010, ///< use short form of demangled name
        GN_LONG = 0x0020, ///< use long form of demangled name
        GN_LOCAL = 0x0040, ///< try to get local name first; if failed, get global
        GN_ISRET = 0x0080, ///< for dummy names: use retloc
        GN_NOT_ISRET = 0x0100, ///< for dummy names: do not use retloc
        GN_NOT_DUMMY = 0x0200, ///< do not return a dummy name
    }

    public enum DemreqTypeT
    {
        DQT_NPURGED_8 = -8, // only calculate number of purged bytes (sizeof(arg)==8)
        DQT_NPURGED_4 = -4, // only calculate number of purged bytes (sizeof(arg)==4)
        DQT_NPURGED_2 = -2, // only calculate number of purged bytes (sizeof(arg)==2)
        DQT_COMPILER = 0,  // only detect compiler that generated the name
        DQT_NAME_TYPE = 1,  // only detect the name type (data/code)
        DQT_FULL = 2,  // really demangle
    };

    public class Name
    {
        public static string ida_get_name(ea_t ea, int gtn_flags)
        {
            int flags = gtn_flags;
            IntPtr name = IntPtr.Zero;
            var size = (int)ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            name = Marshal.AllocCoTaskMem(size);
            ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            string nam = Marshal.PtrToStringAnsi(name, size);
            Marshal.FreeCoTaskMem(name);
            return nam;
        }

        public static string ida_get_visible_name(ea_t ea, int gtn_flags)
        {
            int flags = (int)GTNFlags.GN_VISIBLE | gtn_flags;
            IntPtr name = IntPtr.Zero;
            var size = (int)ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            name = Marshal.AllocCoTaskMem(size);
            ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            string nam = Marshal.PtrToStringAnsi(name, size);
            Marshal.FreeCoTaskMem(name);
            return nam;
        }

        public static string ida_get_colored_name(ea_t ea, int gtn_flags)
        {
            int flags = (int)GTNFlags.GN_VISIBLE | (int)GTNFlags.GN_COLORED | gtn_flags;
            IntPtr name = IntPtr.Zero;
            var size = (int)ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            name = Marshal.AllocCoTaskMem(size);
            ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            string nam = Marshal.PtrToStringAnsi(name, size);
            Marshal.FreeCoTaskMem(name);
            return nam;
        }

        public static string ida_get_short_name(ea_t ea, int gtn_flags)
        {
            int flags = (int)GTNFlags.GN_VISIBLE | (int)GTNFlags.GN_DEMANGLED | (int)GTNFlags.GN_SHORT | gtn_flags;
            IntPtr name = IntPtr.Zero;
            var size = (int)ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            name = Marshal.AllocCoTaskMem(size);
            ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            string nam = Marshal.PtrToStringAnsi(name, size);
            Marshal.FreeCoTaskMem(name);
            return nam;
        }

        public static string ida_get_long_name(ea_t ea, int gtn_flags)
        {
            int flags = (int)GTNFlags.GN_VISIBLE | (int)GTNFlags.GN_DEMANGLED | (int)GTNFlags.GN_LONG | gtn_flags;
            IntPtr name = IntPtr.Zero;
            var size = (int)ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            name = Marshal.AllocCoTaskMem(size);
            ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            string nam = Marshal.PtrToStringAnsi(name, size);
            Marshal.FreeCoTaskMem(name);
            return nam;
        }

        public static string ida_get_colored_short_name(ea_t ea, int gtn_flags)
        {
            int flags = (int)GTNFlags.GN_VISIBLE | (int)GTNFlags.GN_COLORED | (int)GTNFlags.GN_DEMANGLED | (int)GTNFlags.GN_SHORT | gtn_flags;
            IntPtr name = IntPtr.Zero;
            var size = (int)ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            name = Marshal.AllocCoTaskMem(size);
            ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            string nam = Marshal.PtrToStringAnsi(name, size);
            Marshal.FreeCoTaskMem(name);
            return nam;
        }

        public static string ida_get_colored_long_name(ea_t ea, int gtn_flags)
        {
            int flags = (int)GTNFlags.GN_VISIBLE | (int)GTNFlags.GN_COLORED | (int)GTNFlags.GN_DEMANGLED | (int)GTNFlags.GN_LONG | gtn_flags;
            IntPtr name = IntPtr.Zero;
            var size = (int)ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            name = Marshal.AllocCoTaskMem(size);
            ida_get_ea_name(name, ea, flags, IntPtr.Zero);
            string nam = Marshal.PtrToStringAnsi(name, size);
            Marshal.FreeCoTaskMem(name);
            return nam;
        }

        public static string ida_get_demangled_name(ea_t ea, Int32 inhibitor, int demform, int gtn_flags)
        {
            IntPtr name = IntPtr.Zero;
            var size = ida_get_demangled_name_(name, ea, inhibitor, demform, gtn_flags);
            name = Marshal.AllocCoTaskMem((int)size);
            ida_get_demangled_name_(name, ea, inhibitor, demform, gtn_flags);
            string nam = Marshal.PtrToStringAnsi(name, (int)size);
            Marshal.FreeCoTaskMem(name);
            return nam;
        }

        public static string ida_get_colored_demangled_name(ea_t ea, Int32 inhibitor, int demform, int gtn_flags)
        {
            return ida_get_demangled_name(ea, inhibitor, demform, (int)GTNFlags.GN_COLORED | gtn_flags);
        }
    }
}
