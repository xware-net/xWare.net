using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using ssize_t = System.UInt64;

using System.Runtime.InteropServices;
using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    [StructLayout(LayoutKind.Explicit)]
    public struct callui_t
    {
        [FieldOffset(0)]
        public bool cnd;
        [FieldOffset(0)]
        public sbyte i8;
        [FieldOffset(0)]
        public int i;
        [FieldOffset(0)]
        public short i16;
        [FieldOffset(0)]
        public Int32 i32;
        [FieldOffset(0)]
        public byte u8;
        [FieldOffset(0)]
        public ushort u16;
        [FieldOffset(0)]
        public UInt32 u32;
        //char *cptr;
        //void *vptr;
        [FieldOffset(0)]
        public ssize_t ssize;
        //func_t *fptr;
        //segment_t *segptr;
        //struc_t *strptr;
        //plugin_t *pluginptr;
        //sreg_range_t *sraptr;
    };

    public class Kernwin
    {
        public static void ida_info(string înfo)
        {
            IntPtr înfoPointer = (IntPtr)Marshal.StringToHGlobalAnsi(înfo);
            ida_ui_info(înfoPointer);
            Marshal.FreeHGlobal(înfoPointer);
        }

        public static void ida_warning(string warning)
        {
            IntPtr warningPointer = (IntPtr)Marshal.StringToHGlobalAnsi(warning);
            ida_ui_warning(warningPointer);
            Marshal.FreeHGlobal(warningPointer);
        }

        public static int ida_msg(string message)
        {
            IntPtr messagePointer = (IntPtr)Marshal.StringToHGlobalAnsi(message);
            var ret = ida_ui_msg(messagePointer);
            Marshal.FreeHGlobal(messagePointer);
            return ret;
        }

        public static int ida_ask_yn(int dflt, string message)
        {
            IntPtr messagePointer = (IntPtr)Marshal.StringToHGlobalAnsi(message);
            var ret = ida_ui_ask_yn(dflt, messagePointer);
            Marshal.FreeHGlobal(messagePointer);
            return ret;
        }

        public static int ida_ask_buttons(string yes, string no, string cancel, int dflt, string message)
        {
            IntPtr yesPointer = (IntPtr)Marshal.StringToHGlobalAnsi(yes);
            IntPtr noPointer = (IntPtr)Marshal.StringToHGlobalAnsi(no);
            IntPtr cancelPointer = (IntPtr)Marshal.StringToHGlobalAnsi(cancel);
            IntPtr messagePointer = (IntPtr)Marshal.StringToHGlobalAnsi(message);
            var ret = ida_ui_ask_buttons(yesPointer, noPointer, cancelPointer, dflt, messagePointer);
            Marshal.FreeHGlobal(messagePointer);
            Marshal.FreeHGlobal(cancelPointer);
            Marshal.FreeHGlobal(noPointer);
            Marshal.FreeHGlobal(yesPointer);
            return ret;
        }

        //public static callui_t ida_callui(UiNotificationType what, params Object[] args)
        //{
        //    return ida_ui_callui((int)what, args);
        //}
    }
}
