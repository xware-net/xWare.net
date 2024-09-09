using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public class SegSelect
    {
        public static List<SegmentT> Select(uint flags, string titleText, string styleSheet, string icon)
        {
            var segments = new List<SegmentT>();
            IntPtr titlePtr = Marshal.StringToHGlobalAnsi(titleText);
            IntPtr styleSheetPtr = Marshal.StringToHGlobalAnsi(styleSheet);
            IntPtr iconPtr = Marshal.StringToHGlobalAnsi(icon);
            var selectedSegments = SegSelect_select(flags, titlePtr, styleSheetPtr, iconPtr);
            foreach (var selectedSegment in selectedSegments)
            {
                segments.Add(new SegmentT(selectedSegment));
            }
            Marshal.FreeHGlobal(iconPtr);
            Marshal.FreeHGlobal(styleSheetPtr);
            Marshal.FreeHGlobal(titlePtr);
            return segments;
        }

        public static void Free()
        {
            SegSelect_free();
        }
    }
}
