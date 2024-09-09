using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public class WaitBox
    {
        public static void Show(string titleText, string labelText, string styleSheet, string icon)
        {
            IntPtr titlePtr = Marshal.StringToHGlobalAnsi(titleText);
            IntPtr labelPtr = Marshal.StringToHGlobalAnsi(labelText);
            IntPtr styleSheetPtr = Marshal.StringToHGlobalAnsi(styleSheet);
            IntPtr iconPtr = Marshal.StringToHGlobalAnsi(icon);
            WaitBox_show(titlePtr, labelPtr, styleSheetPtr, iconPtr);
            Marshal.FreeHGlobal(iconPtr);
            Marshal.FreeHGlobal(styleSheetPtr);
            Marshal.FreeHGlobal(labelPtr);
            Marshal.FreeHGlobal(titlePtr);
        }

        public static void ShowDefault()
        {
            WaitBox_showDefault();
        }

        public static void Hide()
        {
            WaitBox_hide();
        }

        public static bool IsShowing()
        {
            return WaitBox_isShowing();
        }

        public static bool IsUpdateTime()
        {
            return WaitBox_isUpdateTime();
        }

        public static void SetLabelText(string labelText)
        {
            IntPtr labelPtr = Marshal.StringToHGlobalAnsi(labelText);
            WaitBox_setLabelText(labelPtr);
            Marshal.FreeHGlobal(labelPtr);
        }

        public static void ProcessIdaEvents()
        {
            WaitBox_processIdaEvents();
        }

        public static bool UpdateAndCancelCheck(int progress)
        {
            return WaitBox_updateAndCancelCheck(progress);
        }
    }
}
