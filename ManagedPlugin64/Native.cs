using System;
using System.Runtime.InteropServices;

namespace ManagedPlugin
{
    internal static class Native
    {
        #region INTEROP
        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true, PreserveSig = true)]
        internal static extern bool CloseHandle([In] IntPtr handle);

        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true, PreserveSig = true)]
        internal static extern IntPtr CreateEvent([In] IntPtr securityAttributes, [In] bool manualReset, [In] bool initialState, [In] string name);

        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true, PreserveSig = true)]
        internal static extern IntPtr SetEvent([In] IntPtr hEvent);
        #endregion
    }
}
