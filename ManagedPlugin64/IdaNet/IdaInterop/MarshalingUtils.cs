using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

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

namespace IdaNet.IdaInterop
{
    /// <summary>A set of marshaling utility functions.</summary>
    internal static class MarshalingUtils
    {
        internal static IntPtr Combine(IntPtr baseAddress, int ea64Offset)
        {
            return new IntPtr(baseAddress.ToInt32() + ea64Offset);
        }

        internal static adiff_t GetAddressDifference(IntPtr nativePointer, ushort ea64Offset)
        {
            return (adiff_t)Marshal.ReadInt64(nativePointer, ea64Offset);
        }

        internal static bool GetBool(IntPtr nativePointer, ushort ea64Offset)
        {
            return (0 != Marshal.ReadByte(nativePointer, ea64Offset));
        }

        internal static void SetBool(IntPtr nativePointer, ushort ea64Offset, bool value)
        {
            Marshal.WriteByte(nativePointer, ea64Offset, value == false ? (byte)0 : (byte)1);
        }

        internal static byte GetByte(IntPtr nativePointer, ushort ea64Offset)
        {
            return (byte)Marshal.ReadByte(nativePointer, ea64Offset);
        }

        internal static void SetByte(IntPtr nativePointer, ushort ea64Offset, byte value)
        {
            Marshal.WriteByte(nativePointer, ea64Offset, value);
        }

        internal static byte[] GetBytes(IntPtr nativePointer, ushort ea64Offset, int length)
        {
            byte[] result = new byte[length];
            IntPtr baseAddress;
            baseAddress = new IntPtr(nativePointer.ToInt64() + ea64Offset);
            Marshal.Copy(baseAddress, result, 0, length);
            return result;
        }

        internal static ea_t GetEffectiveAddress(IntPtr nativePointer, ushort ea64Offset)
        {
            return (ea_t)Marshal.ReadInt64(nativePointer, ea64Offset);
        }

        internal static void SetEffectiveAddress(IntPtr nativePointer, ushort ea64Offset, ea_t value)
        {
            Marshal.WriteInt64(nativePointer, ea64Offset, (long)value);
            return;
        }

        internal static T GetFunctionPointer<T>(IntPtr nativePointer, ushort ea64Offset)
            where T : class
        {
            return Marshal.GetDelegateForFunctionPointer(
                Marshal.ReadIntPtr(nativePointer, ea64Offset),
                typeof(T)) as T;
        }

        internal static int GetInt32(IntPtr nativePointer, ushort ea64Offset)
        {
            return Marshal.ReadInt32(nativePointer, ea64Offset);
        }

        internal static void SetInt32(IntPtr nativePointer, ushort ea64Offset, int value)
        {
            Marshal.WriteInt32(nativePointer, ea64Offset, value);
        }

        internal static void SetUInt32(IntPtr nativePointer, ushort ea64Offset, UInt32 value)
        {
            Marshal.WriteInt32(nativePointer, ea64Offset, (int)value);
        }

        internal static IntPtr GetIntPtr(IntPtr nativePointer, ushort ea64Offset)
        {
            return Marshal.ReadIntPtr(nativePointer, ea64Offset);
        }

        internal static void SetIntPtr(IntPtr nativePointer, ushort ea64Offset, IntPtr value)
        {
            Marshal.WriteIntPtr(nativePointer, ea64Offset, value);
        }

        internal static asize_t GetMemoryChunkSize(IntPtr nativePointer, ushort ea64Offset)
        {
            return (asize_t)Marshal.ReadInt64(nativePointer, ea64Offset);
        }

        internal static byte[] GetNullTerminatedBytes(IntPtr nativePointer)
        {
            List<byte> result = new List<byte>();
            int offset = 0;

            while (true)
            {
                byte scannedByte = Marshal.ReadByte(nativePointer, offset);
                if (0 == scannedByte) { return result.ToArray(); }
                result.Add(scannedByte);
                offset++;
            }
        }

        internal static sel_t GetSegmentSelector(IntPtr nativePointer, ushort ea64Offset)
        {
            return (sel_t)Marshal.ReadInt64(nativePointer, ea64Offset);
        }

        internal static string GetString(IntPtr nativePointer, ushort ea64Offset)
        {
            IntPtr stringAddress = Marshal.ReadIntPtr(nativePointer, ea64Offset);
            return (IntPtr.Zero == stringAddress) ? null : Marshal.PtrToStringAnsi(stringAddress);
        }

        internal static string[] GetStringsArray(IntPtr nativePointer, ushort ea64Offset)
        {
            IntPtr arrayBase = Marshal.ReadIntPtr(nativePointer, ea64Offset);
            List<string> names = new List<string>();
            int index = 0;

            do
            {
                IntPtr stringPointer = Marshal.ReadIntPtr(arrayBase, 4 * index++);

                if (IntPtr.Zero == stringPointer) 
                { 
                    break; 
                }

                names.Add(Marshal.PtrToStringAnsi(stringPointer));
            } while (true);

            return names.ToArray();
        }

        internal static ushort GetUShort(IntPtr nativePointer, ushort ea64Offset)
        {
            return (ushort)Marshal.ReadInt16(nativePointer, ea64Offset);
        }

        internal static void SetUShort(IntPtr nativePointer, ushort ea64Offset, ushort value)
        {
            Marshal.WriteInt16(nativePointer, ea64Offset, (short)value);
            return;
        }

        internal static UInt32 GetUInt32(IntPtr nativePointer, ushort ea64Offset)
        {
            return (UInt32)Marshal.ReadInt32(nativePointer, ea64Offset);
        }

        internal static void WriteByte(IntPtr nativePointer, ushort ea64Offset, byte value)
        {
            Marshal.WriteByte(nativePointer, ea64Offset, value);
            return;
        }

        /// <summary>
        /// Convert an IntPtr to a string array
        /// </summary>
        /// <param name="stringPtr">The pointer to the first element of the array</param>
        /// <param name="stringCount">The number of elements in the array</param>
        /// <returns>The string array</returns>
        public static string[] IntPtrToStringArray(IntPtr stringPtr, int stringCount)
        {
            string[] members = new string[stringCount];
            for (int i = 0; i < stringCount; ++i)
            {
                IntPtr s = Marshal.ReadIntPtr(stringPtr, i * IntPtr.Size);
                members[i] = Marshal.PtrToStringAnsi(s);
            }
            return members;
        }
        /// <summary>
        /// Convert a list of IntPtrs to a string array
        /// </summary>
        /// <param name="stringPtr">The pointer to the list of IntPtrs</param>
        /// <param name="stringCount"> number of elements in list</param>
        /// <returns></returns>
        public static string[] ListOfIntPtrToStringArray(List<IntPtr> stringPtr, int stringCount)
        {
            string[] members = new string[stringCount];
            for (int i = 0; i < stringCount; ++i)
            {
                IntPtr s = stringPtr[i];
                members[i] = Marshal.PtrToStringAnsi(s);
                Marshal.FreeCoTaskMem(s);
            }
            return members;
        }
        /// <summary>
        /// Convert a list of IntPtrs to a string array
        /// </summary>
        /// <param name="stringPtr">The pointer to the list of IntPtrs</param>
        /// <param name="stringCount"> number of elements in list</param>
        /// <returns></returns>
        public static string[] ListOfIntPtrToWStringArray(List<IntPtr> stringPtr, int stringCount)
        {
            string[] members = new string[stringCount];
            for (int i = 0; i < stringCount; ++i)
            {
                IntPtr s = stringPtr[i];
                members[i] = Marshal.PtrToStringUni(s);
                Marshal.FreeCoTaskMem(s);
            }
            return members;
        }
        /// <summary>
        /// Convert an IntPtr to a string
        /// </summary>
        /// <param name="stringPtr">The pointer</param>
        /// <returns>The string</returns>
        public static string IntPtrPtrToString(IntPtr stringPtr)
        {
            IntPtr s = Marshal.ReadIntPtr(stringPtr, IntPtr.Size);
            return Marshal.PtrToStringAnsi(s);
        }
        /// <summary>
        /// Shift a pointer by offset (32 or 64 bits pointer)
        /// </summary>
        /// <param name="src">The pointer</param>
        /// <param name="offset">The offset in bytes</param>
        /// <returns>the shifted pointer</returns>
        public static IntPtr IntPtrOffset(IntPtr src, int offset)
        {
            switch (IntPtr.Size)
            {
                case 4:
                    return new IntPtr(src.ToInt32() + offset);
                case 8:
                    return new IntPtr(src.ToInt64() + offset);
                default:
                    throw new NotSupportedException("Surprise!  This is running on a machine where pointers are " + IntPtr.Size + " bytes and arithmetic doesn't work in C# on them.");
            }
        }
    }
}
