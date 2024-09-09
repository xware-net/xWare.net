using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using ManagedPlugin;

using ea_t = System.UInt64;
using sel_t = System.UInt64;
using size_t = System.UInt64;
using asize_t = System.UInt64;
using adiff_t = System.Int64;
using uval_t = System.UInt64;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    /// <summary>Provides access to entry points. Exported functons are considered
    /// as entry point as well. IDA maintains list of entry points to the program.
    /// Each entry point
    /// - has an address
    /// - has a name
    /// - may have an ordinal number
    /// </summary>
    public class EntryPoint
    {
        #region CONSTRUCTORS
        private EntryPoint()
        {
            return;
        }
        #endregion

        #region PROPERTIES

        internal ea_t Address { get; private set; }

        /// <summary>Get number of entry points</summary>
        internal static size_t Count
        {
            get { return ida_get_entry_qty(); }
        }

        internal string Name { get; private set; }

        #endregion

        #region METHODS

        /// <summary>Add an entry point to the list of entry points.</summary>
        /// <param name="ordinal">ordinal number if ordinal number is equal to
        /// <paramref name="linearAddress"/> then ordinal is not used</param>
        /// <param name="linearAddress">Linear address.</param>
        /// <param name="name">name of entry point. If the specified location
        /// alreadyhas a name, the old name will be appended to the regular
        /// comment. If name == NULL, then the old name will be retained.</param>
        /// <param name="makeCode">should the kernel convert bytes at the entry
        /// point to instruction(s)</param>
        /// <returns>success (currently always true)</returns>
        //internal static bool Add(uval_t ordinal, ea_t linearAddress, string name, bool makeCode)
        //{
        //    sbyte[] newNameBytes = Array.ConvertAll(System.Text.Encoding.ASCII.GetBytes(name), q => Convert.ToSByte(q));
        //    unsafe
        //    {
        //        fixed (sbyte* p = newNameBytes)
        //        {
        //            sbyte* sp = (sbyte*)p;
        //            return ida_add_entry(ordinal, linearAddress, sp, makeCode, 0);
        //        }
        //    }
        //}

        internal static IEnumerable<EntryPoint> EnumerateEntryPoints()
        {
            size_t upperBound = Count;
            for (size_t index = 0; index < upperBound; index++)
            {
                uval_t ordinal = ida_get_entry_ordinal(index);
                EntryPoint result = new EntryPoint
                {
                    Address = ida_get_entry(ordinal)
                };

                IntPtr nativeBuffer = IntPtr.Zero;

                try
                {
                    var requiredSize = ida_get_entry_name(IntPtr.Zero, ordinal);
                    if (-1 == requiredSize) 
                    { 
                        result.Name = string.Empty; 
                    } else
                    {
                        nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                        requiredSize = ida_get_entry_name(nativeBuffer, ordinal);
                        if (0 <= requiredSize) 
                        { 
                            result.Name = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                        }
                    }
                }
                catch (Exception ex)
                {
                    PluginBase.WriteDebugMessage("Exception {0}\n stack trace {1}", ex.Message, ex.StackTrace);
                    result.Name = ex.Message;
                }
                finally 
                { 
                    if (IntPtr.Zero != nativeBuffer) 
                    { 
                        Marshal.FreeCoTaskMem(nativeBuffer); 
                    } 
                }

                yield return result;
            }

            yield break;
        }

        /// <summary>Rename entry point</summary>
        /// <param name="ordinal">ordinal number of the entry point</param>
        /// <param name="newName">name of entry point. If the specified location
        /// already has a name, the old name will be appended to a repeatable
        /// comment.</param>
        /// <returns>true on success, false on failure</returns>
        //internal static bool Rename(uval_t ordinal, string newName, int flags)
        //{
        //    sbyte[] newNameBytes = Array.ConvertAll(System.Text.Encoding.ASCII.GetBytes(newName), q => Convert.ToSByte(q));
        //    unsafe
        //    {
        //        fixed (sbyte* p = newNameBytes)
        //        {
        //            sbyte* sp = (sbyte*)p;
        //            return ida_rename_entry(ordinal, sp, flags);
        //        }
        //    }
        //}

        #endregion
    }
}
