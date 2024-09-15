﻿using System;
using System.Runtime.InteropServices;

using EaT = System.UInt64;
using TidT = System.UInt64;
using SelT = System.UInt64;
using SizeT = System.UInt64;
using AsizeT = System.UInt64;
using AdiffT = System.Int64;
using UvalT = System.UInt64;
using BgcolorT = System.UInt32;
using FlagsT = System.UInt32;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public enum FFFlags : uint
    {
        MS_VAL = 0x000000FF,
        MS_CLS = 0x00000600,             ///< Mask for typing
        FF_CODE = 0x00000600,             ///< Code ?
        FF_DATA = 0x00000400,             ///< Data ?
        FF_TAIL = 0x00000200,             ///< Tail ?
        FF_UNK = 0x00000000,             ///< Unknown ?

        FF_IVL = 0x00000100,
        FF_BYTE = 0x00000000,         ///< byte
        FF_WORD = 0x10000000,         ///< word
        FF_DWORD = 0x20000000,         ///< double word
        FF_QWORD = 0x30000000,         ///< quadro word
        FF_TBYTE = 0x40000000,         ///< tbyte
        FF_STRLIT = 0x50000000,         ///< string literal
        FF_STRUCT = 0x60000000,         ///< struct variable
        FF_OWORD = 0x70000000,         ///< octaword/xmm word (16 bytes/128 bits)
        FF_FLOAT = 0x80000000,         ///< float
        FF_DOUBLE = 0x90000000,         ///< double
        FF_PACKREAL = 0xA0000000,         ///< packed decimal real
        FF_ALIGN = 0xB0000000,         ///< alignment directive
        FF_CUSTOM = 0xD0000000,         ///< custom data type
        FF_YWORD = 0xE0000000,         ///< ymm word (32 bytes/256 bits)
        FF_ZWORD = 0xF0000000,         ///< zmm word (64 bytes/512 bits)

        DT_TYPE = 0xF0000000,             //< Mask for DATA typing
        MS_COMM = 0x000FF800,            //< Mask of common bits
        FF_COMM = 0x00000800,            //< Has comment ?
        FF_REF = 0x00001000,            //< has references
        FF_LINE = 0x00002000,            //< Has next or prev lines ?
        FF_NAME = 0x00004000,            //< Has name ?
        FF_LABL = 0x00008000,            //< Has dummy name?
        FF_FLOW = 0x00010000,            //< Exec flow from prev instruction
        FF_SIGN = 0x00020000,            //< Inverted sign of operands
        FF_BNOT = 0x00040000,            //< Bitwise negation of operands
        FF_UNUSED = 0x00080000,           //< unused bit (was used for variable bytes)

        FF_FUNC = 0x10000000,             ///< function start?
        FF_IMMD = 0x40000000,             ///< Has Immediate value ?
        FF_JUMP = 0x80000000,             ///< Has jump table or switch_info?
    }

    public enum SetNameFlags : ushort
    {
        SN_CHECK = 0x00,
        SN_NOCHECK = 0x01, //< Don't fail if the name contains invalid characters.
        SN_PUBLIC = 0x02, //< if set, make name public
        SN_NON_PUBLIC = 0x04, //< if set, make name non-public
        SN_WEAK = 0x08, //< if set, make name weak
        SN_NON_WEAK = 0x10, //< if set, make name non-weak
        SN_AUTO = 0x20, //< if set, make name autogenerated
        SN_NON_AUTO = 0x40, //< if set, make name non-autogenerated
        SN_NOLIST = 0x80, //< if set, exclude name from the list.
        SN_NOWARN = 0x100, //< don't display a warning if failed
        SN_LOCAL = 0x200, //< create local name. a function should exist.
        SN_IDBENC = 0x400, //< the name is given in the IDB encoding;
        SN_FORCE = 0x800, //< if the specified name is already present
        SN_NODUMMY = 0x1000, //< automatically prepend the name with '_' if it
        SN_DELTAIL = 0x2000, //< if name cannot be set because of a tail byte,
    }

    public class Bytes
    {
        internal static bool SetName(EaT ea, string name)
        {
            IntPtr namePtr = Marshal.StringToHGlobalAnsi(name);
            var ret = ida_set_name(ea, namePtr, (int)(SetNameFlags.SN_NON_AUTO | SetNameFlags.SN_NOWARN | SetNameFlags.SN_NOCHECK | SetNameFlags.SN_FORCE));
            Marshal.FreeHGlobal(namePtr);
            return ret;
        }

        internal static bool HasName(EaT ea)
        {
            return ida_has_name(ida_get_flags(ea));
        }

        internal static bool HasComment(EaT ea)
        {
            return ida_has_cmt(ida_get_flags(ea));
        }

        internal static bool SetComment(EaT ea, string comment, bool rptble)
        {
            IntPtr commentPtr = Marshal.StringToHGlobalAnsi(comment);
            var ret = ida_set_cmt(ea, commentPtr, rptble);
            Marshal.FreeHGlobal(commentPtr);
            return ret;
        }

        internal static byte GetByte(EaT ea)
        {
            return ida_get_byte(ea);
        }

        internal static SizeT GetMaxStrlitLength(EaT ea, Int32 strtype, Int32 options)
        {
            return ida_get_max_strlit_length(ea, strtype, options);
        }

        internal static EaT GetEa(EaT ea)
        {
            return (EaT)ida_get_64bit(ea);
        }

        internal static bool IsEa(FlagsT f)
        {
            return IsQword(f);
        }

        internal static bool IsUnknown(FlagsT f)
        {
            return (f & (uint)FFFlags.MS_CLS) == (uint)FFFlags.FF_UNK;
        }

        internal static bool GetVerifyEa(EaT ea, ref EaT rValue)
        {
            // Location valid?
            if (ida_is_loaded(ea))
            {
                // Get ea_t value
                rValue = GetEa(ea);
                return true;
            }

            return false;
        }

        internal static bool GetVerify32(EaT ea, ref uint rValue)
        {
            // Location valid?
            if (ida_is_loaded(ea))
            {
                // Get ea_t value
                rValue = ida_get_32bit(ea);
                return true;
            }

            return false;
        }

        internal static bool GetVerify32(EaT ea, ref ulong rValue)
        {
            // Location valid?
            if (ida_is_loaded(ea))
            {
                // Get ea_t value
                rValue = (ulong)ida_get_32bit(ea);
                return true;
            }

            return false;
        }

        internal static bool PutDword(EaT ea)
        {
            return ida_create_dword(ea, false);
        }

        internal static bool PutEa(EaT ea)
        {
            return ida_create_qword(ea, false);
        }

        internal static FlagsT CalcDflags(FlagsT f, bool force)
        {
            return f | (force ? (uint)FFFlags.FF_COMM : 0);
        }

        internal static bool CreateStruct(EaT ea, AsizeT length, TidT tid, bool force = false)
        {
            return ida_create_data(ea, CalcDflags((FlagsT)FFFlags.FF_STRUCT, force), length, tid);
        }

        internal static void FixDword(EaT ea)
        {
            if (!IsDword(ida_get_flags(ea)))
            {
                SetUnknown(ea, sizeof(uint));
                ida_create_dword(ea, false);
            }
        }

        internal static void FixEa(EaT ea)
        {
            if (!IsQword(ida_get_flags(ea)))
            {
                SetUnknown(ea, sizeof(UInt64));
                ida_create_qword(ea, false);
            }
        }

        internal static void FixFunction(EaT ea)
        {
            FlagsT flags = ida_get_flags(ea);

            // No code here?
            if (!IsCode(flags))
            {
                // Attempt to make it so
                ida_create_insn(ea, IntPtr.Zero);
                ida_add_func(ea, DefineConstants.BADADDR);
            }
            else
            {
                // Yea there is code here, should have a function body too
                if (!IsFunc(flags))
                    ida_add_func(ea, DefineConstants.BADADDR);
            }
        }

        internal static void SetUnknown(EaT ea, uint siz)
        {
            ida_del_items(ea, (int)DelItemsFlags.DELIT_EXPAND, (AsizeT)siz);
        }

        internal static bool IsDword(FlagsT F)
        {
            return IsData(F) && (F & (uint)FFFlags.DT_TYPE) == (uint)FFFlags.FF_DWORD;
        }

        internal static bool IsQword(FlagsT F)
        {
            return IsData(F) && (F & (uint)FFFlags.DT_TYPE) == (uint)FFFlags.FF_QWORD;
        }

        internal static bool IsData(FlagsT F)
        {
            return (F & (uint)FFFlags.MS_CLS) == (uint)FFFlags.FF_DATA;
        }

        internal static bool IsCode(FlagsT F)
        {
            return (F & (uint)FFFlags.MS_CLS) == (uint)FFFlags.FF_CODE;
        }

        internal static bool IsFunc(FlagsT F)
        {
            return (F & (uint)FFFlags.MS_CLS) == (uint)FFFlags.FF_FUNC;
        }

        internal static bool HasXref(FlagsT F)
        {
            return (F & (uint)FFFlags.FF_REF) != 0;
        }

        internal static bool HasAnyName(FlagsT F)
        {
            return (F & ((uint)FFFlags.FF_NAME | (uint)FFFlags.FF_LABL)) != 0;
        }

        public static void SetAnteriorComment(EaT ea, string format)
        {
            IntPtr formatPtr = Marshal.StringToHGlobalAnsi(format);
            ida_add_extra_line(ea, false, formatPtr);
            Marshal.FreeHGlobal(formatPtr);
        }

        public static bool HasAnteriorComment(EaT ea)
        {
            return (ida_get_first_free_extra_cmtidx(ea, DefineConstants.E_PREV) != DefineConstants.E_PREV);
        }

        public static void KillAnteriorComments(EaT ea)
        {
            ida_delete_extra_cmts(ea, DefineConstants.E_PREV);
        }

        public static EaT FindBinary2(EaT start_ea, EaT end_ea, string pattern, ref string errorStr)
        {
            IntPtr patternPtr = Marshal.StringToHGlobalAnsi(pattern);
            IntPtr errorStrPtr = Marshal.AllocCoTaskMem(DefineConstants.MAXSTR);
            var ea = ida_find_binary2(start_ea, end_ea, patternPtr, errorStrPtr);
            errorStr = Marshal.PtrToStringAnsi(errorStrPtr);
            Marshal.FreeCoTaskMem(errorStrPtr);
            Marshal.FreeHGlobal(patternPtr);
            return ea;
        }

        public static EaT FindBinary2(EaT start_ea, EaT end_ea, string pattern)
        {
            IntPtr patternPtr = Marshal.StringToHGlobalAnsi(pattern);
            var ea = ida_find_binary2(start_ea, end_ea, patternPtr, IntPtr.Zero);
            Marshal.FreeHGlobal(patternPtr);
            return ea;
        }
    }

    public class OctetGeneratorT
    {
        #region CONSTRUCTORS
        OctetGeneratorT(EaT ea)
        {
            Value = 0;
            Ea = ea;
            AvailBits = 0;
            HighByteFirst = ida_inf_is_wide_high_byte_first();
        }
        #endregion

        #region PROPERTIES
        internal UInt64 Value = 0;
        internal EaT Ea;
        internal int AvailBits = 0;
        internal bool HighByteFirst = ida_inf_is_wide_high_byte_first();
        #endregion

        #region METHODS
        public void InvertByteOrder()
        {
            HighByteFirst = !HighByteFirst;
        }
        public int Compare(OctetGeneratorT r)
        {

            // COMPARE_FIELDS(ea);
            if (AvailBits < r.AvailBits)
                return 1;
            if (AvailBits > r.AvailBits)
                return -1;
            return 0;
        }
        #endregion
    }

    public class DataTypeT
    {
        public IntPtr UnmanagedPtr { get; set; }

        public DataTypeT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
        }
    }

    public class DataFormatT
    {
        public IntPtr UnmanagedPtr { get; set; }

        public DataFormatT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
        }
    }

    public class CompiledBinpatT
    {
        public IntPtr UnmanagedPtr { get; set; }

        public CompiledBinpatT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
        }
    }

    public class HiddenRangeT : RangeT
    {
        public HiddenRangeT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            base.StartEa = (EaT)MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x00);
            base.EndEa = (EaT)MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x08);
            description = MarshalingUtils.GetString(UnmanagedPtr, 0x10);
            header = MarshalingUtils.GetString(UnmanagedPtr, 0x18);
            footer = MarshalingUtils.GetString(UnmanagedPtr, 0x20);
        }

        public IntPtr UnmanagedPtr { get; set; }

        public IntPtr descriptionPtr
        {
            get => MarshalingUtils.GetIntPtr(UnmanagedPtr, 0x10);
            set => MarshalingUtils.SetIntPtr(UnmanagedPtr, 0x10, value);
        }

        internal string description;

        public IntPtr headerPtr
        {
            get => MarshalingUtils.GetIntPtr(UnmanagedPtr, 0x18);
            set => MarshalingUtils.SetIntPtr(UnmanagedPtr, 0x18, value);
        }

        internal string header;

        public IntPtr footerPtr
        {
            get => MarshalingUtils.GetIntPtr(UnmanagedPtr, 0x20);
            set => MarshalingUtils.SetIntPtr(UnmanagedPtr, 0x20, value);
        }

        internal string footer;

        public bool visible
        {
            get => MarshalingUtils.GetBool(UnmanagedPtr, 0x28);
            set => MarshalingUtils.SetBool(UnmanagedPtr, 0x28, value);
        }

        public BgcolorT color
        {
            get => MarshalingUtils.GetUInt32(UnmanagedPtr, 0x2C);
            set => MarshalingUtils.SetUInt32(UnmanagedPtr, 0x2C, value);
        }
    }
}
