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
using Flags64T = System.UInt64;

using static IdaPlusPlus.IdaInterop;
using IdaNet.IdaInterop;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace IdaNet.IdaInterop
{
    public enum FFFlags : UInt64
    {
        MS_VAL = 0x00000000000000FF,
        MS_CLS = 0x0000000000000600,             ///< Mask for typing
        FF_CODE = 0x0000000000000600,             ///< Code ?
        FF_DATA = 0x0000000000000400,             ///< Data ?
        FF_TAIL = 0x0000000000000200,             ///< Tail ?
        FF_UNK = 0x0000000000000000,             ///< Unknown ?

        FF_IVL = 0x0000000000000100,
        FF_BYTE = 0x0000000000000000,         ///< byte
        FF_WORD = 0x0000000010000000,         ///< word
        FF_DWORD = 0x0000000020000000,         ///< double word
        FF_QWORD = 0x0000000030000000,         ///< quadro word
        FF_TBYTE = 0x0000000040000000,         ///< tbyte
        FF_STRLIT = 0x0000000050000000,         ///< string literal
        FF_STRUCT = 0x0000000060000000,         ///< struct variable
        FF_OWORD = 0x0000000070000000,         ///< octaword/xmm word (16 bytes/128 bits)
        FF_FLOAT = 0x0000000080000000,         ///< float
        FF_DOUBLE = 0x0000000090000000,         ///< double
        FF_PACKREAL = 0x00000000A0000000,         ///< packed decimal real
        FF_ALIGN = 0x00000000B0000000,         ///< alignment directive
        FF_CUSTOM = 0x00000000D0000000,         ///< custom data type
        FF_YWORD = 0x00000000E0000000,         ///< ymm word (32 bytes/256 bits)
        FF_ZWORD = 0x00000000F0000000,         ///< zmm word (64 bytes/512 bits)

        DT_TYPE = 0x00000000F0000000,             //< Mask for DATA typing
        MS_COMM = 0x00000000000FF800,            //< Mask of common bits
        FF_COMM = 0x0000000000000800,            //< Has comment ?
        FF_REF = 0x0000000000001000,            //< has references
        FF_LINE = 0x0000000000002000,            //< Has next or prev lines ?
        FF_NAME = 0x0000000000004000,            //< Has name ?
        FF_LABL = 0x0000000000008000,            //< Has dummy name?
        FF_FLOW = 0x0000000000010000,            //< Exec flow from prev instruction
        FF_SIGN = 0x0000000000020000,            //< Inverted sign of operands
        FF_BNOT = 0x0000000000040000,            //< Bitwise negation of operands
        FF_UNUSED = 0x0000000000080000,           //< unused bit (was used for variable bytes)
        FF_ANYNAME = 0x000000000000C000,

        MS_N_TYPE = 0xF,                          ///< Mask for nth arg
        FF_N_VOID = 0x0,                             ///< Void (unknown)?
        FF_N_NUMH = 0x1,                             ///< Hexadecimal number?
        FF_N_NUMD = 0x2,                             ///< Decimal number?
        FF_N_CHAR = 0x3,                             ///< Char ('x')?
        FF_N_SEG = 0x4,                             ///< Segment?
        FF_N_OFF = 0x5,                             ///< Offset?
        FF_N_NUMB = 0x6,                             ///< Binary number?
        FF_N_NUMO = 0x7,                             ///< Octal number?
        FF_N_ENUM = 0x8,                             ///< Enumeration?
        FF_N_FOP = 0x9,                             ///< Forced operand?
        FF_N_STRO = 0xA,                             ///< Struct offset?
        FF_N_STK = 0xB,                             ///< Stack variable?
        FF_N_FLT = 0xC,                             ///< Floating point number?
        FF_N_CUST = 0xD,                             ///< Custom representation?

        MS_CODE = 0x00000000F0000000,             ///< Mask for CODE typing
        FF_FUNC = 0x0000000010000000,             ///< function start?
        FF_IMMD = 0x0000000040000000,             ///< Has Immediate value ?
        FF_JUMP = 0x0000000080000000,             ///< Has jump table or switch_info?
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

        internal static bool IsEa(Flags64T f)
        {
            return IsQword(f);
        }

        internal static bool IsUnknown(Flags64T f)
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
            Flags64T flags = ida_get_flags(ea);

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

        internal static bool IsDword(Flags64T F)
        {
            return IsData(F) && (F & (uint)FFFlags.DT_TYPE) == (uint)FFFlags.FF_DWORD;
        }

        internal static bool IsQword(Flags64T F)
        {
            return IsData(F) && (F & (uint)FFFlags.DT_TYPE) == (uint)FFFlags.FF_QWORD;
        }

        internal static bool IsData(Flags64T F)
        {
            return (F & (uint)FFFlags.MS_CLS) == (uint)FFFlags.FF_DATA;
        }

        internal static bool IsCode(Flags64T F)
        {
            return (F & (uint)FFFlags.MS_CLS) == (uint)FFFlags.FF_CODE;
        }

        internal static bool IsFunc(Flags64T F)
        {
            return (F & (uint)FFFlags.MS_CLS) == (uint)FFFlags.FF_FUNC;
        }

        internal static bool HasXref(Flags64T F)
        {
            return (F & (uint)FFFlags.FF_REF) != 0;
        }

        internal static bool HasAnyName(Flags64T F)
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

    public class CompiledBinpatT : IEquatable<CompiledBinpatT>
    {
        public BytevecT Bytes { get; set; }
        public BytevecT Mask { get; set; }
        public RangevecT Strlits { get; set; }
        public int Encidx { get; set; }

        public CompiledBinpatT()
        {
            Encidx = -1;
        }

        public bool AllBytesDefined()
        {
            return Mask.Empty();
        }

        public void Qclear()
        {
            Bytes.Qclear();
            Mask.Qclear();
            Strlits.Qclear();
            Encidx = -1;
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as CompiledBinpatT);
        }

        public bool Equals(CompiledBinpatT other)
        {
            return other != null 
                && Bytes == other.Bytes
                && Mask == other.Mask
                && Strlits == other.Strlits
                && Encidx == other.Encidx;
        }

        public override int GetHashCode() => (Bytes, Mask, Strlits, Encidx).GetHashCode();

        public static bool operator ==(CompiledBinpatT a, CompiledBinpatT b)
        {
            return a.Bytes == b.Bytes
                && a.Mask == b.Mask
                && a.Strlits == b.Strlits
                && a.Encidx == b.Encidx;
        }

        public static bool operator !=(CompiledBinpatT a, CompiledBinpatT b)
        {
            return !(a == b);
        }
    }

    public class HiddenRangeT : RangeT
    {
        public HiddenRangeT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            StartEa = (EaT)MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x00);
            EndEa = (EaT)MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x08);
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
