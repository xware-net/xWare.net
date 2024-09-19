using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using EaT = System.UInt64;
using TidT = System.UInt64;
using SelT = System.UInt64;
using SizeT = System.UInt64;
using AsizeT = System.UInt64;
using AdiffT = System.Int64;
using UvalT = System.UInt64;
using BgcolorT = System.UInt32;
using FlagsT = System.UInt32;

using System.Runtime.InteropServices;

namespace IdaNet.IdaInterop
{
    public enum StrucErrorT : int
    {
        STRUC_ERROR_MEMBER_OK = 0,
        STRUC_ERROR_MEMBER_NAME = -1,
        STRUC_ERROR_MEMBER_OFFSET = -2,
        STRUC_ERROR_MEMBER_SIZE = -3,
        STRUC_ERROR_MEMBER_TINFO = -4,
        STRUC_ERROR_MEMBER_STRUCT = -5,
        STRUC_ERROR_MEMBER_UNIVAR = -6,
        STRUC_ERROR_MEMBER_VARLAST = -7,
        STRUC_ERROR_MEMBER_NESTED = -8,
    }

    public enum SmtCodeT : int
    {
        SMT_BADARG = -6,
        SMT_NOCOMPAT = -5,
        SMT_WORSE = -4,
        SMT_SIZE = -3,
        SMT_ARRAY = -2,
        SMT_OVERLAP = -1,
        SMT_FAILED = 0,
        SMT_OK = 1,
        SMT_KEEP = 2,
    };

    [Flags()]
    public enum MemberProperties : UInt32
    {
        MF_OK = 0x00000001,
        MF_UNIMEM = 0x00000002,
        MF_HASUNI = 0x00000004,
        MF_BYTIL = 0x00000008,
        MF_HASTI = 0x00000010,
        MF_BASECLASS = 0x00000020,
        MF_DTOR = 0x00000040,
        MF_DUPNAME = 0x00000080,
        MF_RESERVED1 = 0x80000000,
    }

    public enum StructureFlags : UInt32
    {
        SF_VAR = 0x00000001,
        SF_UNION = 0x00000002,
        SF_HASUNI = 0x00000004,
        SF_NOLIST = 0x00000008,
        SF_TYPLIB = 0x00000010,
        SF_HIDDEN = 0x00000020,
        SF_FRAME = 0x00000040,
        SF_ALIGN = 0x00000F80,
        SF_GHOST = 0x00001000,
    }

    [Flags()]
    public enum MemberFlags : UInt32
    {
        MF_OK = 0x00000001,    ///< is the member ok? (always yes)
        MF_UNIMEM = 0x00000002,    ///< is a member of a union?
        MF_HASUNI = 0x00000004,    ///< has members of type "union"?
        MF_BYTIL = 0x00000008,    ///< the member was created due to the type system
        MF_HASTI = 0x00000010,    ///< has type information?
        MF_BASECLASS = 0x00000020,    ///< a special member representing base class
        MF_DTOR = 0x00000040,    ///< a special member representing destructor
        MF_DUPNAME = 0x00000080,    ///< duplicate name resolved with _N suffix (N==soff)
        MF_RESERVED1 = 0x80000000,    ///< reserved (for internal usage)
    }

    public class MemberT
    {
        public IntPtr UnmanagedPtr { get; set; }
        public TidT Id 
        {
            get { return MarshalingUtils.GetUInt64(UnmanagedPtr, 0x00); }
            set { MarshalingUtils.SetUInt64(UnmanagedPtr, 0x00, value); }
        }
        public EaT Soff 
        {
            get { return MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x08); }
            set { MarshalingUtils.SetEffectiveAddress(UnmanagedPtr, 0x08, value); }
        }
        public EaT Eoff
        {
            get { return MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x10); }
            set { MarshalingUtils.SetEffectiveAddress(UnmanagedPtr, 0x10, value); }
        }
        public FlagsT Flag
        {
            get { return MarshalingUtils.GetUInt32(UnmanagedPtr, 0x18); }
            set { MarshalingUtils.SetUInt32(UnmanagedPtr, 0x18, value); }
        }
        public UInt32 Props
        {
            get { return MarshalingUtils.GetUInt32(UnmanagedPtr, 0x1C); }
            set { MarshalingUtils.SetUInt32(UnmanagedPtr, 0x1C, value); }
        }

        public MemberT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
        }

        bool Unimem()
        {
            return (Props & (UInt32)MemberFlags.MF_UNIMEM) != 0;
        }

        bool HasUnion()
        {
            return (Props & (UInt32)MemberFlags.MF_HASUNI) != 0;
        }

        bool ByTil()
        {
            return (Props & (UInt32)MemberFlags.MF_BYTIL) != 0;
        }

        bool HasTi()
        {
            return (Props & (UInt32)MemberFlags.MF_HASTI) != 0;
        }

        bool IsBaseclass()
        {
            return (Props & (UInt32)MemberFlags.MF_BASECLASS) != 0;
        }

        bool IsDupname()
        {
            return (Props & (UInt32)MemberFlags.MF_DUPNAME) != 0;

        }

        bool IsDestructor()
        {
            return (Props & (UInt32)MemberFlags.MF_DTOR) != 0;
        }

        EaT GetSoff()
        {
            return Unimem() ? 0 : Soff;
        }

        AsizeT GetSize()
        {
            return Eoff - GetSoff();
        }
    }

    public unsafe struct StrpathT
    {
        int len;
        fixed TidT ids[32]; // for union member ids
        AdiffT delta;
    }

    public struct EnumConstT
    {
        TidT tid;
        byte serial;
    }

    public struct CustomDataTypeIdsT
    {
    }

    public struct RefinfoT
    {
        public EaT target;
        public EaT basr;
        public AdiffT tdelta;
        public UInt32 flags;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct OpinfoT
    {
        [FieldOffset(0)]
        public RefinfoT ri;
        [FieldOffset(0)]
        public TidT tid;
        [FieldOffset(0)]
        public StrpathT path;
        [FieldOffset(0)]
        public Int32 strtype;
        [FieldOffset(0)]
        public EnumConstT ec;
        [FieldOffset(0)]
        public CustomDataTypeIdsT cd;

        [FieldOffset(0x1000)]
        public IntPtr UnmanagedPtr;

        public OpinfoT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            ri = new RefinfoT();
            tid = new TidT();
            path = new StrpathT();
            strtype = new Int32();
            ec = new EnumConstT();
            cd = new CustomDataTypeIdsT();
        }
    }

    public class StrucT
    {
        public StrucT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
        }

        public IntPtr UnmanagedPtr { get; set; }

        public TidT id => (TidT)MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x00);

        public UInt32 memqty => MarshalingUtils.GetUInt32(UnmanagedPtr, 0x08);

        IntPtr members => MarshalingUtils.GetIntPtr(UnmanagedPtr, 0x0C);

        public ushort age => MarshalingUtils.GetUShort(UnmanagedPtr, 0x14);

        public StructureFlags props
        {
            get => (StructureFlags)MarshalingUtils.GetUInt32(UnmanagedPtr, 0x16);
            set => MarshalingUtils.SetUInt32(UnmanagedPtr, 0xE, (UInt32)value);
        }

        Int32 ordinal
        {
            get => MarshalingUtils.GetInt32(UnmanagedPtr, 0x1A);
            set => MarshalingUtils.SetInt32(UnmanagedPtr, 0x1A, value);
        }

        public bool is_varstr()
        {
            return (props & StructureFlags.SF_VAR) != 0;
        }

        public bool is_union()
        {
            return (props & StructureFlags.SF_UNION) != 0;
        }

        public bool has_union()
        {
            return (props & StructureFlags.SF_HASUNI) != 0;
        }

        public bool like_union()
        {
            return is_union() || has_union();
        }

        public bool is_choosable()
        {
            return (props & StructureFlags.SF_NOLIST) == 0;
        }

        public bool from_til()
        {
            return (props & StructureFlags.SF_TYPLIB) != 0;
        }

        public bool is_hidden()
        {
            return (props & StructureFlags.SF_HIDDEN) != 0;
        }

        public bool is_frame()
        {
            return (props & StructureFlags.SF_FRAME) != 0;
        }

        public int get_alignment()
        {
            return ((int)(props & StructureFlags.SF_ALIGN) >> 7);
        }

        public bool is_ghost()
        {
            return (props & StructureFlags.SF_GHOST) != 0;
        }

        public bool is_synced()
        {
            return ordinal != -1 && !is_frame();
        }

        public bool is_mappedto()
        {
            return is_synced() && !is_ghost();
        }

        public bool is_copyof()
        {
            return is_synced() && is_ghost();
        }

        public void set_alignment(int shift)
        {
            props &= ~StructureFlags.SF_ALIGN;
            props |= ((StructureFlags)(shift << 7) & StructureFlags.SF_ALIGN);
        }

        public void set_ghost(bool _is_ghost)
        {
            StructureFlags prps = props;
            Globals.setflag(ref prps, StructureFlags.SF_GHOST, _is_ghost);
            props = prps;
        }

        public void unsync()
        {
            ordinal = -1;
        }

        public IntPtr get_last_member()
        {
            return memqty == 0 ? IntPtr.Zero : IntPtr.Zero; // members + memqty - 1;
        }
    }
}
