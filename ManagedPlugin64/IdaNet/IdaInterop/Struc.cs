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

    public class MemberT
    {
        public IntPtr UnmanagedPtr { get; set; }

        public MemberT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
        }
    }

    public unsafe struct StrpathT
    {
        int len;
        fixed tid_t ids[32]; // for union member ids
        adiff_t delta;
    }

    public struct EnumConstT
    {
        tid_t tid;
        byte serial;
    }

    public struct CustomDataTypeIdsT
    {
    }

    public struct RefinfoT
    {
        public ea_t target;
        public ea_t basr;
        public adiff_t tdelta;
        public UInt32 flags;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct OpinfoT
    {
        [FieldOffset(0)]
        public RefinfoT ri;
        [FieldOffset(0)]
        public tid_t tid;
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
            tid = new tid_t();
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

        public tid_t id => (tid_t)MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x00);

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
