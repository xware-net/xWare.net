using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
    public class RegArgT
    {
        public IntPtr UnmanagedPtr;
        public int Reg
        {
            get => MarshalingUtils.GetInt32(UnmanagedPtr, 0x00);
            set => MarshalingUtils.SetInt32(UnmanagedPtr, 0x00, value);
        }
        public IntPtr TypePtr
        {
            get => MarshalingUtils.GetIntPtr(UnmanagedPtr, 0x08);
            set => MarshalingUtils.SetIntPtr(UnmanagedPtr, 0x08, value);
        }
        public byte Type { get; set; }
        public string Name { get; set; }

        public RegArgT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            Reg = MarshalingUtils.GetInt32(UnmanagedPtr, 0x00);
            TypePtr = MarshalingUtils.GetIntPtr(UnmanagedPtr, 0x08);
            Type = MarshalingUtils.GetByte(TypePtr, 0x00);
            Name = MarshalingUtils.GetString(UnmanagedPtr, 0x10);
        }

        public RegArgT(RegArgT other)
        {
            Reg = other.Reg;
            Type = other.Type;
            Name = new StringBuilder().Append(other.Name).ToString();
        }

        ~RegArgT()
        {
            FreeRegArgT();
        }

        public RegArgT Assign(RegArgT other)
        {
            if (this != other)
            {
                FreeRegArgT();
                Reg = other.Reg;
                Type = other.Type;
                Name = new StringBuilder().Append(other.Name).ToString();
            }
            return this;
        }

        public void Swap(RegArgT other)
        {
            (Reg, other.Reg) = (other.Reg, Reg);
            (Type, other.Type) = (other.Type, Type);
            (Name, other.Name) = (other.Name, Name);
        }

        private void FreeRegArgT()
        {
            Name = null;
        }

        public int CompareTo(RegArgT other)
        {
            // Implement comparison logic as needed
            if (Reg != other.Reg)
                return Reg.CompareTo(other.Reg);
            if (Type != other.Type)
                return Type.CompareTo(other.Type);
            return string.Compare(Name, other.Name);
        }

        public override bool Equals(object obj)
        {
            return obj is RegArgT other && Reg == other.Reg && Type == other.Type && Name == other.Name;
        }

        public override int GetHashCode()
        {
            return (Reg, Type, Name).GetHashCode();
        }
    }

    public class Func : RangeT
    {
        public UInt64 flags;

        UvalT frame;            ///< netnode id of frame structure - see frame.hpp
        AsizeT frsize;          ///< size of local variables part of frame in bytes.
                                ///< If #FUNC_FRAME is set and #fpd==0, the frame pointer
                                ///< (EBP) is assumed to point to the top of the local
                                ///< variables range.
        ushort frregs;          ///< size of saved registers in frame. This range is
                                ///< immediately above the local variables range.
        AsizeT argsize;         ///< number of bytes purged from the stack
                                ///< upon returning
        AsizeT fpd;             ///< frame pointer delta. (usually 0, i.e. realBP==typicalBP)
                                ///< use update_fpd() to modify it.

        BgcolorT color;         ///< user defined function color

        // the following fields should not be accessed directly:

        UInt32 pntqty;          ///< number of SP change points
        //stkpnt_t* points;     ///< array of SP change points.
        ///< use ...stkpnt...() functions to access this array.

        int regvarqty;          ///< number of register variables (-1-not read in yet)
                                ///< use find_regvar() to read register variables
        //regvar_t* regvars;    ///< array of register variables.
        ///< this array is sorted by: start_ea.
        ///< use ...regvar...() functions to access this array.

        int llabelqty;          ///< number of local labels
        //llabel_t* llabels;    ///< local labels.
        ///< this array shouldn't be accessed directly; name.hpp
        ///< functions should be used instead.

        int regargqty;          ///< number of register arguments.
                                ///< During analysis IDA tries to guess the register
                                ///< arguments. It stores store the guessing outcome
                                ///< in this field. As soon as it determines the final
                                ///< function prototype, regargqty is set to zero.
        //regarg_t* regargs;    ///< unsorted array of register arguments.
        ///< use ...regarg...() functions to access this array.
        ///< regargs are destroyed when the full function
        ///< type is determined.

        int tailqty;            ///< number of function tails
        //range_t* tails;       ///< array of tails, sorted by ea.
        ///< use func_tail_iterator_t to access function tails.

        public struct Entry
        {
            //
            // Stack frame of the function. It is represented as a structure:
            //
            //    +------------------------------------------------+
            //    | function arguments                             |
            //    +------------------------------------------------+
            //    | return address (isn't stored in func_t)        |
            //    +------------------------------------------------+
            //    | saved registers (SI, DI, etc - func_t::frregs) |
            //    +------------------------------------------------+ <- typical BP
            //    |                                                |  |
            //    |                                                |  | func_t::fpd
            //    |                                                |  |
            //    |                                                | <- real BP
            //    | local variables (func_t::frsize)               |
            //    |                                                |
            //    |                                                |
            //    +------------------------------------------------+ <- SP
            //
            UvalT frame;        ///< netnode id of frame structure - see frame.hpp
            AsizeT frsize;      ///< size of local variables part of frame in bytes.
                                ///< If #FUNC_FRAME is set and #fpd==0, the frame pointer
                                ///< (EBP) is assumed to point to the top of the local
                                ///< variables range.
            ushort frregs;       ///< size of saved registers in frame. This range is
                                 ///< immediately above the local variables range.
            AsizeT argsize;     ///< number of bytes purged from the stack
                                ///< upon returning
            AsizeT fpd;         ///< frame pointer delta. (usually 0, i.e. realBP==typicalBP)
                                ///< use update_fpd() to modify it.

            BgcolorT color;     ///< user defined function color

            // the following fields should not be accessed directly:

            UInt32 pntqty;       ///< number of SP change points
            //stkpnt_t* points;  ///< array of SP change points.
            ///< use ...stkpnt...() functions to access this array.

            int regvarqty;       ///< number of register variables (-1-not read in yet)
                                 ///< use find_regvar() to read register variables
            //regvar_t* regvars; ///< array of register variables.
            ///< this array is sorted by: start_ea.
            ///< use ...regvar...() functions to access this array.

            int llabelqty;       ///< number of local labels
            //llabel_t* llabels; ///< local labels.
            ///< this array shouldn't be accessed directly; name.hpp
            ///< functions should be used instead.

            int regargqty;       ///< number of register arguments.
                                 ///< During analysis IDA tries to guess the register
                                 ///< arguments. It stores store the guessing outcome
                                 ///< in this field. As soon as it determines the final
                                 ///< function prototype, regargqty is set to zero.
            //regarg_t* regargs; ///< unsorted array of register arguments.
            ///< use ...regarg...() functions to access this array.
            ///< regargs are destroyed when the full function
            ///< type is determined.

            int tailqty;         ///< number of function tails
            //range_t* tails;    ///< array of tails, sorted by ea.
            ///< use func_tail_iterator_t to access function tails.
        };

        public struct Tail
        {
            public EaT owner;          ///< the address of the main function possessing this tail
            public int refqty;          ///< number of referers
            //ea_t* referers;    ///< array of referers (function start addresses).
        };

        public Func(EaT start = 0, EaT end = 0, FlagsT f = 0)
        {
            start_ea = start;
            end_ea = end;
            flags = f | (uint)FunctionFlags.FUNC_NORET_PENDING;
            //frame = BADNODE;
            frsize = 0;
            frregs = 0;
            argsize = 0;
            fpd = 0;
            color = 0xffffffff;
            pntqty = 0;
            // points = null;
            regvarqty = 0;
            // regvars = null;
            llabelqty = 0;
            // llabels = null;
            regargqty = 0;
            // regargs = null
            tailqty = 0;
            // tails = null;

        }

        public Func(IntPtr funcPtr)
        {
            UnmanagedPtr = funcPtr;
            IntPtr nativeBuffer = IntPtr.Zero;

            start_ea = ida_get_func_start_ea(funcPtr);
            end_ea = ida_get_func_end_ea(funcPtr);
            flags = ida_get_func_flags(funcPtr);
            frame = MarshalingUtils.GetUInt64(funcPtr, 0x18);
            //owner = MarshalingUtils.GetEffectiveAddress(funcPtr, 0x20);
            //frsize = ;
            //frregs = ;
            //argsize = ;
            //fpd = ;
            //color = ;
            //pntqty = ;
            // points = ;
            //regvarqty = ;
            // regvars = ;
            //llabelqty = ;
            // llabels = ;
            //regargqty = ;
            // regargs = ;
            //tailqty = ;
            // tails = ;
        }

        public IntPtr UnmanagedPtr { get; set; }

        public AsizeT size()
        {
            return ida_get_func_size(UnmanagedPtr);
        }

        public bool is_far()
        {
            return (flags & (UInt64)FunctionFlags.FUNC_FAR) != 0;
        }

        public bool does_return()
        {
            return (flags & (UInt64)FunctionFlags.FUNC_NORET) == 0;
        }

        public bool analyzed_sp()
        {
            return (flags & (UInt64)FunctionFlags.FUNC_SP_READY) != 0;
        }

        public bool need_prolog_analysis()
        {
            return (flags & (UInt64)FunctionFlags.FUNC_PROLOG_OK) == 0;
        }

        //public static void AddFunc(ea_t ea1, ea_t ea2 = 0xffffffffffffffff)
        //{
        //    var f = new func_t(ea1, ea2);
        //    IntPtr ptr = Marshal.AllocHGlobal((int)IdaPlusPlus.IdaInterop.ida_func_t_size());
        //    IdaPlusPlus.IdaInterop.ida_add_func_ex(ptr);
        //    Marshal.FreeHGlobal(ptr);
        //}

        //public static func_t ToManaged(IntPtr ptr)
        //{
        //    func_t f = new func_t();

        //    f.start_ea = IdaPlusPlus.IdaInterop.ida_get_func_start_ea(ptr);
        //    return f;
        //}
    }

    public class FuncParentIteratorT
    {
        public IntPtr UnmanagedPtr;
        private IntPtr fnt;
        private int idx;

        // Default constructor
        public FuncParentIteratorT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            fnt = IntPtr.Zero;
            idx = 0;
        }

        // Constructor with IntPtr argument
        public FuncParentIteratorT(IntPtr ptr, IntPtr _fnt)
        {
            UnmanagedPtr = ptr;
            fnt = IntPtr.Zero;
            Set(_fnt);
        }

        // Destructor
        ~FuncParentIteratorT()
        {
            if (fnt != IntPtr.Zero)
            {
                LockFuncRange(fnt, false);
            }
        }

        // Set function
        public bool Set(IntPtr _fnt)
        {
            return FuncParentIteratorSet(this, _fnt);
        }

        // Parent function
        public ulong Parent()
        {
            return GetRefererAtIndex(fnt, idx);
        }

        // First function
        public bool First()
        {
            idx = 0;
            return ida_is_func_tail(fnt) && GetRefQty(fnt) > 0;
        }

        // Last function
        public bool Last()
        {
            idx = GetRefQty(fnt) - 1;
            return idx >= 0;
        }

        // Next function
        public bool Next()
        {
            if (idx + 1 < GetRefQty(fnt))
            {
                idx++;
                return true;
            }
            return false;
        }

        // Previous function
        public bool Prev()
        {
            if (idx > 0)
            {
                idx--;
                return true;
            }
            return false;
        }

        // Reset function (for internal use)
        public void ResetFnt(IntPtr _fnt)
        {
            fnt = _fnt;
        }

        // Mock functions (implement these as needed)
        private bool FuncParentIteratorSet(FuncParentIteratorT iterator, IntPtr _fnt)
        {
            // Implementation of setting func_t in the iterator
            // Replace this mock function with actual code.
            return true;
        }

        private void LockFuncRange(IntPtr _fnt, bool lockState)
        {
            ida_lock_func_range(_fnt, lockState);
        }

        private bool IsFuncTail(IntPtr _fnt)
        {
            return ida_is_func_tail(_fnt);
        }

        private int GetRefQty(IntPtr _fnt)
        {
            if (ida_is_func_tail(_fnt))
            {
                return ida_get_tail_refqty(_fnt);
            }
            else
            {
                return 0;
            }
        }

        private ulong GetRefererAtIndex(IntPtr _fnt, int index)
        {
            // Return the referer at the given index.
            // Replace this mock function with actual code.
            return 0xDEADBEEF; // Placeholder value
        }
    }
}