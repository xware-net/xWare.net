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
using System.Drawing;
using System.Collections;

namespace IdaNet.IdaInterop
{
    public enum FunctionFlags : UInt64
    {
        FUNC_NORET = 0x00000001,     ///< Function doesn't return
        FUNC_FAR = 0x00000002,     ///< Far function
        FUNC_LIB = 0x00000004,     ///< Library function

        FUNC_STATICDEF = 0x00000008,     ///< Static function

        FUNC_FRAME = 0x00000010,     ///< Function uses frame pointer (BP)
        FUNC_USERFAR = 0x00000020,     ///< User has specified far-ness
                                       ///< of the function
        FUNC_HIDDEN = 0x00000040,     ///< A hidden function chunk
        FUNC_THUNK = 0x00000080,     ///< Thunk (jump) function
        FUNC_BOTTOMBP = 0x00000100,     ///< BP points to the bottom of the stack frame
        FUNC_NORET_PENDING = 0x00200,     ///< Function 'non-return' analysis must be performed.
                                          ///< This flag is verified upon func_does_return()
        FUNC_SP_READY = 0x00000400,     ///< SP-analysis has been performed.
                                        ///< If this flag is on, the stack
                                        ///< change points should not be not
                                        ///< modified anymore. Currently this
                                        ///< analysis is performed only for PC
        FUNC_FUZZY_SP = 0x00000800,     ///< Function changes SP in untraceable way,
                                        ///< for example: and esp, 0FFFFFFF0h
        FUNC_PROLOG_OK = 0x00001000,     ///< Prolog analysis has be performed
                                         ///< by last SP-analysis
        FUNC_PURGED_OK = 0x00004000,     ///< 'argsize' field has been validated.
                                         ///< If this bit is clear and 'argsize'
                                         ///< is 0, then we do not known the real
                                         ///< number of bytes removed from
                                         ///< the stack. This bit is handled
                                         ///< by the processor module.
        FUNC_TAIL = 0x00008000,     ///< This is a function tail.
                                    ///< Other bits must be clear
                                    ///< (except #FUNC_HIDDEN).
        FUNC_LUMINA = 0x00010000,     ///< Function info is provided by Lumina.

        FUNC_RESERVED = 0x8000000000000000, ///< Reserved (for internal usage)
    }

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
        public const ulong BADNODE = ulong.MaxValue;     // Placeholder for BADNODE
        public const uint DefaultColor = 0xFFFFFFFF;     // Placeholder for DEFCOLOR

        public UInt64 Flags;
        public FrameStruct FrameInfo { get; set; }
        public TailStruct TailInfo { get; set; }

        public struct FrameStruct
        {
            public UvalT Frame;        // netnode id of frame structure
            public AsizeT FrSize;       // size of local variables part of frame in bytes
            public ushort FrRegs;      // size of saved registers in frame
            public AsizeT ArgSize;      // number of bytes purged from the stack
            public AsizeT Fpd;          // frame pointer delta
            public BgcolorT Color;         // user-defined function color

            public UInt32 PntQty;        // number of SP change points
            public IntPtr Points;      // array of SP change points
            public int RegVarQty;      // number of register variables
            public IntPtr RegVars;     // array of register variables
            public int LLabelQty;      // number of local labels
            public IntPtr LLabels;     // array of local labels
            public int RegArgQty;      // number of register arguments
            public IntPtr RegArgs;     // array of register arguments
            public int TailQty;        // number of function tails
            public IntPtr Tails;       // array of tails
        };

        public struct TailStruct
        {
            public EaT Owner;           // the address of the main function possessing this tail
            public int RefQty;          // number of referers
            public IntPtr Referers;     // array of referers (function start addresses)
        };

        public Func(EaT start = 0, EaT end = 0, FlagsT f = 0)
        {
            StartEa = start;
            EndEa = end;
            Flags = f | (uint)FunctionFlags.FUNC_NORET_PENDING;

            FrameInfo = new FrameStruct
            {
                Frame = BADNODE,
                FrSize = 0,
                FrRegs = 0,
                ArgSize = 0,
                Fpd = 0,
                Color = DefaultColor,
                PntQty = 0,
                Points = IntPtr.Zero,
                RegVarQty = 0,
                RegVars = IntPtr.Zero,
                LLabelQty = 0,
                LLabels = IntPtr.Zero,
                RegArgQty = 0,
                RegArgs = IntPtr.Zero,
                TailQty = 0,
                Tails = IntPtr.Zero
            };

            TailInfo = new TailStruct
            {
                Owner = start,
                RefQty = 0,
                Referers = IntPtr.Zero
            };
        }

        public Func(IntPtr funcPtr)
        {
            UnmanagedPtr = funcPtr;
            IntPtr nativeBuffer = IntPtr.Zero;

            StartEa = ida_get_func_start_ea(funcPtr);
            EndEa = ida_get_func_end_ea(funcPtr);
            Flags = ida_get_func_flags(funcPtr);
            FrameInfo = new FrameStruct
            {
                Frame = MarshalingUtils.GetUInt64(funcPtr, 0x18),
                FrSize = 0,
                FrRegs = 0,
                ArgSize = 0,
                Fpd = 0,
                Color = DefaultColor,
                PntQty = 0,
                Points = IntPtr.Zero,
                RegVarQty = 0,
                RegVars = IntPtr.Zero,
                LLabelQty = 0,
                LLabels = IntPtr.Zero,
                RegArgQty = 0,
                RegArgs = IntPtr.Zero,
                TailQty = 0,
                Tails = IntPtr.Zero
            };

            TailInfo = new TailStruct
            {
                Owner = MarshalingUtils.GetEffectiveAddress(funcPtr, 0x20),
                RefQty = 0,
                Referers = IntPtr.Zero
            };
        }

        public IntPtr UnmanagedPtr { get; set; }

        public AsizeT size()
        {
            return ida_get_func_size(UnmanagedPtr);
        }

        public bool IsFar()
        {
            return (Flags & (UInt64)FunctionFlags.FUNC_FAR) != 0;
        }

        public bool DoesReturn()
        {
            return (Flags & (UInt64)FunctionFlags.FUNC_NORET) == 0;
        }

        public bool AnalyzedSp()
        {
            return (Flags & (UInt64)FunctionFlags.FUNC_SP_READY) != 0;
        }

        public bool NeedPrologAnalysis()
        {
            return (Flags & (UInt64)FunctionFlags.FUNC_PROLOG_OK) == 0;
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

    public class LockFunc : IDisposable
    {
        private IntPtr pfn; // Pointer to func_t

        // Constructor
        public LockFunc(IntPtr _pfn)
        {
            pfn = _pfn;
            LockFuncRange(pfn, true);
        }

        // Destructor (called when the object is garbage collected or disposed)
        ~LockFunc()
        {
            Dispose(false);
        }

        // Dispose method to support explicit disposal (e.g. using block)
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // Helper method for resource cleanup
        protected virtual void Dispose(bool disposing)
        {
            if (pfn != IntPtr.Zero)
            {
                LockFuncRange(pfn, false);
                pfn = IntPtr.Zero;
            }
        }

        // Placeholder for lock_func_range function
        private void LockFuncRange(IntPtr func, bool lockRange)
        {
            // Implement the locking mechanism based on your requirements
        }
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

    public class FuncTailIteratorT : IDisposable
    {
        private IntPtr pfn; // Pointer to func_t
        private int idx;
        private RangeT seglim; // valid and used only if pfn == IntPtr.Zero

        // Constructor
        public FuncTailIteratorT()
        {
            pfn = IntPtr.Zero;
            idx = -1;
        }

        // Overloaded Constructor
        public FuncTailIteratorT(IntPtr _pfn, ulong ea = BADADDR)
        {
            pfn = IntPtr.Zero;
            Set(_pfn, ea);
        }

        // Destructor
        ~FuncTailIteratorT()
        {
            Dispose(false);
        }

        // Dispose method for manual resource management
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // Dispose pattern helper
        protected virtual void Dispose(bool disposing)
        {
            if (pfn != IntPtr.Zero)
            {
                LockFuncRange(pfn, false);
                pfn = IntPtr.Zero;
            }
        }

        // Set function
        public bool Set(IntPtr _pfn, ulong ea = BADADDR)
        {
            return FuncTailIteratorSet(this, _pfn, ea);
        }

        // Set EA (effective address)
        public bool SetEa(ulong ea)
        {
            return FuncTailIteratorSetEa(this, ea);
        }

        // Set an arbitrary range
        public bool SetRange(ulong ea1, ulong ea2)
        {
            Dispose();
            pfn = IntPtr.Zero;
            idx = -1;
            seglim = new RangeT(ea1, ea2);
            return !seglim.IsEmpty();
        }

        // Return the current chunk (range)
        public RangeT Chunk
        {
            get
            {
                if (pfn == IntPtr.Zero)
                    return seglim;

                return (idx >= 0 && idx < GetTailQty()) ? GetTail(idx) : GetRange(pfn);
            }
        }

        // Methods for navigating chunks
        public bool First()
        {
            if (pfn != IntPtr.Zero)
            {
                idx = 0;
                return GetTailQty() > 0;
            }
            return false;
        }

        public bool Last()
        {
            if (pfn != IntPtr.Zero)
            {
                idx = GetTailQty() - 1;
                return true;
            }
            return false;
        }

        public bool Next()
        {
            if (pfn != IntPtr.Zero && idx + 1 < GetTailQty())
            {
                idx++;
                return true;
            }
            return false;
        }

        public bool Prev()
        {
            if (idx >= 0)
            {
                idx--;
                return true;
            }
            return false;
        }

        public bool Main()
        {
            idx = -1;
            return pfn != IntPtr.Zero;
        }

        // Placeholder for tail quantity retrieval (assumes func_t has this information)
        private int GetTailQty()
        {
            // Implementation to retrieve tail quantity from pfn
            return 0; // Replace with actual implementation
        }

        // Placeholder for retrieving a tail at a given index
        private RangeT GetTail(int index)
        {
            // Implementation to retrieve tail from pfn
            return new RangeT(); // Replace with actual implementation
        }

        // Placeholder for range_t equivalent in func_t
        private RangeT GetRange(IntPtr func)
        {
            // Implementation to retrieve range from pfn
            return new RangeT(); // Replace with actual implementation
        }

        // Placeholder for lock_func_range
        private void LockFuncRange(IntPtr func, bool lockRange)
        {
            // Implement the locking mechanism
        }

        // Placeholder for external functions
        private bool FuncTailIteratorSet(FuncTailIteratorT iterator, IntPtr _pfn, ulong ea)
        {
            // Implement logic for setting func_t and ea
            return true; // Replace with actual implementation
        }

        private bool FuncTailIteratorSetEa(FuncTailIteratorT iterator, ulong ea)
        {
            // Implement logic for setting ea
            return true; // Replace with actual implementation
        }

        // Constants
        private const ulong BADADDR = 0xFFFFFFFFFFFFFFFF;
    }

    public class FuncItemIteratorT
    {
        private FuncTailIteratorT fti;
        private ulong ea;

        public FuncItemIteratorT()
        {
            ea = BADADDR;
        }

        public FuncItemIteratorT(IntPtr pfn, ulong _ea = BADADDR)
        {
            Set(pfn, _ea);
        }

        /// Set a function range. If pfn == null then a segment range will be set.
        public bool Set(IntPtr pfn, ulong _ea = BADADDR)
        {
            ea = (_ea != BADADDR || pfn == IntPtr.Zero) ? _ea : GetStartEA(pfn);
            return fti.Set(pfn, _ea);
        }

        /// Set an arbitrary range
        public bool SetRange(ulong ea1, ulong ea2)
        {
            ea = ea1;
            return fti.SetRange(ea1, ea2);
        }

        public bool First()
        {
            if (!fti.Main())
                return false;

            ea = fti.Chunk.StartEa;
            return true;
        }

        public bool Last()
        {
            if (!fti.Last())
                return false;

            ea = fti.Chunk.EndEa;
            return true;
        }

        public ulong Current()
        {
            return ea;
        }

        public RangeT Chunk()
        {
            return fti.Chunk;
        }

        public bool Next(TestfDelegate func, IntPtr ud)
        {
            return FuncItemIteratorNext(this, func, ud);
        }

        public bool Prev(TestfDelegate func, IntPtr ud)
        {
            return FuncItemIteratorPrev(this, func, ud);
        }

        public bool NextAddr()
        {
            return Next(FAny, IntPtr.Zero);
        }

        public bool NextHead()
        {
            return Next(FIsHead, IntPtr.Zero);
        }

        public bool NextCode()
        {
            return Next(FIsCode, IntPtr.Zero);
        }

        public bool NextData()
        {
            return Next(FIsData, IntPtr.Zero);
        }

        public bool NextNotTail()
        {
            return Next(FIsNotTail, IntPtr.Zero);
        }

        public bool PrevAddr()
        {
            return Prev(FAny, IntPtr.Zero);
        }

        public bool PrevHead()
        {
            return Prev(FIsHead, IntPtr.Zero);
        }

        public bool PrevCode()
        {
            return Prev(FIsCode, IntPtr.Zero);
        }

        public bool PrevData()
        {
            return Prev(FIsData, IntPtr.Zero);
        }

        public bool PrevNotTail()
        {
            return Prev(FIsNotTail, IntPtr.Zero);
        }

        public bool DecodePrevInsn(IntPtr outInsn)
        {
            return FuncItemIteratorDecodePrevInsn(this, outInsn);
        }

        public bool DecodePrecedingInsn(IntPtr visited, IntPtr pFarRef, IntPtr outInsn)
        {
            return FuncItemIteratorDecodePrecedingInsn(this, visited, pFarRef, outInsn);
        }

        public bool Succ(TestfDelegate func, IntPtr ud)
        {
            return FuncItemIteratorSucc(this, func, ud);
        }

        public bool SuccCode()
        {
            return Succ(FIsCode, IntPtr.Zero);
        }

        // Delegate type for test functions
        public delegate bool TestfDelegate(IntPtr func, IntPtr ud);

        // Placeholder for external functions
        private bool FuncItemIteratorNext(FuncItemIteratorT iterator, TestfDelegate func, IntPtr ud)
        {
            // Implement logic to handle "next" iteration
            return true; // Replace with actual implementation
        }

        private bool FuncItemIteratorPrev(FuncItemIteratorT iterator, TestfDelegate func, IntPtr ud)
        {
            // Implement logic to handle "prev" iteration
            return true; // Replace with actual implementation
        }

        private bool FuncItemIteratorDecodePrevInsn(FuncItemIteratorT iterator, IntPtr outInsn)
        {
            // Implement logic for decoding previous instruction
            return true; // Replace with actual implementation
        }

        private bool FuncItemIteratorDecodePrecedingInsn(FuncItemIteratorT iterator, IntPtr visited, IntPtr pFarRef, IntPtr outInsn)
        {
            // Implement logic for decoding preceding instruction
            return true; // Replace with actual implementation
        }

        private bool FuncItemIteratorSucc(FuncItemIteratorT iterator, TestfDelegate func, IntPtr ud)
        {
            // Implement logic for successive iteration
            return true; // Replace with actual implementation
        }

        private EaT GetStartEA(IntPtr pfn)
        {
            // Implement logic to retrieve start_ea from func_t
            return 0; // Replace with actual implementation
        }

        // Delegate stubs for test functions
        private bool FAny(IntPtr func, IntPtr ud) { return true; }
        private bool FIsHead(IntPtr func, IntPtr ud) { return true; }
        private bool FIsCode(IntPtr func, IntPtr ud) { return true; }
        private bool FIsData(IntPtr func, IntPtr ud) { return true; }
        private bool FIsNotTail(IntPtr func, IntPtr ud) { return true; }

        // Constants
        private const ulong BADADDR = 0xFFFFFFFFFFFFFFFF;
    }
}