using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using EaT = System.UInt64;
using SelT = System.UInt64;
using SizeT = System.UInt64;
using AsizeT = System.UInt64;
using AdiffT = System.Int64;
using UvalT = System.UInt64;
using BgcolorT = System.UInt32;

using static IdaPlusPlus.IdaInterop;
using System.Security.Cryptography;

namespace IdaNet.IdaInterop
{
    public class RangeT : IEquatable<RangeT>
    {
        public IntPtr UnmanagedPtr;
        public EaT StartEa;
        public EaT EndEa;

        public RangeT()
        {
            UnmanagedPtr = IntPtr.Zero;
            this.StartEa = 0;
            this.EndEa = 0;
        }

        public RangeT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            this.StartEa = 0;
            this.EndEa = 0;
        }

        public RangeT(EaT ea1, EaT ea2)
        {
            UnmanagedPtr = IntPtr.Zero;
            this.StartEa = ea1;
            this.EndEa = ea2;
        }

        public RangeT(IntPtr ptr, EaT ea1, EaT ea2)
        {
            UnmanagedPtr = ptr;
            this.StartEa = ea1;
            this.EndEa = ea2;
        }

        public int Compare(in RangeT r)
        {
            return StartEa > r.StartEa ? 1 : StartEa < r.StartEa ? -1 : 0;
        }

        public static bool operator ==(RangeT ImpliedObject, in RangeT r)
        {
            return ImpliedObject.Compare(r) == 0;
        }

        public static bool operator !=(RangeT ImpliedObject, in RangeT r)
        {
            return ImpliedObject.Compare(r) != 0;
        }

        public static bool operator >(RangeT ImpliedObject, in RangeT r)
        {
            return ImpliedObject.Compare(r) > 0;
        }

        public static bool operator <(RangeT ImpliedObject, in RangeT r)
        {
            return ImpliedObject.Compare(r) < 0;
        }

        public bool Contains(EaT ea)
        {
            return StartEa <= ea && EndEa > ea;
        }

        public bool Contains(in RangeT r)
        {
            return r.StartEa >= StartEa && r.EndEa <= EndEa;
        }

        public bool Overlaps(in RangeT r)
        {
            return r.StartEa < EndEa && StartEa < r.EndEa;
        }

        public void Clear()
        {
            StartEa = EndEa = 0;
        }

        public bool IsEmpty()
        {
            return StartEa >= EndEa;
        }

        public AsizeT Size()
        {
            return EndEa - StartEa;
        }

        public void Intersect(in RangeT r)
        {
            if (StartEa < r.StartEa)
            {
                StartEa = r.StartEa;
            }
            if (EndEa > r.EndEa)
            {
                EndEa = r.EndEa;
            }
            if (EndEa < StartEa)
            {
                EndEa = StartEa;
            }
        }

        public void Extend(EaT ea)
        {
            if (StartEa > ea)
            {
                StartEa = ea;
            }
            if (EndEa < ea)
            {
                EndEa = ea;
            }
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as RangeT);
        }

        public bool Equals(RangeT other)
        {
            return other != null &&
                   StartEa == other.StartEa &&
                   EndEa == other.EndEa;
        }

        public override int GetHashCode() => (StartEa, EndEa).GetHashCode();

        public SizeT Print(IntPtr buf, SizeT bufsize)
        {
            return ida_range_t_print(UnmanagedPtr, buf, bufsize);
        }

        public override string ToString()
        {
            return string.Format($"(0x{StartEa:X16} - 0x{EndEa:X16})");
        }
    }

    public class RangevecT : QVector<RangeT>
    {
    }

    public enum RangeKindT
    {
        RANGE_KIND_UNKNOWN,
        RANGE_KIND_FUNC,
        RANGE_KIND_SEGMENT,
        RANGE_KIND_HIDDEN_RANGE,
    }

    public class RangesetT : IEquatable<RangesetT>
    {
        public IntPtr UnmanagedPtr;

        private List<RangeT> bag;
        private RangeT cache;
        private int undoCode = -1;

        public RangesetT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            bag = new List<RangeT>();
            cache = null;
        }

        public RangesetT(IntPtr ptr, RangeT range)
        {
            UnmanagedPtr = ptr;
            bag = new List<RangeT>();
            cache = null;
            if (!range.IsEmpty())
            {
                bag.Add(range);
            }
        }

        public RangesetT(IntPtr ptr, RangesetT other)
        {
            UnmanagedPtr = ptr;
            bag = new List<RangeT>(other.bag);
            cache = null;
        }

        public RangesetT Assign(RangesetT other)
        {
            bag = new List<RangeT>(other.bag);
            cache = null;
            return this;
        }

        public void Swap(ref RangesetT other)
        {
            var temp = this.bag;
            this.bag = other.bag;
            other.bag = temp;

            var tempCache = this.cache;
            this.cache = other.cache;
            other.cache = tempCache;
        }

        public bool Add(RangeT range)
        {
            if (range.IsEmpty())
                return false;

            var rangePtr = Marshal.AllocHGlobal(Marshal.SizeOf<RangeT>());
            Marshal.StructureToPtr(range, rangePtr, false);
            var ret = ida_rangeset_t_add(UnmanagedPtr, rangePtr);
            Marshal.FreeHGlobal(rangePtr);
            return ret;
        }

        public bool Add(ulong start, ulong end)
        {
            return Add(new RangeT(start, end));
        }

        public bool Add(RangesetT other)
        {
            return ida_rangeset_t_add2(UnmanagedPtr, other.UnmanagedPtr);
        }

        public bool Subtract(RangeT range)
        {
            var rangePtr = Marshal.AllocHGlobal(Marshal.SizeOf<RangeT>());
            Marshal.StructureToPtr(range, rangePtr, false);
            var ret = ida_rangeset_t_sub(UnmanagedPtr, rangePtr);
            Marshal.FreeHGlobal(rangePtr);
            return ret;
        }

        public bool Subtract(EaT address)
        {
            return Subtract(new RangeT(address, address + 1));
        }

        public bool Subtract(RangesetT other)
        {
            return ida_rangeset_t_sub2(UnmanagedPtr, other.UnmanagedPtr);
        }

        public bool HasCommon(RangeT range)
        {
            var rangePtr = Marshal.AllocHGlobal(Marshal.SizeOf<RangeT>());
            Marshal.StructureToPtr(range, rangePtr, false);
            var ret = ida_rangeset_t_has_common(UnmanagedPtr, rangePtr, false);
            Marshal.FreeHGlobal(rangePtr);
            return ret;
        }

        public bool Includes(RangeT range)
        {
            var rangePtr = Marshal.AllocHGlobal(Marshal.SizeOf<RangeT>());
            Marshal.StructureToPtr(range, rangePtr, false);
            var ret = ida_rangeset_t_has_common(UnmanagedPtr, rangePtr, true);
            Marshal.FreeHGlobal(rangePtr);
            return ret;
        }

        public SizeT Print(IntPtr buf, SizeT bufsize)
        {
            return ida_rangeset_t_print(UnmanagedPtr, buf, bufsize);
        }

        public AsizeT Count()
        {
            // Assuming counting size of all ranges
            return 0;  // Implement actual logic
        }

        public RangeT GetRange(int index)
        {
            return bag[index];
        }

        public RangeT LastRange()
        {
            return bag[^1];
        }

        public int NumberOfRanges()
        {
            return bag.Count;
        }

        public bool IsEmpty()
        {
            return bag.Count == 0;
        }

        public void Clear()
        {
            bag.Clear();
            cache = null;
        }

        public bool Contains(EaT ea)
        {
            return !IsEmpty() && FindRange(ea) != null;
        }

        public bool Contains(RangesetT other)
        {
            return ida_rangeset_t_contains(UnmanagedPtr, other.UnmanagedPtr);
        }

        public bool Intersect(RangesetT other)
        {
            return ida_rangeset_t_intersect(UnmanagedPtr, other.UnmanagedPtr);
        }

        public bool IsSubsetOf(RangesetT other)
        {
            return other.Contains(this);
        }

        public bool IsEqual(RangesetT other)
        {
            return bag.Equals(other.bag);
        }

        public static bool operator ==(RangesetT a, RangesetT b)
        {
            return a.IsEqual(b);
        }

        public static bool operator !=(RangesetT a, RangesetT b)
        {
            return !a.IsEqual(b);
        }

        public RangeT FindRange(EaT ea)
        {
            return Marshal.PtrToStructure<RangeT>(ida_rangeset_t_find_range(UnmanagedPtr, ea));
        }

        public RangeT CachedRange()
        {
            return cache;
        }

        public EaT NextAddress(EaT ea)
        {
            return ida_rangeset_t_next_addr(UnmanagedPtr, ea);
        }

        public EaT PreviousAddress(EaT ea)
        {
            return ida_rangeset_t_prev_addr(UnmanagedPtr, ea);
        }

        public EaT NextRange(EaT ea)
        {
            return ida_rangeset_t_next_range(UnmanagedPtr, ea);
        }

        public EaT PreviousRange(EaT ea)
        {
            return ida_rangeset_t_prev_range(UnmanagedPtr, ea);
        }

        public int MoveChunk(ulong from, ulong to, ulong size)
        {
            // Handle move logic
            return 0;
        }

        public int CheckMoveArgs(ulong from, ulong to, ulong size)
        {
            // Validation logic
            return 0;
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as RangesetT);
        }

        public bool Equals(RangesetT other)
        {
            return other != null 
                && bag == other.bag 
                && cache == other.cache
                && undoCode == other.undoCode;
        }

        public override int GetHashCode() => (bag, cache, undoCode).GetHashCode();
    }
}
