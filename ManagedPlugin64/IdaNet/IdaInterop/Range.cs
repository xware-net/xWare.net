using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using EaT = System.UInt64;
using SelT = System.UInt64;
using SizeT = System.UInt64;
using AsizeT = System.UInt64;
using AdiffT = System.Int64;
using UvalT = System.UInt64;
using BgcolorT = System.UInt32;

namespace IdaNet.IdaInterop
{
	public class RangeT : IEquatable<RangeT>
    {
		public EaT start_ea;
		public EaT end_ea;

		public RangeT()
		{
			this.start_ea = 0;
			this.end_ea = 0;
		}

		public RangeT(EaT ea1, EaT ea2)
		{
			this.start_ea = ea1;
			this.end_ea = ea2;
		}

		public int Compare(in RangeT r)
		{
			return start_ea > r.start_ea ? 1 : start_ea < r.start_ea ? -1 : 0;
		}

        public static bool operator ==(RangeT ImpliedObject, in RangeT r)
        {
            return ImpliedObject.Compare(r) == 0;
        }

        public static bool operator !=(RangeT ImpliedObject, in RangeT r)
        {
            return ImpliedObject.Compare(r) != 0;
        }

        //public static bool operator >(Range ImpliedObject, in Range r)
        //{
        //	return ImpliedObject.Compare(r) > 0;
        //}

        //public static bool operator <(Range ImpliedObject, in Range r)
        //{
        //	return ImpliedObject.Compare(r) < 0;
        //}

        public bool Contains(EaT ea)
		{
			return start_ea <= ea && end_ea > ea;
		}

		public bool Contains(in RangeT r)
		{
			return r.start_ea >= start_ea && r.end_ea <= end_ea;
		}

		public bool Overlaps(in RangeT r)
		{
			return r.start_ea < end_ea && start_ea < r.end_ea;
		}

		public void Clear()
		{
			start_ea = end_ea = 0;
		}

		public bool Empty()
		{
			return start_ea >= end_ea;
		}

		public AsizeT Size()
		{
			return end_ea - start_ea;
		}

		public void Intersect(in RangeT r)
		{
			if (start_ea < r.start_ea)
			{
				start_ea = r.start_ea;
			}
			if (end_ea > r.end_ea)
			{
				end_ea = r.end_ea;
			}
			if (end_ea < start_ea)
			{
				end_ea = start_ea;
			}
		}

		public void Extend(EaT ea)
		{
			if (start_ea > ea)
			{
				start_ea = ea;
			}
			if (end_ea < ea)
			{
				end_ea = ea;
			}
		}

        public override bool Equals(object obj)
        {
            return Equals(obj as RangeT);
        }

        public bool Equals(RangeT other)
        {
            return other != null &&
                   start_ea == other.start_ea &&
                   end_ea == other.end_ea;
        }

        public override int GetHashCode()
        {
            int hashCode = 662085783;
            hashCode = hashCode * -1521134295 + start_ea.GetHashCode();
            hashCode = hashCode * -1521134295 + end_ea.GetHashCode();
            return hashCode;
        }

		/// Print the Range.
		/// \param buf the output buffer
		/// \param bufsize the size of the buffer
		//public size_t print(ref string buf, size_t bufsize)
		//{
		//	return new ida_export(range_t_print(this, ref buf, new size_t(bufsize)));
		//}

		public override string ToString()
		{
			return string.Format($"(0x{start_ea:X16} - 0x{end_ea:X16})");
		}
    }

    public class RangevecT : List<RangeT>
	{
    }

    public enum RangeKindT
	{
		RANGE_KIND_UNKNOWN,
		RANGE_KIND_FUNC,			
		RANGE_KIND_SEGMENT,			
		RANGE_KIND_HIDDEN_RANGE		
	}

    public class RangeSetT 
    {
    }
}
