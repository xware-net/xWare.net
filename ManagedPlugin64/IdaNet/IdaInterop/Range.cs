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
		public EaT StartEa;
		public EaT EndEa;

		public RangeT()
		{
			this.StartEa = 0;
			this.EndEa = 0;
		}

		public RangeT(EaT ea1, EaT ea2)
		{
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

        public override int GetHashCode()
        {
            int hashCode = 662085783;
            hashCode = hashCode * -1521134295 + StartEa.GetHashCode();
            hashCode = hashCode * -1521134295 + EndEa.GetHashCode();
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
			return string.Format($"(0x{StartEa:X16} - 0x{EndEa:X16})");
		}
    }

    public class RangevecT : List<RangeT>
	{
        public bool Empty()
        {
            return base.Count == 0;
        }

        public void Qclear()
        {
            base.Clear();
        }
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
