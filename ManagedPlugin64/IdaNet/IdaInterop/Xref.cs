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
using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    /// CODE xref types
    public enum CrefT
    {
        fl_U,                         ///< unknown -- for compatibility with old
                                      ///< versions. Should not be used anymore.
        fl_CF = 16,                   ///< Call Far
                                      ///< This xref creates a function at the
                                      ///< referenced location
        fl_CN,                        ///< Call Near
                                      ///< This xref creates a function at the
                                      ///< referenced location
        fl_JF,                        ///< Jump Far
        fl_JN,                        ///< Jump Near
        fl_USobsolete,                ///< User specified (obsolete)
        fl_F,                         ///< Ordinary flow: used to specify execution
                                      ///< flow to the next instruction.
    };

    /// DATA xref types
    public enum DrefT
    {
        dr_U,                         ///< Unknown -- for compatibility with old
                                      ///< versions. Should not be used anymore.
        dr_O,                         ///< Offset
                                      ///< The reference uses 'offset' of data
                                      ///< rather than its value
                                      ///<    OR
                                      ///< The reference appeared because the "OFFSET"
                                      ///< flag of instruction is set.
                                      ///< The meaning of this type is IDP dependent.
        dr_W,                         ///< Write access
        dr_R,                         ///< Read access
        dr_T,                         ///< Text (for forced operands only)
                                      ///< Name of data is used in manual operand
        dr_I,                         ///< Informational
                                      ///< (a derived java class references its base
                                      ///<  class informationally)
        dr_S,                         ///< Reference to enum member (symbolic constant)
    };

    public class XRefblkT
    {
        public IntPtr UnmanagedPtr { get; set; }

        internal const int XREF_ALL = 0x00;
        internal const int XREF_FAR = 0x01;
        internal const int XREF_DATA = 0x02;

        internal XRefblkT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
        }

        internal EaT From
        {
            get { return MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x00); }
            set { MarshalingUtils.SetEffectiveAddress(UnmanagedPtr, 0x00, value); }
        }

        internal EaT To
        {
            get { return MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x08); }
            set { MarshalingUtils.SetEffectiveAddress(UnmanagedPtr, 0x08, value); }
        }

        internal bool Iscode
        {
            get { return (0 != MarshalingUtils.GetByte(UnmanagedPtr, 0x10)); }
        }

        internal byte Type
        {
            get { return MarshalingUtils.GetByte(UnmanagedPtr, 0x11); }
        }

        internal bool User
        {
            get { return (0 != MarshalingUtils.GetByte(UnmanagedPtr, 0x12)); }
        }

        public bool FirstFrom(EaT _from, int flags)
        {
            return ida_xrefblk_t_first_from(UnmanagedPtr, _from, flags);
        }

        public bool NextFrom()
        {
            return ida_xrefblk_t_next_from(UnmanagedPtr);
        }

        public bool FirstTo(EaT _to, int flags)
        {
            return ida_xrefblk_t_first_to(UnmanagedPtr, _to, flags);
        }
        public bool NextTo()
        {
            return ida_xrefblk_t_next_to(UnmanagedPtr);
        }

        public bool NextFrom(EaT _from, EaT _to, int flags)
        {
            if (FirstFrom(_from, flags))
            {
                To = _to;
                return NextFrom();
            }

            return false;
        }

        public bool NextTo(EaT _from, EaT _to, int flags)
        {
            if (FirstTo(_to, flags))
            {
                From = _from;
                return NextTo();
            }

            return false;
        }
    }
}
