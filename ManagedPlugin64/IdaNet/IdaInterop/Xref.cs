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

        internal const int XREF_ALL = 0x00; // return all references
        internal const int XREF_FAR = 0x01; // don't return ordinary flow xrefs
        internal const int XREF_DATA = 0x02; // return data references only

        internal XRefblkT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
        }

        // must have setters/getters

        internal ea_t from              ///< the referencing address - filled by first_to(),next_to()
        {
            get { return MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x00); }
            private set { MarshalingUtils.SetEffectiveAddress(UnmanagedPtr, 0x00, value); }
        }

        internal ea_t to                ///< the referenced address - filled by first_from(), next_from()
        {
            get { return MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x08); }
            private set { MarshalingUtils.SetEffectiveAddress(UnmanagedPtr, 0x08, value); }
        }

        internal bool iscode            ///< 1-is code reference; 0-is data reference
        {
            get { return (0 != MarshalingUtils.GetByte(UnmanagedPtr, 0x10)); }
        }

        internal byte type              ///< type of the last returned reference (::cref_t & ::dref_t)
        {
            get { return MarshalingUtils.GetByte(UnmanagedPtr, 0x11); }
        }

        internal bool user              ///< 1-is user defined xref, 0-defined by ida
        {
            get { return (0 != MarshalingUtils.GetByte(UnmanagedPtr, 0x12)); }
        }

        public bool first_from(ea_t _from, int flags)
        {
            return ida_xrefblk_t_first_from(UnmanagedPtr, _from, flags);
        }
        public bool next_from()
        {
            return ida_xrefblk_t_next_from(UnmanagedPtr);
        }

        public bool first_to(ea_t _to, int flags)
        {
            return ida_xrefblk_t_first_to(UnmanagedPtr, _to, flags);
        }
        public bool next_to()
        {
            return ida_xrefblk_t_next_to(UnmanagedPtr);
        }

        public bool next_from(ea_t _from, ea_t _to, int flags)
        {
            if (first_from(_from, flags))
            {
                to = _to;
                return next_from();
            }

            return false;
        }

        public bool next_to(ea_t _from, ea_t _to, int flags)
        {
            if (first_to(_to, flags))
            {
                from = _from;
                return next_to();
            }

            return false;
        }
    }
}
