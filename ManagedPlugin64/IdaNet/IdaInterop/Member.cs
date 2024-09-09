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

namespace IdaNet.IdaInterop
{
    public class Member_t
    {
        public Member_t(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
        }

        public IntPtr UnmanagedPtr { get; set; }

        public tid_t tid => MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x00);

        public ea_t Soff => MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x08);

        public ea_t eoff => MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x10);

        public flags_t flag => (flags_t)MarshalingUtils.GetEffectiveAddress(UnmanagedPtr, 0x18);

        public MemberProperties props => (MemberProperties)MarshalingUtils.GetInt32(UnmanagedPtr, 0x1C);

        /// Is a member of a union?
        public bool unimem()
        {
            return (props & MemberProperties.MF_UNIMEM) != 0;
        }

        /// Has members of type "union"?
        public bool has_union()
        {
            return (props & MemberProperties.MF_HASUNI) != 0;
        }

        /// Was the member created due to the type system?
        public bool by_til()
        {
            return (props & MemberProperties.MF_BYTIL) != 0;
        }

        /// Has type information?
        public bool has_ti()
        {
            return (props & MemberProperties.MF_HASTI) != 0;
        }

        /// Is a base class member?
        public bool is_baseclass()
        {
            return (props & MemberProperties.MF_BASECLASS) != 0;
        }

        /// Duplicate name was resolved during import?
        public bool is_dupname()
        {
            return (props & MemberProperties.MF_DUPNAME) != 0;
        }

        /// Is a virtual destructor?
        public bool is_destructor()
        {
            return (props & MemberProperties.MF_DTOR) != 0;
        }

        /// Get start offset (for unions - returns 0)
        public ea_t get_soff()
        {
            return unimem() ? 0 : Soff;
        }

        /// Get member size
        public asize_t get_size()
        {
            return eoff - get_soff();
        }
    }
}
