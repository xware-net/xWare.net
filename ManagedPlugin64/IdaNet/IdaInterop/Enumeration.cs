using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Runtime.InteropServices;
using static IdaPlusPlus.IdaInterop;

using const_t = System.UInt64;
using uval_t = System.UInt64;
using enum_t = System.UInt64;
using size_t = System.UInt64;

namespace IdaNet.IdaInterop
{
    public class Enumeration
    {
        public delegate bool VisitEnumMemberDelegate(const_t cid, uval_t value);

        // Visit all members of a given enum
        public static int ForAllEnumMembers(enum_t id, VisitEnumMemberDelegate cv)
        {
            IntPtr callback = (null == cv)
                 ? IntPtr.Zero
                 : Marshal.GetFunctionPointerForDelegate(cv);

            return ida_for_all_enum_members(id, callback);
        }

        private static string GetEnumName(enum_t e)
        {
            IntPtr nativeBuffer = IntPtr.Zero;
            var requiredSize = ida_get_enum_name2(IntPtr.Zero, e, 0);
            if (-1 == requiredSize)
            {
                return string.Empty;
            }
            else
            {
                nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                requiredSize = ida_get_enum_name2(nativeBuffer, e, 0);
                if (0 <= requiredSize)
                {
                    var enumName = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                    Marshal.FreeCoTaskMem(nativeBuffer);
                    return enumName;
                }
            }

            return string.Empty;
        }

        private static string GetEnumMemberName(const_t id)
        {
            IntPtr nativeBuffer = IntPtr.Zero;
            var requiredSize = ida_get_enum_member_name(IntPtr.Zero, id);
            if (-1 == requiredSize)
            {
                return string.Empty;
            }
            else
            {
                nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                requiredSize = ida_get_enum_member_name(nativeBuffer, id);
                if (0 <= requiredSize)
                {
                    var enumMemeberName = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                    Marshal.FreeCoTaskMem(nativeBuffer);
                    return enumMemeberName;
                }
            }

            return string.Empty;
        }

        public size_t Index;
        public enum_t EnumType => ida_getn_enum(Index);
        public string Name => GetEnumName(EnumType);
        public size_t Width
        {
            get => ida_get_enum_width(EnumType);
            set => ida_set_enum_width(EnumType, (int)value);
        }

        // number of members
        public size_t Size => ida_get_enum_size(EnumType);
        public bool IsBf => ida_is_bf(EnumType);
        public bool IsEnumHidden
        {
            get => ida_is_enum_hidden(EnumType);
            set => ida_set_enum_hidden(EnumType, value);
        }
        public bool IsEnumFromTil
        {
            get => ida_is_enum_fromtil(EnumType);
            set => ida_set_enum_fromtil(EnumType, value);
        }
        public bool IsGhostEnum => ida_is_ghost_enum(EnumType);

        private static string members = string.Empty;
        VisitEnumMemberDelegate callback = VisitEnumMember;
        public static bool VisitEnumMember(const_t cid, uval_t value)
        {
            string memberName = GetEnumMemberName(cid);
            string memberValue = value.ToString();
            if (string.IsNullOrEmpty(members))
            {
                members += string.Format($"{memberName}={memberValue}");
            }
            else
            {
                members += string.Format($", {memberName}={memberValue}");
            }
            return false;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append($"enum {Name} : {Width} (hidden={IsEnumHidden}, fromtil={IsEnumFromTil}) ");
            sb.Append("{{ ");
            members = string.Empty;
            ForAllEnumMembers(EnumType, callback);
            sb.Append(members);
            //for (ulong i = 0; i < Size; i++)
            //{
            //    if (i != 0)
            //        sb.Append(", ");

            //    sb.Append($"{MemberName}={MemberValue};");
            //}
            sb.Append("}};");
            return sb.ToString();
        }
    }
}
