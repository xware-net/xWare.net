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
using Flags64T = System.UInt64;

using IdaNet.IdaInterop;
using System.Data.SqlTypes;
using System.Runtime.InteropServices;
using System.Diagnostics;
using Microsoft.SqlServer.Server;
using System.ComponentModel;
using System.Net.NetworkInformation;

using static IdaPlusPlus.IdaInterop;

namespace ManagedPlugin.Source
{
    public enum TypeIds : UInt64
    {
        // Add RTTI definitions to IDA
        // Structure type IDs

        s_type_info_ID = 1,
        s_ClassHierarchyDescriptor_ID = 2,
        s_PMD_ID = 3,
        s_BaseClassDescriptor_ID = 4,
        s_CompleteObjectLocator_ID = 5,
    };

    public class RTTI
    {
        public const uint BCD_NOTVISIBLE = 0x01;
        public const uint BCD_AMBIGUOUS = 0x02;
        public const uint BCD_PRIVORPROTINCOMPOBJ = 0x04;
        public const uint BCD_PRIVORPROTBASE = 0x08;
        public const uint BCD_VBOFCONTOBJ = 0x10;
        public const uint BCD_NONPOLYMORPHIC = 0x20;
        public const uint BCD_HASPCHD = 0x40;

        const uint CHD_MULTINH = 0x01;    // Multiple inheritance
        const uint CHD_VIRTINH = 0x02;    // Virtual inheritance
        const uint CHD_AMBIGUOUS = 0x04;    // Ambiguous inheritance
        const uint IS_TOP_LEVEL = 0x8000;

        public static void FreeWorkingData()
        {
            ClassInformer.stringCache.Clear();
            ClassInformer.tdSet.Clear();
            ClassInformer.chdSet.Clear();
            ClassInformer.bcdSet.Clear();
        }

        public static string MangleNumber(uint number, string buffer)
        {
            //
            // 0 = A@
            // X = X-1 (1 <= X <= 10)
            // -X = ? (X - 1)
            // 0x0..0xF = 'A'..'P'

            // Can only get unsigned inputs
            int num = (int)number;
            if (num == 0)
                return ("A@");
            else
            {
                int sign = 0;
                if (num < 0)
                {
                    sign = 1;
                    num = -num;
                }

                if (num <= 10)
                {
                    buffer = string.Format($"{(sign != 0 ? "?" : "")}{num - 1}").Substring(0, 64);
                    return (buffer);
                }
                else
                {
                    // Count digits
                    string buffer2 = string.Empty;
                    int count = 64;

                    while ((num > 0) && (count > 0))
                    {
                        buffer2 += ('A' + (num % 16));
                        num = (num / 16);
                        count--;
                    };

                    if (count == 0)
                        Console.WriteLine(" *** mangleNumber() overflow! ***");

                    buffer = string.Format($"{(sign != 0 ? "?" : "")}{buffer2}@").Substring(0, 64);
                    return (buffer);
                }
            }
        }

        public static bool AddStruct(ref StrucT struc, ref TidT id, string name, string comment)
        {
            var ret = false;

            IntPtr nativeBuffer = Marshal.StringToHGlobalAnsi(name);
            IntPtr nativeBuffer1 = Marshal.StringToHGlobalAnsi(comment);

            id = ida_get_struc_id(nativeBuffer);
            if (id == DefineConstants.BADADDR)
            {
                id = ida_add_struc(DefineConstants.BADADDR, nativeBuffer, false);
            }

            if (id != DefineConstants.BADADDR)
                struc = new StrucT(ida_get_struc(id));

            if (struc.UnmanagedPtr != IntPtr.Zero)
            {
                // Clear the old one out if it exists and set the comment
                int dd = ida_del_struc_members(struc.UnmanagedPtr, 0, ida_inf_get_privrange_start_ea());
                bool rr = ida_set_struc_cmt(id, nativeBuffer1, true);
                ret = true;
            }
            else
                PluginBase.WriteDebugMessage($"** addStruct(\"{name}\") failed");

            Marshal.FreeHGlobal(nativeBuffer);
            Marshal.FreeHGlobal(nativeBuffer1);
            return ret;
        }

        public static int AddStrucMember(IntPtr sptr, IntPtr name, EaT offset, Flags64T flag, IntPtr type, AsizeT nbytes)
        {
            int r = ida_add_struc_member(sptr, name, offset, flag, type, nbytes);
            switch (r)
            {
                case (int)StrucErrorT.STRUC_ERROR_MEMBER_NAME:
                    Kernwin.ida_msg("AddStrucMember(): error: already has member with this name (bad name)\n");
                    break;

                case (int)StrucErrorT.STRUC_ERROR_MEMBER_OFFSET:
                    Kernwin.ida_msg("AddStrucMember(): error: already has member at this offset\n");
                    break;

                case (int)StrucErrorT.STRUC_ERROR_MEMBER_SIZE:
                    Kernwin.ida_msg("AddStrucMember(): error: bad number of bytes or bad sizeof(type)\n");
                    break;

                case (int)StrucErrorT.STRUC_ERROR_MEMBER_TINFO:
                    Kernwin.ida_msg("AddStrucMember(): error: bad typeid parameter\n");
                    break;

                case (int)StrucErrorT.STRUC_ERROR_MEMBER_STRUCT:
                    Kernwin.ida_msg("AddStrucMember(): error: bad struct id (the 1st argument)\n");
                    break;

                case (int)StrucErrorT.STRUC_ERROR_MEMBER_UNIVAR:
                    Kernwin.ida_msg("AddStrucMember(): error: unions can't have variable sized members\n");
                    break;

                case (int)StrucErrorT.STRUC_ERROR_MEMBER_VARLAST:
                    Kernwin.ida_msg("AddStrucMember(): error: variable sized member should be the last member in the structure\n");
                    break;

                case (int)StrucErrorT.STRUC_ERROR_MEMBER_NESTED:
                    Kernwin.ida_msg("AddStrucMember(): error: recursive structure nesting is forbidden\n");
                    break;
            };

            return (r);
        }

        private static void AddMember2(StrucT structure, string ptr, EaT offset, UInt64 flags, IntPtr mtoffPtr, AsizeT size)
        {
            IntPtr sptr = Marshal.StringToHGlobalAnsi(ptr);
            if (ida_add_struc_member(structure.UnmanagedPtr, sptr, offset, flags, mtoffPtr, size) != 0)
            {
                Kernwin.ida_msg($" ** ADD_MEMBER2(): {ptr} failed! {offset}, {size} **\n");
            }

            Marshal.FreeHGlobal(sptr);
        }

        public static void AddDefinitionsToIda()
        {
            // Member type info for 32bit offset types
            OpinfoT mtoff = new OpinfoT();
            mtoff.ri.flags = (uint)RefType.REF_OFF64;
            mtoff.ri.target = DefineConstants.BADADDR;

            IntPtr mtoffPtr = Marshal.AllocHGlobal(Marshal.SizeOf(mtoff));
            Marshal.StructureToPtr(mtoff, mtoffPtr, true);

            IntPtr stringPointer = Marshal.StringToHGlobalAnsi("TypeDescriptor");
            StrucT structure = null;
            var s_type_info_ID = ida_get_struc_id(stringPointer);
            if (s_type_info_ID == DefineConstants.BADADDR)
            {
                Kernwin.ida_msg("** Failed to load the IDA TypeDescriptor type, generating one **\n");

                //Structure structure = null;
                if (AddStruct(ref structure, ref s_type_info_ID, "type_info", "RTTI std::type_info class (#classinformer)"))
                {
                    AddMember2(structure, "vfptr", TypeInfo.OffsetOfVfptr(), ida_off_flag() | ida_qword_flag(), mtoffPtr, TypeInfo.OffsetOf_M_data() - TypeInfo.OffsetOfVfptr());
                    AddMember2(structure, "_M_data", TypeInfo.OffsetOf_M_data(), ida_dword_flag(), IntPtr.Zero, sizeof(EaT));

                    // Name string zero size
                    OpinfoT mt = new OpinfoT();
                    IntPtr mtPtr = Marshal.AllocHGlobal(Marshal.SizeOf(mt));
                    Marshal.StructureToPtr(mt, mtPtr, true);
                    //ZeroMemory(mt, sizeof(refinfo_t));
                    {
                        IntPtr sptr = Marshal.StringToHGlobalAnsi("_M_d_name");
                        if (AddStrucMember(structure.UnmanagedPtr, sptr, TypeInfo.OffsetOf_M_d_name(), ida_strlit_flag(), mtPtr, 0) != 0)
                        {
                            Kernwin.ida_msg("** addDefinitionsToIda():  _M_d_name failed! \n");
                        }

                        Marshal.FreeHGlobal(sptr);
                    }

                    Marshal.FreeHGlobal(mtPtr);
                }
            }

            Marshal.FreeHGlobal(stringPointer);
            Marshal.FreeHGlobal(mtoffPtr);

            var s_PMD_ID = (UInt64)TypeIds.s_PMD_ID;
            structure = null;
            // Must come before the following  "_RTTIBaseClassDescriptor"
            if (AddStruct(ref structure, ref s_PMD_ID, "_PMD", "RTTI Base class descriptor displacement container (#classinformer)"))
            {
                AddMember2(structure, "mdisp", PMD.OffsetOfMdisp(), ida_dword_flag(), IntPtr.Zero, sizeof(int));
                AddMember2(structure, "pdisp", PMD.OffsetOfPdisp(), ida_dword_flag(), IntPtr.Zero, sizeof(int));
                AddMember2(structure, "vdisp", PMD.OffsetOfVdisp(), ida_dword_flag(), IntPtr.Zero, sizeof(int));
            }

            var s_ClassHierarchyDescriptor_ID = (UInt64)TypeIds.s_ClassHierarchyDescriptor_ID;
            structure = null;
            if (AddStruct(ref structure, ref s_ClassHierarchyDescriptor_ID, "_RTTIClassHierarchyDescriptor", "RTTI Class Hierarchy Descriptor (#classinformer)"))
            {
                AddMember2(structure, "signature", RTTIClassHierarchyDescriptor.OffsetOfSignature(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                AddMember2(structure, "attributes", RTTIClassHierarchyDescriptor.OffsetOfAttributes(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                AddMember2(structure, "numBaseClasses", RTTIClassHierarchyDescriptor.OffsetOfNumBaseClasses(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                AddMember2(structure, "baseClassArray", RTTIClassHierarchyDescriptor.OffsetOfBaseClassArray(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
            }

            var s_BaseClassDescriptor_ID = (UInt64)TypeIds.s_BaseClassDescriptor_ID;
            structure = null;
            if (AddStruct(ref structure, ref s_BaseClassDescriptor_ID, "_RTTIBaseClassDescriptor", "RTTI Base Class Descriptor (#classinformer)"))
            {
                AddMember2(structure, "typeDescriptor", RTTIBaseClassDescriptor.OffsetOfTypeDescriptor(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                AddMember2(structure, "numContainedBases", RTTIBaseClassDescriptor.OffsetOfNumContainedBases(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                OpinfoT mt = new OpinfoT();
                mt.tid = s_PMD_ID;
                IntPtr mtPtr = Marshal.AllocHGlobal(Marshal.SizeOf(mt));
                Marshal.StructureToPtr(mt, mtPtr, true);
                AddMember2(structure, "pmd", RTTIBaseClassDescriptor.OffsetOfPmd(), ida_stru_flag(), mtPtr, PMD.Size());
                AddMember2(structure, "attributes", RTTIBaseClassDescriptor.OffsetOfAttributes(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                Marshal.FreeHGlobal(mtPtr);
            }

            var s_CompleteObjectLocator_ID = (UInt64)TypeIds.s_CompleteObjectLocator_ID;
            structure = null;
            if (AddStruct(ref structure, ref s_CompleteObjectLocator_ID, "_RTTIClassHierarchyDescriptor", "RTTI Complete Object Locator (#classinformer)"))
            {
                AddMember2(structure, "signature", RTTICompleteObjectLocator.OffsetOfSignature(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                AddMember2(structure, "offset", RTTICompleteObjectLocator.OffsetOfOffset(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                AddMember2(structure, "cdOffset", RTTICompleteObjectLocator.OffsetOfCdOffset(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                AddMember2(structure, "typeDescriptor", RTTICompleteObjectLocator.OffsetOfTypeDescriptor(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                AddMember2(structure, "classDescriptor", RTTICompleteObjectLocator.OffsetOfClassDescriptor(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
                AddMember2(structure, "objectBase", RTTICompleteObjectLocator.OffsetOfObjectBase(), ida_dword_flag(), IntPtr.Zero, sizeof(uint));
            }
        }

        public static bool TryStructRTTI(EaT ea, TidT tid, string typeName = null, bool hasChd = false)
        {
            if (tid == (TidT)TypeIds.s_type_info_ID)
            {
                if (!Bytes.HasName(ea))
                {
                    if (typeName == null)
                        Debugger.Break();
                    uint nameLen = (uint)(typeName.Length + 1);
                    uint structSize = (uint)TypeInfo.OffsetOf_M_d_name() + nameLen;

                    // Place struct
                    Bytes.SetUnknown(ea, structSize);
                    bool result = false;
                    if (ClassInformer.OptionPlaceStructs)
                        result = Bytes.CreateStruct(ea, structSize, (TidT)TypeIds.s_type_info_ID);
                    if (!result)
                    {
                        Bytes.PutEa(ea + TypeInfo.OffsetOfVfptr());
                        Bytes.PutEa(ea + TypeInfo.OffsetOf_M_data());

                        ida_create_strlit((ea + TypeInfo.OffsetOf_M_d_name()), nameLen, DefineConstants.STRTYPE_C);
                    }

                    // sh!ft: End should be aligned
                    EaT end = (ea + TypeInfo.OffsetOf_M_d_name() + nameLen);
                    if (end % 4 != 0)
                        ida_create_align(end, (4 - (end % 4)), 0);

                    return true;
                }
            }
            else
            {
                if (tid == (TidT)TypeIds.s_ClassHierarchyDescriptor_ID)
                {
                    if (!Bytes.HasName(ea))
                    {
                        Bytes.SetUnknown(ea, RTTIClassHierarchyDescriptor.Size());
                        bool result = false;
                        if (ClassInformer.OptionPlaceStructs)
                            result = Bytes.CreateStruct(ea, RTTIClassHierarchyDescriptor.Size(), (TidT)TypeIds.s_ClassHierarchyDescriptor_ID);
                        if (!result)
                        {
                            Bytes.PutDword(ea + RTTIClassHierarchyDescriptor.OffsetOfSignature());
                            Bytes.PutDword(ea + RTTIClassHierarchyDescriptor.OffsetOfAttributes());
                            Bytes.PutDword(ea + RTTIClassHierarchyDescriptor.OffsetOfNumBaseClasses());
                            Bytes.PutDword(ea + RTTIClassHierarchyDescriptor.OffsetOfBaseClassArray());
                        }

                        return true;
                    }
                }
                else
                {
                    if (tid == (TidT)TypeIds.s_PMD_ID)
                    {
                        if (!Bytes.HasName(ea))
                        {
                            Bytes.SetUnknown(ea, PMD.Size());
                            bool result = false;
                            if (ClassInformer.OptionPlaceStructs)
                                result = Bytes.CreateStruct(ea, PMD.Size(), (TidT)TypeIds.s_PMD_ID);
                            if (!result)
                            {
                                Bytes.PutDword(ea + PMD.OffsetOfMdisp());
                                Bytes.PutDword(ea + PMD.OffsetOfPdisp());
                                Bytes.PutDword(ea + PMD.OffsetOfVdisp());
                            }

                            return true;
                        }
                    }
                    else
                    {
                        if (tid == (TidT)TypeIds.s_CompleteObjectLocator_ID)
                        {
                            if (!Bytes.HasName(ea))
                            {
                                Bytes.SetUnknown(ea, RTTICompleteObjectLocator.Size());
                                bool result = false;
                                if (ClassInformer.OptionPlaceStructs)
                                    result = Bytes.CreateStruct(ea, RTTICompleteObjectLocator.Size(), (TidT)TypeIds.s_CompleteObjectLocator_ID);
                                if (!result)
                                {
                                    Bytes.PutDword(ea + RTTICompleteObjectLocator.OffsetOfSignature());
                                    Bytes.PutDword(ea + RTTICompleteObjectLocator.OffsetOfOffset());
                                    Bytes.PutDword(ea + RTTICompleteObjectLocator.OffsetOfCdOffset());
                                    Bytes.PutDword(ea + RTTICompleteObjectLocator.OffsetOfTypeDescriptor());
                                    Bytes.PutDword(ea + RTTICompleteObjectLocator.OffsetOfClassDescriptor());
                                    Bytes.PutDword(ea + RTTICompleteObjectLocator.OffsetOfObjectBase());
                                }

                                return true;
                            }
                        }
                        else
                        {
                            if (tid == (TidT)TypeIds.s_BaseClassDescriptor_ID)
                            {
                                // recursive
                                TryStructRTTI(ea + RTTIBaseClassDescriptor.OffsetOfPmd(), (TidT)TypeIds.s_PMD_ID);

                                if (!Bytes.HasName(ea))
                                {
                                    Bytes.SetUnknown(ea, RTTIBaseClassDescriptor.Size());
                                    bool result = false;
                                    if (ClassInformer.OptionPlaceStructs)
                                        result = Bytes.CreateStruct(ea, RTTIBaseClassDescriptor.Size(), (TidT)TypeIds.s_BaseClassDescriptor_ID);
                                    if (!result)
                                    {
                                        Bytes.PutDword(ea + RTTIBaseClassDescriptor.OffsetOfTypeDescriptor());
                                        Bytes.PutDword(ea + RTTIBaseClassDescriptor.OffsetOfNumContainedBases());
                                        Bytes.PutDword(ea + RTTIBaseClassDescriptor.OffsetOfAttributes());
                                        if (hasChd)
                                        {
                                            Bytes.PutDword(ea + RTTIBaseClassDescriptor.OffsetOfAttributes() + sizeof(uint));
                                        }
                                    }

                                    return true;
                                }
                            }
                            else
                            {
                                Debugger.Break();
                            }
                        }
                    }
                }
            }

            return false;
        }

        internal static string FORMAT_RTTI_VFTABLE = "??_7{0}6B@";
        internal static string FORMAT_RTTI_VFTABLE_PREFIX = "??_7";
        // type 'RTTI Type Descriptor'
        internal static string FORMAT_RTTI_TYPE = "??_R0?{0}@8";
        // 'RTTI Base Class Descriptor at (a,b,c,d)'
        internal static string FORMAT_RTTI_BCD = "??_R1{0}{1}{2}{3}{4}8";
        // `RTTI Base Class Array'
        internal static string FORMAT_RTTI_BCA = "??_R2{0}8";
        // 'RTTI Class Hierarchy Descriptor'
        internal static string FORMAT_RTTI_CHD = "??_R3{0}8";
        // 'RTTI Complete Object Locator'
        internal static string FORMAT_RTTI_COL = "??_R4{0}6B@";
        internal static string FORMAT_RTTI_COL_PREFIX = "??_R4";

        // Process RTTI vftable info
        // Returns TRUE if if vftable and wasn't named on entry
        internal static bool processVftable(EaT vft, EaT col)
        {
            bool result = false;

            EaT colBase;
            EaT typeInfo;
            uint tdOffset = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfTypeDescriptor());
            uint objectLocator = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfObjectBase());
            colBase = (col - (UInt64)objectLocator);
            typeInfo = (colBase + (UInt64)tdOffset);

            //// Verify and fix if vftable exists here
            VTableInfo vi = new VTableInfo();
            if (VTableInfo.GetTableInfo(vft, ref vi))
            {
                //PluginBase.WriteDebugMessage($"{vi.ea_begin:X16} - {vi.ea_end:X16} c: {vi.methodCount}\n");

                // Get COL type name
                EaT chd;
                uint cdOffset = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfClassDescriptor());
                chd = (colBase + (UInt64)cdOffset);

                string colName = string.Empty;
                TypeInfo.GetName(typeInfo, ref colName);
                string demangledColName = string.Empty;
                _ = ClassInformer.GetPlainTypeName(colName, ref demangledColName);

                uint chdAttributes = ida_get_32bit(chd + RTTIClassHierarchyDescriptor.OffsetOfAttributes());
                uint offset = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfOffset());

                // Parse BCD info
                List<bcdInfo> list = new List<bcdInfo>();
                uint numBaseClasses = 0;
                GetBCDInfo(col, ref list, ref numBaseClasses);

                bool sucess = false, isTopLevel = false;
                string cmt = string.Empty;

                // ======= Simple or no inheritance
                if ((offset == 0) && ((chdAttributes & (DefineConstants.CHD_MULTINH | DefineConstants.CHD_VIRTINH)) == 0))
                {
                    // Set the vftable name
                    if (!Bytes.HasName(vft))
                    {
                        result = true;

                        // Decorate raw name as a vftable. I.E. const Name::`vftable'
                        string decorated = string.Empty;
                        decorated = string.Format(FORMAT_RTTI_VFTABLE, colName.Substring(4));
                        Bytes.SetName(vft, decorated);
                    }

                    // Set COL name. I.E. const Name::`RTTI Complete Object Locator'
                    if (!Bytes.HasName(col))
                    {
                        string decorated = string.Empty;
                        decorated = string.Format(FORMAT_RTTI_COL, colName.Substring(4));
                        Bytes.SetName(col, decorated);
                    }

                    // Build object hierarchy string
                    int placed = 0;
                    if (numBaseClasses > 1)
                    {
                        // Parent
                        string plainName = string.Empty;
                        _ = ClassInformer.GetPlainTypeName(list[0].m_name, ref plainName);
                        cmt = string.Format($"{((list[0].m_name[3] == 'V') ? "" : "struct ")}{plainName}: ");
                        placed++;
                        isTopLevel = (list[0].m_name == colName) ? true : false;

                        // Child object hierarchy
                        for (uint i = 1; i < numBaseClasses; i++)
                        {
                            // Append name
                            _ = ClassInformer.GetPlainTypeName(list[(int)i].m_name, ref plainName);
                            cmt += string.Format($"{((list[(int)i].m_name[3] == 'V') ? "" : "struct ")}{plainName}, ");
                            placed++;
                        }

                        // Nix the ending ',' for the last one
                        if (placed > 1)
                        {
                            int ix = cmt.LastIndexOf(", ");
                            if (ix != -1)
                            {
                                cmt = cmt.Substring(0, ix);
                            }
                        }
                    }
                    else
                    {
                        // Plain, no inheritance object(s)
                        cmt = string.Format($"{((colName[3] == 'V') ? "" : "struct ")}{demangledColName}: ");
                        isTopLevel = true;
                    }

                    if (placed > 1)
                        cmt += ';';

                    sucess = true;
                }
                // ======= Multiple inheritance, and, or, virtual inheritance hierarchies
                else
                {

                    bcdInfo bi;
                    bi.m_name = string.Empty;
                    int index = 0;
                    bool foundInList = false;

                    // Must be the top level object for the type
                    if (offset == 0)
                    {
                        if (colName != list[0].m_name)
                        {
                            Debugger.Break();
                        }
                        bi = list[0];
                        isTopLevel = true;
                        foundInList = true;
                    }
                    else
                    {
                        // Get our object BCD level by matching COL offset to displacement
                        for (int i = 0; i < numBaseClasses; i++)
                        {
                            if (list[i].m_pmd.mdisp == offset)
                            {
                                bi = list[i];
                                index = i;
                                foundInList = true;
                                break;
                            }
                        }

                        // If not found in list, use the first base object instead
                        if (!foundInList)
                        {
                            //msg("** " EAFORMAT " MI COL class offset: %X(%d) not in BCD.\n", vft, offset, offset);
                            for (int i = 0; i < numBaseClasses; i++)
                            {
                                if (list[i].m_pmd.pdisp != -1)
                                {
                                    bi = list[i];
                                    index = i;
                                    break;
                                }
                            }
                        }
                    }

                    if (foundInList)
                    {
                        // Top object level layout
                        int placed = 0;
                        if (isTopLevel)
                        {
                            // Set the vft name
                            if (!Bytes.HasName(vft))
                            {
                                result = true;

                                string decorated = string.Empty;
                                decorated = string.Format(FORMAT_RTTI_VFTABLE, colName.Substring(4));
                                Bytes.SetName(vft, decorated);
                            }

                            // COL name
                            if (!Bytes.HasName(col))
                            {
                                string decorated = string.Empty;
                                decorated = string.Format(FORMAT_RTTI_COL, colName.Substring(4));
                                Bytes.SetName(col, decorated);
                            }

                            // Build hierarchy string starting with parent
                            string plainName = string.Empty;
                            _ = ClassInformer.GetPlainTypeName(list[0].m_name, ref plainName);
                            cmt = string.Format($"{((list[0].m_name[3] == 'V') ? "" : "struct ")}{plainName}: ");
                            placed++;

                            // Concatenate forward child hierarchy
                            for (int i = 1; i < numBaseClasses; i++)
                            {
                                _ = ClassInformer.GetPlainTypeName(list[i].m_name, ref plainName);
                                cmt += string.Format($"{((list[i].m_name[3] == 'V') ? "" : "struct ")}{plainName}, ");
                                placed++;
                            }
                            if (placed > 1)
                            {
                                int ix = cmt.LastIndexOf(", ");
                                if (ix != -1)
                                {
                                    cmt = cmt.Substring(0, ix);
                                }
                            }
                        }
                        else
                        {
                            // Combine COL and CHD name
                            string combinedName = string.Empty;
                            combinedName = string.Format($"{colName.Substring(4)}6B{bi.m_name.Substring(4)}@");

                            // Set vftable name
                            if (!Bytes.HasName(vft))
                            {
                                result = true;

                                string decorated = string.Empty;
                                decorated = FORMAT_RTTI_VFTABLE_PREFIX;
                                decorated += combinedName;
                                if (decorated.Length > DefineConstants.MAXSTR)
                                    decorated = decorated.Substring(0, DefineConstants.MAXSTR);
                                Bytes.SetName(vft, decorated);
                            }

                            // COL name
                            if (!Bytes.HasName((EaT)col))
                            {
                                string decorated = string.Empty;
                                decorated = FORMAT_RTTI_COL_PREFIX;
                                decorated += combinedName;
                                if (decorated.Length > DefineConstants.MAXSTR)
                                    decorated = decorated.Substring(0, DefineConstants.MAXSTR);
                                Bytes.SetName((EaT)col, decorated);
                            }

                            // Build hierarchy string starting with parent
                            string plainName = string.Empty;
                            _ = ClassInformer.GetPlainTypeName(bi.m_name, ref plainName);
                            cmt = string.Format($"{((bi.m_name[3] == 'V') ? "" : "struct ")}{plainName}: ");
                            placed++;

                            // Concatenate forward child hierarchy
                            if (++index < (int)numBaseClasses)
                            {
                                for (; index < (int)numBaseClasses; index++)
                                {
                                    _ = ClassInformer.GetPlainTypeName(list[index].m_name, ref plainName);
                                    cmt += string.Format($"{((list[index].m_name[3] == 'V') ? "" : "struct ")}{plainName}, ");
                                    placed++;
                                }

                                if (placed > 1)
                                {
                                    int ix = cmt.LastIndexOf(", ");
                                    if (ix != -1)
                                    {
                                        cmt = cmt.Substring(0, ix);
                                    }
                                }
                            }
                        }

                        if (placed > 1)
                            cmt += ';';

                        sucess = true;
                    }
                    else
                    {
                        //msg(EAFORMAT" ** Couldn't find a BCD for MI/VI hierarchy!\n", vft);
                    }
                }

                if (sucess)
                {
                    // Store entry
                    string entryString = string.Format($"{demangledColName}@{cmt}");
                    //Kernwin.ida_msg(string.Format($" --> {vft:X16}, {vi.methodCount}, {chdAttributes & 0xF}, {isTopLevel}, {entryString}\n"));
                    RTTIChooser.AddTableEntry(vft, (ushort)(vi.methodCount), (ushort)((chdAttributes & 0xF) | (isTopLevel ? RTTI.IS_TOP_LEVEL : 0)), entryString);

                    // Add a separating comment above RTTI COL
                    EaT colPtr = (vft - ClassInformer.GetPtrSize());
                    Bytes.FixEa(colPtr);
                    cmt += string.Format($"  {attributeLabel(chdAttributes)} (#classinformer)");
                    if (!Bytes.HasAnteriorComment(colPtr))
                    {
                        string comment = string.Format($"\n; {((colName[3] == 'V') ? "class" : "struct")} {cmt}");
                        Bytes.SetAnteriorComment(colPtr, comment);
                    }

                    //vftable::processMembers(plainName, vft, end);
                }
            }
            else
            {
                // Usually a typedef reference to a COL, not a vftable

                //qstring tmp;
                //idaFlags2String(get_flags(vft), tmp);
                //msg(EAFORMAT" ** Vftable attached to this COL, error? (%s)\n", vft, tmp.c_str());


                // Just set COL name
                if (!Bytes.HasName(col))
                {
                    string colName = string.Empty;
                    TypeInfo.GetName(typeInfo, ref colName);

                    string decorated = string.Empty;
                    decorated = string.Format(FORMAT_RTTI_COL, colName.Substring(4));
                    Bytes.SetName(col, decorated);
                }
            }

            return result;
        }

        // Return a short label indicating the CHD inheritance type by attributes
        // TODO: Consider CHD_AMBIGUOUS?
        internal static string attributeLabel(uint attributes)
        {
            if ((attributes & 3) == RTTI.CHD_MULTINH)
            {
                return ("[MI]");
            }
            else
            {
                if ((attributes & 3) == RTTI.CHD_VIRTINH)
                {
                    return ("[VI]");
                }
                else
                {
                    if ((attributes & 3) == (RTTI.CHD_MULTINH | RTTI.CHD_VIRTINH))
                    {
                        return ("[MI VI]");
                    }
                    else
                    {
                        return ("");
                    }
                }
            }
        }

        // Class name list container
        public struct bcdInfo
        {
            public string m_name;
            public uint m_attribute;
            public PMD m_pmd;
        };

        public static void GetBCDInfo(EaT col, ref List<bcdInfo> list, ref uint numBaseClasses)
        {
            numBaseClasses = 0;
            uint cdOffset = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfClassDescriptor());
            uint objectLocator = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfObjectBase());
            EaT colBase = (col - (UInt64)objectLocator);
            EaT chd = (colBase + (UInt64)cdOffset);

            if (chd != 0)
            {
                if ((numBaseClasses = ida_get_32bit(chd + RTTIClassHierarchyDescriptor.OffsetOfNumBaseClasses())) != 0)
                {
                    // resize list
                    if (numBaseClasses > list.Count)
                        while (numBaseClasses - list.Count > 0)
                        {
                            bcdInfo binfo = new bcdInfo();
                            binfo.m_name = string.Empty;
                            list.Add(binfo);
                        }
                    else if (numBaseClasses < list.Count)
                        while (list.Count - numBaseClasses > 0)
                            list.RemoveAt(list.Count - 1);

                    //list.Resize(numBaseClasses);
                    // Get pointer
                    uint bcaOffset = ida_get_32bit(chd + RTTIClassHierarchyDescriptor.OffsetOfBaseClassArray());
                    EaT baseClassArray = (colBase + (UInt64)bcaOffset);

                    if (baseClassArray != DefineConstants.BADADDR)
                    {
                        for (int i = 0; i < numBaseClasses; i++, baseClassArray += 4)
                        {
                            uint bcdOffset = ida_get_32bit(baseClassArray);
                            EaT bcd = colBase + (UInt64)bcdOffset;

                            uint tdOffset = ida_get_32bit(bcd + RTTIBaseClassDescriptor.OffsetOfTypeDescriptor());
                            var typeInfo = colBase + (UInt64)tdOffset;

                            bcdInfo bi = list[i];
                            TypeInfo.GetName(typeInfo, ref bi.m_name);

                            // Add info to list
                            uint mdisp = ida_get_32bit(bcd + (RTTIBaseClassDescriptor.OffsetOfPmd() + PMD.OffsetOfMdisp()));
                            uint pdisp = ida_get_32bit(bcd + (RTTIBaseClassDescriptor.OffsetOfPmd() + PMD.OffsetOfPdisp()));
                            uint vdisp = ida_get_32bit(bcd + (RTTIBaseClassDescriptor.OffsetOfPmd() + PMD.OffsetOfVdisp()));
                            // As signed int
                            bi.m_pmd.mdisp = (int)mdisp;
                            bi.m_pmd.pdisp = (int)pdisp;
                            bi.m_pmd.vdisp = (int)vdisp;
                            bi.m_attribute = ida_get_32bit(bcd + RTTIBaseClassDescriptor.OffsetOfAttributes());

                            list[i] = bi;
                            //msg("   BN: [%d] \"%s\", ATB: %04X\n", i, szBuffer1, get_32bit((ea_t) &pBCD->attributes));
                            //msg("       mdisp: %d, pdisp: %d, vdisp: %d, attributes: %04X\n", *((PINT) &mdisp), *((PINT) &pdisp), *((PINT) &vdisp), attributes);
                        }
                    }
                }
            }
        }

        [Flags]
        public enum UnDecorateFlags
        {
            UNDNAME_COMPLETE = (0x0000),  // Enable full undecoration
            UNDNAME_NO_LEADING_UNDERSCORES = (0x0001),  // Remove leading underscores from MS extended keywords
            UNDNAME_NO_MS_KEYWORDS = (0x0002),  // Disable expansion of MS extended keywords
            UNDNAME_NO_FUNCTION_RETURNS = (0x0004),  // Disable expansion of return type for primary declaration
            UNDNAME_NO_ALLOCATION_MODEL = (0x0008),  // Disable expansion of the declaration model
            UNDNAME_NO_ALLOCATION_LANGUAGE = (0x0010),  // Disable expansion of the declaration language specifier
            UNDNAME_NO_MS_THISTYPE = (0x0020),  // NYI Disable expansion of MS keywords on the 'this' type for primary declaration
            UNDNAME_NO_CV_THISTYPE = (0x0040),  // NYI Disable expansion of CV modifiers on the 'this' type for primary declaration
            UNDNAME_NO_THISTYPE = (0x0060),  // Disable all modifiers on the 'this' type
            UNDNAME_NO_ACCESS_SPECIFIERS = (0x0080),  // Disable expansion of access specifiers for members
            UNDNAME_NO_THROW_SIGNATURES = (0x0100),  // Disable expansion of 'throw-signatures' for functions and pointers to functions
            UNDNAME_NO_MEMBER_TYPE = (0x0200),  // Disable expansion of 'static' or 'virtual'ness of members
            UNDNAME_NO_RETURN_UDT_MODEL = (0x0400),  // Disable expansion of MS model for UDT returns
            UNDNAME_32_BIT_DECODE = (0x0800),  // Undecorate 32-bit decorated names
            UNDNAME_NAME_ONLY = (0x1000),  // Crack only the name for primary declaration;
                                           // return just [scope::]name.  Does expand template params
            UNDNAME_TYPE_ONLY = (0x2000),  // Don't undecorate arguments to function
            UNDNAME_HAVE_PARAMETERS = (0x4000),  // Don't undecorate special names (v-table, vcall, vector xxx, metatype, etc)
            UNDNAME_NO_ECSU = (0x8000),
            UNDNAME_NO_IDENT_CHAR_CHECK = (0x10000),
            UNDNAME_NO_PTR64 = (0x20000),
        }

        [DllImport("dbghelp.dll", SetLastError = true, PreserveSig = true)]
        public static extern int UnDecorateSymbolName(
            [In][MarshalAs(UnmanagedType.LPStr)] string DecoratedName,
            [Out] StringBuilder UnDecoratedName,
            [In][MarshalAs(UnmanagedType.U4)] int UndecoratedLength,
            [In][MarshalAs(UnmanagedType.U4)] UnDecorateFlags Flags);
    }

    public struct TypeInfo
    {
        public IntPtr vfptr;	        // type_info class vftable
        public EaT _M_data;       // NULL until loaded at runtime
        public string _M_d_name;   // Mangled name (prefix: .?AV=classes, .?AU=structs)

        public static ulong OffsetOfVfptr() { return 0; }
        public static ulong OffsetOf_M_data() { return 8; }
        public static ulong OffsetOf_M_d_name() { return 8 + 8; }

        public static bool IsValid(EaT typeInfo)
        {
            //// TRUE if we've already seen it
            if (ClassInformer.tdSet.Contains(typeInfo))
                return true;

            if (ida_is_loaded(typeInfo))
            {
                // Verify what should be a vftable
                EaT ea = Bytes.GetEa(typeInfo + TypeInfo.OffsetOfVfptr());
                if (ida_is_loaded(ea))
                {
                    // _M_data should be NULL statically
                    EaT _M_data = DefineConstants.BADADDR;
                    if (Bytes.GetVerifyEa((typeInfo + TypeInfo.OffsetOf_M_data()), ref _M_data))
                    {
                        if (_M_data == 0)
                        {
                            return (IsTypeName(typeInfo + TypeInfo.OffsetOf_M_d_name()));
                        }
                    }
                }
            }

            return false;
        }

        // Read ASCII string from IDB at address
        public static SizeT GetIdaString(EaT ea, ref string buffer)
        {
            // Return cached name if it exists
            if (ClassInformer.stringCache.ContainsKey(ea))
            {
                buffer = ClassInformer.stringCache[ea];
                return (SizeT)buffer.Length;
            }

            SizeT requiredSize = ida_get_ida_string(IntPtr.Zero, ea);
            if (requiredSize > 0)
            {
                IntPtr nativeBuffer = IntPtr.Zero;
                if (0 <= requiredSize)
                {
                    nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
                    requiredSize = ida_get_ida_string(nativeBuffer, ea);
                    buffer = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
                }

                Marshal.FreeCoTaskMem(nativeBuffer);
            }

            return requiredSize;
        }

        public static bool IsTypeName(EaT ea)
        {
            //PluginBase.WriteDebugMessage($"     Check is type name at 0x{ea:X}");
            // Should start with a period
            byte b;
            if ((b = Bytes.GetByte(ea)) == '.')
            {
                // Read the rest of the possible name string
                string buffer = null;
                if (GetIdaString(ea, ref buffer) > 0)
                {
                    // skip "."
                    string mangledTypeName = buffer.Substring(1);
                    // Should be valid if it properly demangles
                    StringBuilder builder = new StringBuilder(1024);
                    if (RTTI.UnDecorateSymbolName(mangledTypeName, builder, builder.Capacity, (RTTI.UnDecorateFlags.UNDNAME_32_BIT_DECODE | RTTI.UnDecorateFlags.UNDNAME_TYPE_ONLY /*| RTTI.UnDecorateFlags.UNDNAME_NO_ECSU*/)) != 0)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static SizeT GetName(EaT typeInfo, ref string buffer)
        {
            return GetIdaString(typeInfo + TypeInfo.OffsetOf_M_d_name(), ref buffer);
        }

        public static void TryStruct(EaT typeInfo)
        {
            // Only place once per address
            if (ClassInformer.tdSet.Contains(typeInfo))
                return;
            else
                ClassInformer.tdSet.Add(typeInfo);

            // Get type name
            string name = string.Empty;
            SizeT nameLen = GetName(typeInfo, ref name);

            RTTI.TryStructRTTI(typeInfo, (TidT)TypeIds.s_type_info_ID, name);
            if (nameLen > 0)
            {
                if (!Bytes.HasName(typeInfo))
                {
                    // Set decorated name/label
                    string name2 = string.Format($"??_R0?{name}@8");
                    Bytes.SetName(typeInfo, name2);
                }
            }
            else
            {
                Debugger.Break();
            }
        }
    };

    // Base class "Pointer to Member Data"
    public struct PMD
    {
        public int mdisp;  // 00 Member displacement
        public int pdisp;  // 04 Vftable displacement
        public int vdisp;  // 08 Displacement inside vftable

        public static ulong OffsetOfMdisp() { return 0; }
        public static ulong OffsetOfPdisp() { return 4; }
        public static ulong OffsetOfVdisp() { return 4 + 4; }
        public static uint Size() { return 4 + 4 + 4; }
    };

    public struct RTTIBaseClassDescriptor
    {
        public uint typeDescriptor;        // 00 Type descriptor of the class
        public uint numContainedBases;     // 04 Number of nested classes following in the Base Class Array
        public PMD pmd;                    // 08 Pointer-to-member displacement info
        public uint attributes;            // 14 Flags

        public static ulong OffsetOfTypeDescriptor() { return 0; }
        public static ulong OffsetOfNumContainedBases() { return 4; }
        public static ulong OffsetOfPmd() { return 4 + 4; }
        public static ulong OffsetOfAttributes() { return 4 + 4 + 4 + 4 + 4; }
        public static uint Size() { return 4 + 4 + 4 + 4 + 4 + 4; }

        public static bool IsValid(EaT bcd, EaT colBase64)
        {
            // TRUE if we've already seen it
            if (ClassInformer.bcdSet.Contains(bcd))
                return true;

            if (ida_is_loaded(bcd))
            {
                // Check attributes flags first
                uint attributes = 0xffffffff;
                if (Bytes.GetVerify32((bcd + RTTIBaseClassDescriptor.OffsetOfAttributes()), ref attributes))
                {
                    // Valid flags are the lower byte only
                    if ((attributes & 0xFFFFFF00) == 0)
                    {
                        // Check for valid type_info
                        uint tdOffset = ida_get_32bit(bcd + RTTIBaseClassDescriptor.OffsetOfTypeDescriptor());
                        EaT typeInfo = (colBase64 + (UInt64)tdOffset);
                        return TypeInfo.IsValid(typeInfo);
                    }
                }
            }

            return false;
        }

        public static void TryStruct(EaT bcd, string baseClassName, EaT colBase64)
        {
            // Only place it once
            if (ClassInformer.bcdSet.Contains(bcd))
            {
                // Seen already, just return type name
                uint tdOffset = ida_get_32bit(bcd + RTTIBaseClassDescriptor.OffsetOfTypeDescriptor());
                EaT typeInfo = (colBase64 + (UInt64)tdOffset);

                string buffer = null;
                TypeInfo.GetName(typeInfo, ref buffer);
                baseClassName = buffer.Substring(3);
                return;
            }
            else
                ClassInformer.bcdSet.Add(bcd);

            if (ida_is_loaded(bcd))
            {
                uint attributes = ida_get_32bit(bcd + RTTIBaseClassDescriptor.OffsetOfAttributes());
                RTTI.TryStructRTTI(bcd, (TidT)TypeIds.s_BaseClassDescriptor_ID, null, ((attributes & RTTI.BCD_HASPCHD) > 0));

                // Has appended CHD?
                if ((attributes & RTTI.BCD_HASPCHD) != 0)
                {
                    // yes, process it
                    EaT chdOffset = (bcd + (RTTIBaseClassDescriptor.OffsetOfAttributes() + sizeof(uint)));

                    Bytes.FixDword(chdOffset);
                    uint chdOffset32 = ida_get_32bit(chdOffset);
                    EaT chd = (colBase64 + (UInt64)chdOffset32);

                    if (!Bytes.HasComment(chdOffset))
                    {
                        string buf = string.Format($"0x{chd:X16}");
                        Bytes.SetComment(chdOffset, buf, true);
                    }

                    if (ida_is_loaded(chd))
                        RTTIClassHierarchyDescriptor.TryStruct(chd, colBase64);
                    else
                        Debugger.Break();
                }

                uint tdOffset = ida_get_32bit(bcd + RTTIBaseClassDescriptor.OffsetOfTypeDescriptor());
                EaT typeInfo = (colBase64 + (UInt64)tdOffset);
                TypeInfo.TryStruct(typeInfo);

                // Get raw type/class name
                string buf1 = null;
                TypeInfo.GetName(typeInfo, ref buf1);
                baseClassName = buf1.Substring(3);

                if (!ClassInformer.OptionPlaceStructs && attributes != 0)
                {
                    // Place attributes comment
                    EaT ea = (bcd + RTTIBaseClassDescriptor.OffsetOfAttributes());
                    if (!Bytes.HasComment(ea))
                    {
                        string s = string.Empty;
                        bool b = false;
                        {
                            if ((attributes & RTTI.BCD_NOTVISIBLE) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }
                                s += "BCD_NOTVISIBLE";
                                b = true;
                            }
                        };
                        {
                            if ((attributes & RTTI.BCD_AMBIGUOUS) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }
                                s += "BCD_AMBIGUOUS";
                                b = true;
                            }
                        };
                        {
                            if ((attributes & RTTI.BCD_PRIVORPROTINCOMPOBJ) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }
                                s += "BCD_PRIVORPROTINCOMPOBJ";
                                b = true;
                            }
                        };
                        {
                            if ((attributes & RTTI.BCD_PRIVORPROTBASE) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }
                                s += "BCD_PRIVORPROTBASE";
                                b = true;
                            }
                        };
                        {
                            if ((attributes & RTTI.BCD_VBOFCONTOBJ) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }
                                s += "BCD_VBOFCONTOBJ";
                                b = true;
                            }
                        };
                        {
                            if ((attributes & RTTI.BCD_NONPOLYMORPHIC) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }
                                s += "BCD_NONPOLYMORPHIC";
                                b = true;
                            }
                        };
                        {
                            if ((attributes & RTTI.BCD_HASPCHD) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }
                                s += "BCD_HASPCHD";
                                b = true;
                            }
                        };

                        Bytes.SetComment(ea, s, true);
                    }
                }

                // Give it a label
                if (!Bytes.HasName(bcd))
                {
                    // Name::`RTTI Base Class Descriptor at (0, -1, 0, 0)'
                    string buffer = string.Empty, buffer1 = string.Empty, buffer2 = string.Empty, buffer3 = string.Empty, buffer4 = string.Empty;
                    buffer1 = RTTI.MangleNumber(ida_get_32bit(bcd + RTTIBaseClassDescriptor.OffsetOfPmd() + PMD.OffsetOfMdisp()), buffer1);
                    buffer2 = RTTI.MangleNumber(ida_get_32bit(bcd + RTTIBaseClassDescriptor.OffsetOfPmd() + PMD.OffsetOfPdisp()), buffer2);
                    buffer3 = RTTI.MangleNumber(ida_get_32bit(bcd + RTTIBaseClassDescriptor.OffsetOfPmd() + PMD.OffsetOfVdisp()), buffer3);
                    buffer4 = RTTI.MangleNumber(attributes, buffer4);
                    buffer = string.Format("??_R1{0}{1}{2}{3}{4}8)", buffer1, buffer2, buffer3, buffer4, baseClassName);
                    Bytes.SetName(bcd, buffer);
                }
            }
            else
                Debugger.Break();
        }
    }

    public struct RTTIClassHierarchyDescriptor
    {
        uint signature;         // 00 Zero until loaded
        uint attributes;        // 04 Flags
        uint numBaseClasses;	// 08 Number of classes in the following 'baseClassArray'
        uint baseClassArray;    // 0C *X64 int32 offset to _RTTIBaseClassArray*

        public static ulong OffsetOfSignature() { return 0; }
        public static ulong OffsetOfAttributes() { return 4; }
        public static ulong OffsetOfNumBaseClasses() { return 4 + 4; }
        public static ulong OffsetOfBaseClassArray() { return 4 + 4 + 4; }
        public static uint Size() { return 4 + 4 + 4 + 4; }

        public static bool IsValid(EaT chd, EaT colBase64 = 0)
        {
            // TRUE if we've already seen it
            if (ClassInformer.chdSet.Contains(chd))
                return true;

            if (ida_is_loaded(chd))
            {
                // signature should be zero statically
                uint signature = 0xffffffff;
                if (Bytes.GetVerify32((chd + RTTIClassHierarchyDescriptor.OffsetOfSignature()), ref signature))
                {
                    if (signature == 0)
                    {
                        // Check attributes flags
                        uint attributes = 0xffffffff;
                        if (Bytes.GetVerify32((chd + RTTIClassHierarchyDescriptor.OffsetOfAttributes()), ref attributes))
                        {
                            // Valid flags are the lower nibble only
                            if ((attributes & 0xFFFFFFF0) == 0)
                            {
                                // Should have at least one base class
                                uint numBaseClasses = 0;
                                if (Bytes.GetVerify32((chd + RTTIClassHierarchyDescriptor.OffsetOfNumBaseClasses()), ref numBaseClasses))
                                {
                                    if (numBaseClasses >= 1)
                                    {
                                        uint baseClassArrayOffset = ida_get_32bit(chd + RTTIClassHierarchyDescriptor.OffsetOfBaseClassArray());
                                        EaT baseClassArray = (colBase64 + (UInt64)baseClassArrayOffset);

                                        if (ida_is_loaded(baseClassArray))
                                        {
                                            EaT baseClassDescriptor = (colBase64 + (UInt64)ida_get_32bit(baseClassArray));
                                            return (RTTIBaseClassDescriptor.IsValid(baseClassDescriptor, colBase64));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        public static void TryStruct(EaT chd, EaT colBase64)
        {
            if (ClassInformer.chdSet.Contains(chd))
            {
                return;
            }
            else
            {
                ClassInformer.chdSet.Add(chd);
            }

            if (ida_is_loaded(chd))
            {
                // Place CHD
                RTTI.TryStructRTTI(chd, (UInt64)TypeIds.s_ClassHierarchyDescriptor_ID);

                // Place attributes comment
                uint attributes = ida_get_32bit(chd + RTTIClassHierarchyDescriptor.OffsetOfAttributes());
                if (attributes != 0)
                {
                    if (!ClassInformer.OptionPlaceStructs)
                    {
                        EaT ea = (chd + RTTIClassHierarchyDescriptor.OffsetOfAttributes());
                        if (!Bytes.HasComment(ea))
                        {
                            string s = string.Empty;
                            bool b = false;
                            if ((attributes & DefineConstants.CHD_MULTINH) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }

                                s += "CHD_MULTINH";
                                b = true;
                            }

                            if ((attributes & DefineConstants.CHD_VIRTINH) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }

                                s += "CHD_VIRTINH";
                                b = true;
                            }

                            if ((attributes & DefineConstants.CHD_AMBIGUOUS) != 0)
                            {
                                if (b)
                                {
                                    s += " | ";
                                }

                                s += "CHD_AMBIGUOUS";
                                b = true;
                            }

                            Bytes.SetComment(ea, s, true);
                        }
                    }
                }

                // ---- Place BCD's ----
                uint numBaseClasses = 0;
                if (Bytes.GetVerify32((chd + RTTIClassHierarchyDescriptor.OffsetOfNumBaseClasses()), ref numBaseClasses))
                {
                    EaT baseClassArray;

                    uint baseClassArrayOffset = ida_get_32bit(chd + RTTIClassHierarchyDescriptor.OffsetOfBaseClassArray());
                    baseClassArray = (colBase64 + (UInt64)baseClassArrayOffset);

                    EaT ea = (chd + RTTIClassHierarchyDescriptor.OffsetOfBaseClassArray());
                    if (!Bytes.HasComment(ea))
                    {
                        string buffer = string.Format($"0x{baseClassArray:X16}");
                        Bytes.SetComment(ea, buffer, true);
                    }

                    // to continue
                    if (baseClassArray != 0 && (baseClassArray != DefineConstants.BADADDR))
                    {
                        if (numBaseClasses > 1)
                        {
                            //int digits = (int)strlen(_itoa(numBaseClasses, format, 10));
                            //if (digits > 1)
                            //    _snprintf_s(format, sizeof(format), SIZESTR(format), "  BaseClass[%%0%dd] 0x%%016I64X", digits);
                            //else
                            //    strcpy_s(format, sizeof(format), "  BaseClass[%d] 0x%016I64X");
                        }

                        //for (Globals.uint i = 0; i < numBaseClasses; i++, baseClassArray += sizeof(EXTERNC)) // getPtrSize()
                        //{
                        //    string baseClassName = new string(new char[DefineConstants.MAXSTR]);
                        //    fixDword(baseClassArray);
                        //    uint bcOffset = get_32bit(baseClassArray);
                        //    ea_t bcd = (colBase64 + (ulong)bcOffset);

                        //    // Add index comment to to it
                        //    if (!Globals.hasComment(new ea_t(baseClassArray)))
                        //    {
                        //        if (numBaseClasses == 1)
                        //        {
                        //            string buffer = new string(new char[DefineConstants.MAXSTR]);
                        //            sprintf_s(buffer, sizeof(char), "  BaseClass 0x" EAFORMAT, bcd);
                        //            setComment(baseClassArray, buffer, false);
                        //        }
                        //        else
                        //        {
                        //            string buffer = new string(new char[DefineConstants.MAXSTR]);
                        //            _snprintf_s(buffer, sizeof(char), SIZESTR(buffer), format, i, bcd);
                        //            setComment(baseClassArray, buffer, DefineConstants.false);
                        //        }
                        //    }

                        //    // Place BCD struct, and grab the base class name
                        //    _RTTIBaseClassDescriptor.tryStruct(new ea_t(bcd), baseClassName, new ea_t(colBase64));

                        //}

                        //// Now we have the base class name, name and label some things
                        //if (i == 0)
                        //{
                        //    // Set array name
                        //    if (!Globals.hasName(new ea_t(baseClassArray)))
                        //    {
                        //        // ??_R2A@@8 = A::`RTTI Base Class Array'
                        //        string mangledName = new string(new char[DefineConstants.MAXSTR]);
                        //        _snprintf_s(mangledName, sizeof(char), SIZESTR(mangledName), Globals.FORMAT_RTTI_BCA, baseClassName);
                        //        setName(baseClassArray, mangledName);
                        //    }

                        //    // Add a spacing comment line above us
                        //    if (!hasAnteriorComment(baseClassArray))
                        //    {
                        //        setAnteriorComment(baseClassArray, "");
                        //    }

                        //    // Set CHD name
                        //    if (!Globals.hasName(new ea_t(chd)))
                        //    {
                        //        // A::`RTTI Class Hierarchy Descriptor'
                        //        string mangledName = new string(new char[DefineConstants.MAXSTR]);
                        //        _snprintf_s(mangledName, sizeof(char), SIZESTR(mangledName), Globals.FORMAT_RTTI_CHD, baseClassName);
                        //        setName(chd, mangledName);
                        //    }
                        //}
                    }

                    // Make following DWORD if it's bytes are zeros
                    if (numBaseClasses > 0)
                    {
                        if (ida_is_loaded(baseClassArray))
                        {
                            if (ida_get_32bit(baseClassArray) == 0)
                            {
                                Bytes.FixDword(baseClassArray);
                            }
                        }
                    }
                }
                else
                {
                    Debugger.Break();
                }
            }
            else
            {
                Debugger.Break();
            }
        }
    };

    public struct RTTICompleteObjectLocator
    {
        uint Signature;             // 00 32bit zero, 64bit one, until loaded
        uint Offset;                // 04 Offset of this vftable in the complete class
        uint CdOffset;              // 08 Constructor displacement offset
        uint TypeDescriptor;        // 0C (type_info *) of the complete class  *X64 int32 offset
        uint ClassDescriptor;       // 10 (_RTTIClassHierarchyDescriptor *) Describes inheritance hierarchy  *X64 int32 offset
        uint ObjectBase;            // 14 Object base offset (base = ptr col - objectBase)

        public static ulong OffsetOfSignature() { return 0; }
        public static ulong OffsetOfOffset() { return 4; }
        public static ulong OffsetOfCdOffset() { return 4 + 4; }
        public static ulong OffsetOfTypeDescriptor() { return 4 + 4 + 4; }
        public static ulong OffsetOfClassDescriptor() { return 4 + 4 + 4 + 4; }
        public static ulong OffsetOfObjectBase() { return 4 + 4 + 4 + 4 + 4; }
        public static uint Size()
        {
            return 0x18;
        }

        public static bool IsValid(EaT col)
        {
            if (ida_is_loaded(col))
            {
                // Check signature
                uint signature = 0xffffffff;
                if (Bytes.GetVerify32((col + RTTICompleteObjectLocator.OffsetOfSignature()), ref signature))
                {
                    if (signature == 1)
                    {
                        // TODO: Can any of these be zero and still be valid?
                        uint objectLocator = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfObjectBase());
                        if (objectLocator != 0)
                        {
                            uint tdOffset = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfTypeDescriptor());
                            if (tdOffset != 0)
                            {
                                uint cdOffset = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfClassDescriptor());
                                if (cdOffset != 0)
                                {
                                    EaT colBase = (col - (UInt64)objectLocator);
                                    EaT typeInfo = (colBase + (UInt64)tdOffset);
                                    //PluginBase.WriteDebugMessage($"  test TypeInfo.IsValid(0x{typeInfo:X})");
                                    if (TypeInfo.IsValid(typeInfo))
                                    {
                                        EaT classDescriptor = (colBase + (UInt64)cdOffset);
                                        //PluginBase.WriteDebugMessage($"  test RTTIClassHierarchyDescriptor.IsValid(0x{col:X}) 0x{typeInfo:X} 0x{classDescriptor:X}");
                                        if (RTTIClassHierarchyDescriptor.IsValid(classDescriptor, colBase))
                                        {
                                            //PluginBase.WriteDebugMessage($"  RTTICompleteObjectLocator.IsValid({col:X16}) {typeInfo:X16} {classDescriptor:X16}");
                                            //PluginBase.WriteDebugMessage($"{col:X16} {typeInfo:X16} {classDescriptor:X16}\n");
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        // Same as above but from an already validated typeInfo perspective
        bool IsValid2(EaT col)
        {
            // 'signature' should be zero
            uint signature = 0xffffffff;
            if (Bytes.GetVerify32((col + RTTICompleteObjectLocator.OffsetOfSignature()), ref signature))
            {
                if (signature == 0)
                {
                    // Verify CHD
                    EaT classDescriptor = Bytes.GetEa(col + RTTICompleteObjectLocator.OffsetOfClassDescriptor());
                    if (classDescriptor != 0 && (classDescriptor != DefineConstants.BADADDR))
                        return (RTTIClassHierarchyDescriptor.IsValid(classDescriptor));

                    return (false);
                }

                return (false);
            }

            return (false);
        }

        public static bool TryStruct(EaT col)
        {
            if (!Bytes.HasName(col))
            {
                RTTI.TryStructRTTI(col, (TidT)TypeIds.s_CompleteObjectLocator_ID);

                uint tdOffset = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfTypeDescriptor());
                uint cdOffset = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfClassDescriptor());
                uint objectLocator = ida_get_32bit(col + RTTICompleteObjectLocator.OffsetOfObjectBase());
                EaT colBase = (col - (UInt64)objectLocator);
                EaT typeInfo = (colBase + (UInt64)tdOffset);
                TypeInfo.TryStruct(typeInfo);
                EaT classDescriptor = (colBase + (UInt64)cdOffset);
                RTTIClassHierarchyDescriptor.TryStruct(classDescriptor, colBase);

                // Set absolute address comments
                EaT ea = (col + RTTICompleteObjectLocator.OffsetOfTypeDescriptor());
                if (!Bytes.HasComment(ea))
                {
                    string buffer = string.Format($"0x{typeInfo:X16}");
                    Bytes.SetComment(ea, buffer, true);
                }

                ea = (col + RTTICompleteObjectLocator.OffsetOfClassDescriptor());
                if (!Bytes.HasComment(ea))
                {
                    string buffer = string.Format($"0x{classDescriptor:X16}");
                    Bytes.SetComment(ea, buffer, true);
                }

                return true;
            }

            return false;
        }
    };
}
