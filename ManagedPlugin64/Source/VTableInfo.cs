using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using ea_t = System.UInt64;
using sel_t = System.UInt64;
using size_t = System.UInt64;
using asize_t = System.UInt64;
using adiff_t = System.Int64;
using uval_t = System.UInt64;
using bgcolor_t = System.UInt32;

using IdaNet.IdaInterop;

using static IdaPlusPlus.IdaInterop;

namespace ManagedPlugin.Source
{
    public class VTableInfo
    {
        public string VTableName { get; set; }
        public ea_t ea_begin { get; set; }
        public ea_t ea_end { get; set; }
        public asize_t methodCount { get; set; }

        internal const uint FF_CODE = 0x00000600;  // Code
        internal const uint FF_DATA = 0x00000400;    // Data
        internal const uint FF_TAIL = 0x00000200;    // Tail; second, third (tail) byte of instruction or data
        internal const uint FF_UNK = 0x00000000;    // Unexplored
                                                    // * Data F0000000
        internal const uint DT_TYPE = 0xF0000000;   // Data type mask
        internal const uint FF_BYTE = 0x00000000;   // byte
        internal const uint FF_WORD = 0x10000000;   // word
        internal const uint FF_DWORD = 0x20000000;  // double word
        internal const uint FF_QWORD = 0x30000000;  // quad word
        internal const uint FF_TBYTE = 0x40000000; // triple byte
        internal const uint FF_STRLIT = 0x50000000;  // string literal
        internal const uint FF_STRUCT = 0x60000000;  // struct variable
        internal const uint FF_OWORD = 0x70000000;  // octal word/XMM word (16 bytes/128 bits)
        internal const uint FF_FLOAT = 0x80000000;  // float
        internal const uint FF_DOUBLE = 0x90000000;  // double
        internal const uint FF_PACKREAL = 0xA0000000;  // packed decimal real
        internal const uint FF_ALIGN = 0xB0000000;  // alignment directive
                                                    // 0xC0000000  // reserved
        internal const uint FF_CUSTOM = 0xD0000000;  // custom data type
        internal const uint FF_YWORD = 0xE0000000;  // YMM word (32 bytes/256 bits)
        internal const uint FF_ZWORD = 0xF0000000;  // ZMM word (64 bytes/512 bits)
                                                    // * Code F0000000
        internal const uint MS_CODE = 0xF0000000;    // Code type mask
        internal const uint FF_FUNC = 0x10000000;    // Function start
                                                     // 0x20000000LU    // Reserved
        internal const uint FF_IMMD = 0x40000000;    // Has Immediate value
        internal const uint FF_JUMP = 0x80000000;    // Has jump table or switch_info
                                                     // Instruction/Data operands 0F000000
        internal const uint MS_1TYPE = 0x0F000000;   // Mask for the type of other operands
        internal const uint FF_1VOID = 0x00000000;   // Void (unknown)
        internal const uint FF_1NUMH = 0x01000000;   // Hexadecimal number
        internal const uint FF_1NUMD = 0x02000000;   // Decimal number
        internal const uint FF_1CHAR = 0x03000000;   // Char ('x')
        internal const uint FF_1SEG = 0x04000000;   // Segment
        internal const uint FF_1OFF = 0x05000000;   // Offset
        internal const uint FF_1NUMB = 0x06000000;   // Binary number
        internal const uint FF_1NUMO = 0x07000000;   // Octal number
        internal const uint FF_1ENUM = 0x08000000;   // Enumeration
        internal const uint FF_1FOP = 0x09000000;   // Forced operand
        internal const uint FF_1STRO = 0x0A000000;   // Struct offset
        internal const uint FF_1STK = 0x0B000000;   // Stack variable
        internal const uint FF_1FLT = 0x0C000000;   // Floating pouint number
        internal const uint FF_1CUST = 0x0D000000;   // Custom representation

        internal const uint MS_0TYPE = 0x00F00000; // Mask for 1st arg typing
        internal const uint FF_0VOID = 0x00000000;   // Void (unknown)
        internal const uint FF_0NUMH = 0x00100000;   // Hexadecimal number
        internal const uint FF_0NUMD = 0x00200000;   // Decimal number
        internal const uint FF_0CHAR = 0x00300000;   // Char ('x')
        internal const uint FF_0SEG = 0x00400000;   // Segment
        internal const uint FF_0OFF = 0x00500000;   // Offset
        internal const uint FF_0NUMB = 0x00600000;   // Binary number
        internal const uint FF_0NUMO = 0x00700000;   // Octal number
        internal const uint FF_0ENUM = 0x00800000;   // Enumeration
        internal const uint FF_0FOP = 0x00900000;   // Forced operand
        internal const uint FF_0STRO = 0x00A00000;   // Struct offset
        internal const uint FF_0STK = 0x00B00000;   // Stack variable
        internal const uint FF_0FLT = 0x00C00000;   // Floating pouint number
        internal const uint FF_0CUST = 0x00D00000;   // Custom representation

        // State information 000FF800
        internal const uint MS_COMM = 0x000FF800;    // Mask of common bits
        internal const uint FF_FLOW = 0x00010000;    // Exec flow from prev instruction
        internal const uint FF_SIGN = 0x00020000;    // Inverted sign of operands
        internal const uint FF_BNOT = 0x00040000;    // Bitwise negation of operands
        internal const uint FF_UNUSED = 0x00080000;    // unused bit (was used for variable bytes)
        internal const uint FF_COMM = 0x00000800;    // Has comment 
        internal const uint FF_REF = 0x00001000;    // has references
        internal const uint FF_LINE = 0x00002000;    // Has next or prev lines 
        internal const uint FF_NAME = 0x00004000;    // Has name 
        internal const uint FF_LABL = 0x00008000;    // Has dummy name
                                                     // 000001FF
        internal const uint FF_IVL = 0x00000100;	// Has byte value in 000000FF

        static void idaFlags2String(uint f, ref string s, bool withValue)
        {
            s = string.Empty;
            //#define FTEST(_f) if(f & _f){ if(!first) s += ", "; s += #_f; first = FALSE; }

            // F0000000
            bool first = true;
            if (Bytes.IsData(f))
            {
                switch (f & DT_TYPE)
                {
                    case FF_BYTE: s += "FF_BYTE"; break;
                    case FF_WORD: s += "FF_WORD"; break;
                    case FF_DWORD: s += "FF_DWORD"; break;
                    case FF_QWORD: s += "FF_QWORD"; break;
                    case FF_TBYTE: s += "FF_TBYTE"; break;
                    case FF_STRLIT: s += "FF_STRLIT"; break;
                    case FF_STRUCT: s += "FF_STRUCT"; break;
                    case FF_OWORD: s += "FF_OWORD"; break;
                    case FF_FLOAT: s += "FF_FLOAT"; break;
                    case FF_DOUBLE: s += "FF_DOUBLE"; break;
                    case FF_PACKREAL: s += "FF_PACKREAL"; break;
                    case FF_ALIGN: s += "FF_ALIGN"; break;

                    case FF_CUSTOM: s += "FF_CUSTOM"; break;
                    case FF_YWORD: s += "FF_YWORD"; break;
                    case FF_ZWORD: s += "FF_ZWORD"; break;

                };

                first = false;
            }
            else
            if (Bytes.IsCode(f))
            {
                if ((f & MS_CODE) != 0)
                {
                    if ((f & FF_FUNC) != 0)
                    {
                        if (!first)
                            s += ", ";
                        s += "FF_FUNC";
                        first = false;
                    }

                    if ((f & FF_IMMD) != 0)
                    {
                        if (!first)
                            s += ", ";
                        s += "FF_IMMD";
                        first = false;
                    }

                    if ((f & FF_JUMP) != 0)
                    {
                        if (!first)
                            s += ", ";
                        s += "FF_JUMP";
                        first = false;
                    }
                }
            }

            // 0F000000
            if ((f & MS_1TYPE) != 0)
            {
                if (!first) s += ", ";
                switch (f & MS_1TYPE)
                {
                    //default: s += ",FF_1VOID"; break;
                    case FF_1NUMH: s += "FF_1NUMH"; break;
                    case FF_1NUMD: s += "FF_1NUMD"; break;
                    case FF_1CHAR: s += "FF_1CHAR"; break;
                    case FF_1SEG: s += "FF_1SEG"; break;
                    case FF_1OFF: s += "FF_1OFF"; break;
                    case FF_1NUMB: s += "FF_1NUMB"; break;
                    case FF_1NUMO: s += "FF_1NUMO"; break;
                    case FF_1ENUM: s += "FF_1ENUM"; break;
                    case FF_1FOP: s += "FF_1FOP"; break;
                    case FF_1STRO: s += "FF_1STRO"; break;
                    case FF_1STK: s += "FF_1STK"; break;
                    case FF_1FLT: s += "FF_1FLT"; break;
                    case FF_1CUST: s += "FF_1CUST"; break;
                };

                first = false;
            }

            // 00F00000
            if ((f & MS_0TYPE) != 0)
            {
                if (!first) s += ", ";
                switch (f & MS_0TYPE)
                {
                    //default: s += ",FF_0VOID"; break;
                    case FF_0NUMH: s += "FF_0NUMH"; break;
                    case FF_0NUMD: s += "FF_0NUMD"; break;
                    case FF_0CHAR: s += "FF_0CHAR"; break;
                    case FF_0SEG: s += "FF_0SEG"; break;
                    case FF_0OFF: s += "FF_0OFF"; break;
                    case FF_0NUMB: s += "FF_0NUMB"; break;
                    case FF_0NUMO: s += "FF_0NUMO"; break;
                    case FF_0ENUM: s += "FF_0ENUM"; break;
                    case FF_0FOP: s += "FF_0FOP"; break;
                    case FF_0STRO: s += "FF_0STRO"; break;
                    case FF_0STK: s += "FF_0STK"; break;
                    case FF_0FLT: s += "FF_0FLT"; break;
                    case FF_0CUST: s += "FF_0CUST"; break;
                };

                first = false;
            }

            // 000F0000
            if ((f & 0xF0000) != 0)
            {
                if ((f & FF_FLOW) != 0)
                {
                    if (!first)
                        s += ", ";
                    s += "FF_FLOW";
                    first = false;
                }

                if ((f & FF_SIGN) != 0)
                {
                    if (!first)
                        s += ", ";
                    s += "FF_SIGN";
                    first = false;
                }

                if ((f & FF_SIGN) != 0)
                {
                    if (!first)
                        s += ", ";
                    s += "FF_SIGN";
                    first = false;
                }

                if ((f & FF_UNUSED) != 0)
                {
                    if (!first)
                        s += ", ";
                    s += "FF_UNUSED";
                    first = false;
                }
            }

            // 0000F000
            if ((f & 0xF000) != 0)
            {
                if ((f & FF_REF) != 0)
                {
                    if (!first)
                        s += ", ";
                    s += "FF_REF";
                    first = false;
                }

                if ((f & FF_LINE) != 0)
                {
                    if (!first)
                        s += ", ";
                    s += "FF_LINE";
                    first = false;
                }

                if ((f & FF_NAME) != 0)
                {
                    if (!first)
                        s += ", ";
                    s += "FF_NAME";
                    first = false;
                }

                if ((f & FF_LABL) != 0)
                {
                    if (!first)
                        s += ", ";
                    s += "FF_LABL";
                    first = false;
                }
            }

            // 00000F00
            if (!first) s += ", ";
            switch (f & (FF_CODE | FF_DATA | FF_TAIL))
            {
                case FF_CODE: s += "FF_CODE"; break;
                case FF_DATA: s += "FF_DATA"; break;
                case FF_TAIL: s += "FF_TAIL"; break;
                default: s += "FF_UNK"; break;
            };

            first = false;
            if ((f & FF_COMM) != 0) s += ", FF_COMM";
            if ((f & FF_IVL) != 0) s += ", FF_IVL";

            // 000000FF optional value dump
            if (withValue && ((f & FF_IVL) != 0))
            {
                string buffer;
                buffer = string.Format($", value: {(f & 0xff):X2}");
                s += buffer;
            }
        }

        static void dumpFlags(ea_t ea, bool withValue = false)
        {
            string s = string.Empty;
            idaFlags2String(ida_get_flags(ea), ref s, withValue);
            PluginBase.WriteDebugMessage($"{ea:X16} Flags: {s}\n");
        }

        public static bool GetTableInfo(ea_t ea, ref VTableInfo info)
        {
            // Start of a vft should have an xref and a name (auto, or user, etc).
            // Ideal flags 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
            //dumpFlags(ea);
            uint flags = ida_get_flags(ea);
            if (Bytes.HasXref(flags) && Bytes.HasAnyName(flags) && (Bytes.IsEa(flags) || Bytes.IsUnknown(flags)))
            {
                info = new VTableInfo();

                // Get raw (auto-generated mangled, or user named) vft name
                //if (!get_name(DefineConstants.BADADDR, ea, info.name, SIZESTR(info.name)))
                //    msg(EAFORMAT" ** vftable::getTableInfo(): failed to get raw name!\n", ea);

                // Determine the vft's method count
                ea_t start = info.ea_begin = ea;
                while (true)
                {
                    // Should be an ea_t sized offset to a function here (could be unknown if dirty IDB)
                    // Ideal flags for 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
                    //PluginBase.WriteDebugMessage($"{ea:X16}\n");
                    //dumpFlags(ea);
                    uint indexFlags = ida_get_flags(ea);
                    if (!(Bytes.IsEa(indexFlags) || Bytes.IsUnknown(indexFlags)))
                    {
                        //PluginBase.WriteDebugMessage($" ******* 1\n");
                        break;
                    }

                    // Look at what this (assumed vftable index) points too
                    ea_t memberPtr = Bytes.GetEa(ea);
                    if (!(memberPtr != 0 && (memberPtr != DefineConstants.BADADDR)))
                    {
                        // vft's often have a trailing zero ea_t (alignment, or?), fix it
                        if (memberPtr == 0)
                        {
                            Bytes.FixEa(ea);
                        }

                        //PluginBase.WriteDebugMessage($" ******* 2\n");
                        break;
                    }

                    // Should see code for a good vft method here, but it could be dirty
                    uint flags1 = ida_get_flags(memberPtr);
                    if (!(Bytes.IsCode(flags1) || Bytes.IsUnknown(flags1)))
                    {
                        // New for version 2.5: there are rare cases where IDA hasn't fix unresolved bytes
                        // So except if the member pointer is in a code segment as a 2nd chance
                        IntPtr segP = ida_getseg(memberPtr);
                        if (segP != IntPtr.Zero)
                        {
                            var segment = new SegmentT(segP);
                            if (segment.type != SegmentType.SEG_CODE)
                            {
                                //PluginBase.WriteDebugMessage($" ******* 3\n");
                                break;
                            }
                        }
                        else
                        {
                            //PluginBase.WriteDebugMessage($" ******* 3.5\n");
                            break;
                        }
                    }

                    if (ea != start)
                    {
                        // If we see a ref after first index it's probably the beginning of the next vft or something else
                        if (Bytes.HasXref(indexFlags))
                        {
                            //PluginBase.WriteDebugMessage($" ******* 4\n");
                            break;
                        }

                        // If we see a COL here it must be the start of another vftable
                        if (RTTICompleteObjectLocator.IsValid(memberPtr))
                        {
                            //PluginBase.WriteDebugMessage($" ******* 5\n");
                            break;
                        }
                    }

                    // As needed fix ea_t pointer, and, or, missing code and function def here
                    Bytes.FixEa(ea);
                    Bytes.FixFunction(memberPtr);

                    ea += sizeof(ea_t); // ObjectExplorer.getPtrSize();
                };

                // Reached the presumed end of it
                if ((info.methodCount = ((ea - start) / sizeof(ea_t))) > 0)
                {
                    info.ea_end = ea;
                    //PluginBase.WriteDebugMessage($"{info.ea_begin:X16} - {info.ea_end:X16} c: {info.methodCount}");
                    //msg(" vftable: "EAFORMAT"-"EAFORMAT", methods: %d\n", rtInfo.eaStart, rtInfo.eaEnd, rtInfo.uMethods);
                    return (true);
                }
            }

            //dumpFlags(ea);
            return (false);
        }

        public bool IsValid(string name)
        {
            return name.StartsWith("??_7");
        }
    };

}
