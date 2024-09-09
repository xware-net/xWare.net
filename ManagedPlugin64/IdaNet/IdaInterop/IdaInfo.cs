using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using ea_t = System.UInt64;
using sel_t = System.UInt64;
using size_t = System.UInt64;
using asize_t = System.UInt64;
using adiff_t = System.Int64;
using uval_t = System.UInt64;
using System.Runtime.InteropServices;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    // Known input file formats (kept in \inf{filetype}):
    public enum filetype_t
    {
        f_EXE_old, //< MS DOS EXE File
        f_COM_old, //< MS DOS COM File
        f_BIN, //< Binary File
        f_DRV, //< MS DOS Driver
        f_WIN, //< New Executable (NE)
        f_HEX, //< Intel Hex Object File
        f_MEX, //< MOS Technology Hex Object File
        f_LX, //< Linear Executable (LX)
        f_LE, //< Linear Executable (LE)
        f_NLM, //< Netware Loadable Module (NLM)
        f_COFF, //< Common Object File Format (COFF)
        f_PE, //< Portable Executable (PE)
        f_OMF, //< Object Module Format
        f_SREC, //< R-records
        f_ZIP, //< ZIP file (this file is never loaded to IDA database)
        f_OMFLIB, //< Library of OMF Modules
        f_AR, //< ar library
        f_LOADER, //< file is loaded using LOADER DLL
        f_ELF, //< Executable and Linkable Format (ELF)
        f_W32RUN, //< Watcom DOS32 Extender (W32RUN)
        f_AOUT, //< Linux a.out (AOUT)
        f_PRC, //< PalmPilot program file
        f_EXE, //< MS DOS EXE File
        f_COM, //< MS DOS COM File
        f_AIXAR, //< AIX ar library
        f_MACHO, //< Mac OS X
        f_PSXOBJ //< Sony Playstation PSX object file
    }

    public enum comp_t : byte
    {
        COMP_MASK = 0x0F,
        COMP_UNK = 0x00,      ///< Unknown
        COMP_MS = 0x01,      ///< Visual C++
        COMP_BC = 0x02,      ///< Borland C++
        COMP_WATCOM = 0x03,      ///< Watcom C++
        COMP_GNU = 0x06,      ///< GNU C++
        COMP_VISAGE = 0x07,      ///< Visual Age C++
        COMP_BP = 0x08,      ///< Delphi
        COMP_UNSURE = 0x80,      ///< uncertain compiler id
    }

    public enum cm_t : byte
    {
        CM_MASK = 0x03,
        CM_UNKNOWN = 0x00,  ///< unknown
        CM_N8_F16 = 0x01,  ///< if sizeof(int)<=2: near 1 byte, far 2 bytes
        CM_N64 = 0x01,  ///< if sizeof(int)>2: near 8 bytes, far 8 bytes
        CM_N16_F32 = 0x02,  ///< near 2 bytes, far 4 bytes
        CM_N32_F48 = 0x03,  ///< near 4 bytes, far 6 bytes

        //@}
        /// \defgroup CM_M_ Model
        //@{
        CM_M_MASK = 0x0C,
        CM_M_NN = 0x00,  ///< small:   code=near, data=near (or unknown if CM_UNKNOWN)
        CM_M_FF = 0x04,  ///< large:   code=far, data=far
        CM_M_NF = 0x08,  ///< compact: code=near, data=far
        CM_M_FN = 0x0C,  ///< medium:  code=far, data=near

        /// Does the given model specify far code?.
        /// \defgroup CM_CC_ Calling convention
        CM_CC_MASK = 0xF0,
        CM_CC_INVALID = 0x00,  ///< this value is invalid
        CM_CC_UNKNOWN = 0x10,  ///< unknown calling convention
        CM_CC_VOIDARG = 0x20,  ///< function without arguments
                               ///< if has other cc and argnum == 0,
                               ///< represent as f() - unknown list
        CM_CC_CDECL = 0x30,  ///< stack
        CM_CC_ELLIPSIS = 0x40,  ///< cdecl + ellipsis
        CM_CC_STDCALL = 0x50,  ///< stack, purged
        CM_CC_PASCAL = 0x60,  ///< stack, purged, reverse order of args
        CM_CC_FASTCALL = 0x70,  ///< stack, purged (x86), first args are in regs (compiler-dependent)
        CM_CC_THISCALL = 0x80,  ///< stack, purged (x86), first arg is in reg (compiler-dependent)
        CM_CC_MANUAL = 0x90,  ///< special case for compiler specific (not used)
        CM_CC_SPOILED = 0xA0,  ///< This is NOT a cc! Mark of __spoil record
                               ///< the low nibble is count and after n {spoilreg_t}
                               ///< present real cm_t byte. if n == BFA_FUNC_MARKER,
                               ///< the next byte is the function attribute byte.
        CM_CC_GOLANG = 0xB0,  ///< GO: arguments and return value in stack
        CM_CC_RESERVE3 = 0xC0,
        CM_CC_SPECIALE = 0xD0,  ///< ::CM_CC_SPECIAL with ellipsis
        CM_CC_SPECIALP = 0xE0,  ///< Equal to ::CM_CC_SPECIAL, but with purged stack
        CM_CC_SPECIAL = 0xF0,  ///< usercall: locations of all arguments
                               ///< and the return value are explicitly specified
    }

    // Information about the target compiler
    public class compiler_info_t
    {
        public byte id = 0; //< compiler id (see \ref COMP_)
        public byte cm = 0; //< memory model and calling convention (see \ref CM_)
        public byte size_i = 0; //< sizeof(int)
        public byte size_b = 0; //< sizeof(bool)
        public byte size_e = 0; //< sizeof(enum)
        public byte defalign = 0; //< default alignment for structures
        public byte size_s = 0; //< short
        public byte size_l = 0; //< long
        public byte size_ll = 0; //< longlong
        public byte size_ldbl = 0; //< longdouble (if different from \ph{tbyte_size})

        public compiler_info_t() 
        { 
        }

        public compiler_info_t(byte[] other)
        {
            this.id = other[0];
            this.cm = other[1];
            this.size_i = other[2];
            this.size_b = other[3];
            this.size_e = other[4];
            this.defalign = other[5];
            this.size_s = other[6];
            this.size_l = other[7];
            this.size_ll = other[8];
            this.size_ldbl = other[9];
        }

        public override string ToString()
        {
            return string.Format($"(id={Enum.GetName(typeof(comp_t), id & (byte)comp_t.COMP_MASK)}, cm={((cm_t)cm).Stringify()}, size_i={size_i}, size_b={size_b}, size_e={size_e}, defalign={defalign}, size_s={size_s}, size_l={size_l}, size_ll={size_ll}, size_ldbl={size_ldbl})");
        }
    }

    // Storage types for flag bits
    public enum storage_type_t
    {
        STT_CUR = -1, //< use current storage type (may be used only as a function argument)
        STT_VA = 0, //< regular storage: virtual arrays, an explicit flag for each byte
        STT_MM = 1, //< memory map: sparse storage. useful for huge objects
        STT_DBG = 2 //< memory map: temporary debugger storage. used internally
    }

    public class IdaInfo
    {
        public string tag; //[DefineConstants.IDAINFO_TAG_SIZE];
        public char zero;       //< this field is not present in the database
        public ushort version;  //< Version of database

        public string procname; //[DefineConstants.IDAINFO_PROCNAME_SIZE]; 
        public ushort s_genflags; //< \ref INFFL_
                                  // \defgroup INFFL_ General idainfo flags
                                  // Used by idainfo::s_genflags

        public uint lflags; //< \ref LFLG_
                            // \defgroup LFLG_ Misc. database flags
                            // used by idainfo::lflags

        public uint database_change_count; //< incremented after each byte and regular
                                           //< segment modifications

        public ushort filetype; //< The input file type

        public ushort ostype; //< OS type the program is for
                              //< bit definitions in libfuncs.hpp

        public ushort apptype; //< Application type
                               //< bit definitions in libfuncs.hpp

        public byte asmtype; //< target assembler number

        public byte specsegs; //< What format do special segments use? 0-unspecified, 4-entries are 4 bytes, 8- entries are 8 bytes.

        public uint af; //< \ref AF_
                        // \defgroup AF_ Analysis flags
                        // used by idainfo::af

        public uint af2; //< \ref AF2_
                         // \defgroup AF2_ Analysis flags 2
                         // Used by idainfo::af2

        public asize_t baseaddr; // = new asize_t(); //< base address of the program (paragraphs)
        public sel_t start_ss; // = new sel_t(); //< selector of the initial stack segment
        public sel_t start_cs; // = new sel_t(); //< selector of the segment with the main entry point
        public ea_t start_ip; // = new ea_t(); //< IP register value at the start of
                              //< program execution
        public ea_t start_ea; // = new ea_t(); //< Linear address of program entry point
        public ea_t start_sp; // = new ea_t(); //< SP register value at the start of
                              //< program execution
        public ea_t main; // = new ea_t(); //< address of main()
        public ea_t min_ea; // = new ea_t(); //< current limits of program
        public ea_t max_ea; // = new ea_t(); //< maxEA is excluded
        public ea_t omin_ea; // = new ea_t(); //< original minEA (is set after loading the input file)
        public ea_t omax_ea; // = new ea_t(); //< original maxEA (is set after loading the input file)

        public ea_t lowoff; // = new ea_t(); //< Low  limit for offsets
                            //< (used in calculation of 'void' operands)
        public ea_t highoff; // = new ea_t(); //< High limit for offsets
                             //< (used in calculation of 'void' operands)

        public asize_t maxref; // = new asize_t(); //< Max tail for references

        public RangeT privrange; // = new Range(); //< Range of addresses reserved for internal use.
                                //< Initially (MAXADDR, MAXADDR+0x800000)
        public adiff_t netdelta; // = new adiff_t(); //< Delta value to be added to all adresses for mapping to netnodes.
                                 //< Initially 0

        // CROSS REFERENCES
        public byte xrefnum; //< Number of references to generate
                             //< in the disassembly listing
                             //< 0 - xrefs won't be generated at all
        public byte type_xrefnum; //< Number of references to generate
                                  //< in the struct & enum windows
                                  //< 0 - xrefs won't be generated at all
        public byte refcmtnum; //< Number of comment lines to
                               //< generate for refs to string literals
                               //< or demangled names
                               //< 0 - such comments won't be
                               //< generated at all
        public byte s_xrefflag; //< \ref SW_X
                                // \defgroup SW_X Xref options
                                // Used by idainfo::s_xrefflag

        // NAMES
        public ushort max_autoname_len; //< max autogenerated name length (without zero byte)
        public sbyte nametype; //< \ref NM_
                               // \defgroup NM_ Dummy names representation types
                               // Used by idainfo::nametype

        public uint short_demnames; //< short form of demangled names
        public uint long_demnames; //< long form of demangled names
                                   //< see demangle.h for definitions
        public byte demnames; //< \ref DEMNAM_
                              // \defgroup DEMNAM_ Demangled name flags
                              // used by idainfo::demnames

        public byte listnames; //< \ref LN_
                               // \defgroup LN_ Name list options
                               // Used by idainfo::listnames

        // DISASSEMBLY LISTING DETAILS
        public byte indent; //< Indentation for instructions
        public byte comment; //< Indentation for comments
        public ushort margin; //< max length of data lines
        public ushort lenxref; //< max length of line with xrefs
        public uint outflags; //< \ref OFLG_
                              // \defgroup OFLG_ output flags
                              // used by idainfo::outflags

        public byte s_cmtflg; //< \ref SCF_
                              // \defgroup SCF_ Comment options
                              // Used by idainfo::s_cmtflg

        public byte s_limiter; //< \ref LMT_
                               // \defgroup LMT_ Delimiter options
                               // Used by idainfo::s_limiter

        public short bin_prefix_size; //< # of instruction bytes (opcodes) to show in line prefix
        public byte s_prefflag; //< \ref PREF_
                                // \defgroup PREF_ Line prefix options
                                // Used by idainfo::s_prefflag

        // STRING LITERALS
        public byte strlit_flags; //< \ref STRF_
                                  // \defgroup STRF_ string literal flags
                                  // Used by idainfo::strlit_flags

        public byte strlit_break; //< string literal line break symbol
        public sbyte strlit_zeroes; //< leading zeroes
        public int strtype; //< current ascii string type
                            //< see nalt.hpp for string types
        public string strlit_pref; //[DefineConstants.IDAINFO_STRLIT_PREF_SIZE];

        public asize_t strlit_sernum; // = new asize_t(); //< serial number

        // DATA ITEMS
        public asize_t datatypes; // = new asize_t(); //< data types allowed in data carousel

        // COMPILER
        public compiler_info_t cc; //< Target compiler
        public uint abibits; //< ABI features. Depends on info returned by get_abi_name()
                             //< Processor modules may modify them in set_compiler

        // \defgroup ABI_ abi options
        // Used by idainfo::abibits

        public UInt32 appcall_options;               ///< appcall options, see idd.hpp

        public static IdaInfo GetIdaInfo()
        {
            IdaInfo idaInfo = new IdaInfo();

            idaInfo.version = IdaPlusPlus.IdaInterop.ida_inf_get_version();
            int requiredSize = 16;
            IntPtr nativeBuffer = Marshal.AllocCoTaskMem((int)requiredSize);
            ida_inf_get_procname(nativeBuffer, 16);
            idaInfo.procname = Marshal.PtrToStringAnsi(nativeBuffer, (int)requiredSize);
            Marshal.FreeCoTaskMem(nativeBuffer);
            // remove ending nulls
            int ix = idaInfo.procname.IndexOf('\x00');
            if (ix != -1)
                idaInfo.procname = idaInfo.procname.Substring(0, ix);

            idaInfo.s_genflags = ida_inf_get_genflags();
            idaInfo.lflags = ida_inf_get_lflags();
            idaInfo.database_change_count = ida_inf_get_database_change_count();
            idaInfo.filetype = ida_inf_get_filetype();
            idaInfo.ostype = ida_inf_get_ostype();
            idaInfo.asmtype = ida_inf_get_asmtype();
            idaInfo.specsegs = ida_inf_get_specsegs();
            idaInfo.af = ida_inf_get_af();
            idaInfo.af2 = ida_inf_get_af2();
            idaInfo.baseaddr = ida_inf_get_baseaddr();
            idaInfo.start_ss = ida_inf_get_start_ss();
            idaInfo.start_cs = ida_inf_get_start_cs();
            idaInfo.start_ip = ida_inf_get_start_ip();
            idaInfo.start_ea = ida_inf_get_start_ea();
            idaInfo.start_sp = ida_inf_get_start_sp();
            idaInfo.main = ida_inf_get_main();
            idaInfo.min_ea = ida_inf_get_min_ea();
            idaInfo.max_ea = ida_inf_get_max_ea();
            idaInfo.omin_ea = ida_inf_get_omin_ea();
            idaInfo.omax_ea = ida_inf_get_omax_ea();
            idaInfo.lowoff = ida_inf_get_lowoff();
            idaInfo.highoff = ida_inf_get_highoff();
            idaInfo.maxref = ida_inf_get_maxref();
            idaInfo.privrange = new RangeT();
            idaInfo.privrange.start_ea = ida_inf_get_privrange_start_ea();
            idaInfo.privrange.end_ea = ida_inf_get_privrange_end_ea();
            idaInfo.netdelta = ida_inf_get_netdelta();
            idaInfo.xrefnum = ida_inf_get_xrefnum();
            idaInfo.type_xrefnum = ida_inf_get_type_xrefnum();
            idaInfo.refcmtnum = ida_inf_get_refcmtnum();
            idaInfo.s_xrefflag = ida_inf_get_xrefflag();
            idaInfo.max_autoname_len = ida_inf_get_max_autoname_len();
            idaInfo.nametype = ida_inf_get_nametype();
            idaInfo.short_demnames = ida_inf_get_short_demnames();
            idaInfo.long_demnames = ida_inf_get_long_demnames();
            idaInfo.demnames = ida_inf_get_demnames();
            idaInfo.listnames = ida_inf_get_listnames();
            idaInfo.indent = ida_inf_get_indent();
            idaInfo.comment = ida_inf_get_comment();
            idaInfo.margin = ida_inf_get_margin();
            idaInfo.lenxref = ida_inf_get_lenxref();
            idaInfo.outflags = ida_inf_get_outflags();
            idaInfo.s_limiter = ida_inf_get_limiter();
            idaInfo.bin_prefix_size = ida_inf_get_bin_prefix_size();
            idaInfo.s_prefflag = ida_inf_get_prefflag();
            idaInfo.strlit_flags = ida_inf_get_strlit_flags();
            idaInfo.strlit_break = ida_inf_get_strlit_break();
            idaInfo.strlit_zeroes = ida_inf_get_strlit_zeroes();
            idaInfo.strtype = ida_inf_get_strtype();
            // idaInfo.strlit_pref = ida_inf_get_strlit_pref();
            idaInfo.strlit_sernum = ida_inf_get_strlit_sernum();
            idaInfo.datatypes = ida_inf_get_datatypes();
            idaInfo.cc = new compiler_info_t();
            idaInfo.cc.id = ida_inf_get_cc_id();
            idaInfo.cc.cm = ida_inf_get_cc_cm();
            idaInfo.cc.size_i = ida_inf_get_cc_size_i();
            idaInfo.cc.size_b = ida_inf_get_cc_size_b();
            idaInfo.cc.size_e = ida_inf_get_cc_size_e();
            idaInfo.cc.defalign = ida_inf_get_cc_defalign();
            idaInfo.cc.size_s = ida_inf_get_cc_size_s();
            idaInfo.cc.size_l = ida_inf_get_cc_size_l();
            idaInfo.cc.size_ll = ida_inf_get_cc_size_ll();
            idaInfo.cc.size_ldbl = ida_inf_get_cc_size_ldbl();
            idaInfo.abibits = ida_inf_get_abibits();
            idaInfo.appcall_options = ida_inf_get_appcall_options();
            return idaInfo;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"version={version}");
            sb.AppendLine($"procname={procname}");
            sb.AppendLine($"s_genflags=0x{s_genflags:X4} ({((InfoFlags)s_genflags).Stringify()})");
            sb.AppendLine($"lflags=0x{lflags:X8} ({((MiscDatabaseFlags)lflags).Stringify()})");
            sb.AppendLine($"database_change_count={database_change_count}");
            sb.AppendLine($"filetype=0x{filetype:X4} ({Enum.GetName(typeof(filetype_t), filetype)})");
            sb.AppendLine($"ostype=0x{ostype:X4}");
            sb.AppendLine($"asmtype={asmtype}");
            sb.AppendLine($"specsegs=0x{specsegs:X2}");
            sb.AppendLine($"af=0x{af:X8} ({((AnalysisFlags)af).Stringify()})");
            sb.AppendLine($"af2=0x{af2:X8} ({((AnalysisFlagsEx)af2).Stringify()})");
            sb.AppendLine($"baseaddr=0x{baseaddr:X16}");
            sb.AppendLine($"start_ss=0x{start_ss:X16}");
            sb.AppendLine($"start_cs=0x{start_cs:X16}");
            sb.AppendLine($"start_ip=0x{start_ip:X16}");
            sb.AppendLine($"start_ea=0x{start_ea:X16}");
            sb.AppendLine($"start_sp=0x{start_sp:X16}");
            sb.AppendLine($"main=0x{main:X16}");
            sb.AppendLine($"min_ea=0x{min_ea:X16}");
            sb.AppendLine($"max_ea=0x{max_ea:X16}");
            sb.AppendLine($"omin_ea=0x{omin_ea:X16}");
            sb.AppendLine($"omax_ea=0x{omax_ea:X16}");
            sb.AppendLine($"lowoff=0x{lowoff:X16}");
            sb.AppendLine($"highoff=0x{highoff:X16}");
            sb.AppendLine($"maxref=0x{maxref:X16}");
            sb.AppendLine($"privrange={privrange}");

            sb.AppendLine($"cc={cc.ToString()}");
            return sb.ToString();
        }
    }
}
