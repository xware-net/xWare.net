//C++ TO C# CONVERTER TASK: Check to ensure that the necessary preprocessor flags are defined:
internal static class DefineConstants
{
    public const int IDA_SDK_VERSION = 760;
    public const ulong BADMEMSIZE = 0x7FFFFFFFFFFFFFFFUl;
    public const int MAXSTR = 1024;         //< maximum string size
    public const int __MF__ = 0;            //< byte sex of our platform (Most significant byte First).

    public const int IDAINFO_TAG_SIZE = 3;
    public const int IDAINFO_PROCNAME_SIZE = 16;
    public const int IDAINFO_STRLIT_PREF_SIZE = 16;

    public const int STRWIDTH_1B = 0;
    public const int STRWIDTH_2B = 1;
    public const int STRWIDTH_4B = 2;
    public const int STRWIDTH_MASK = 0x03;

    public const int STRLYT_TERMCHR = 0;
    public const int STRLYT_PASCAL1 = 1;
    public const int STRLYT_PASCAL2 = 2;
    public const int STRLYT_PASCAL4 = 3;
    public const int STRLYT_MASK = 0xFC;
    public const int STRLYT_SHIFT = 2;

    public const int STRTYPE_TERMCHR = STRWIDTH_1B | STRLYT_TERMCHR << STRLYT_SHIFT;
    public const int STRTYPE_C = STRTYPE_TERMCHR;


    public const int SREG_NUM = 16;
    public const int ADDSEG_NOSREG = 0x0001; //< set all default segment register values to #BADSEL
    public const int ADDSEG_OR_DIE = 0x0002; //< qexit() if can't add a segment
    public const int ADDSEG_NOTRUNC = 0x0004; //< don't truncate the new segment at the beginning of the next segment if they overlap.
    public const int ADDSEG_QUIET = 0x0008; //< silent mode, no "Adding segment..." in the messages window
    public const int ADDSEG_FILLGAP = 0x0010; //< fill gap between new segment and previous one.
    public const int ADDSEG_SPARSE = 0x0020; //< use sparse storage method for the new ranges
    public const int ADDSEG_NOAA = 0x0040; //< do not mark new segment for auto-analysis
    public const int ADDSEG_IDBENC = 0x0080; //< 'name' and 'sclass' are given in the IDB encoding;
    public const int SEGMOD_KILL = 0x0001; //< disable addresses if segment gets shrinked or deleted
    public const int SEGMOD_KEEP = 0x0002; //< keep information (code & data, etc)
    public const int SEGMOD_SILENT = 0x0004; //< be silent
    public const int SEGMOD_KEEP0 = 0x0008; //< flag for internal use, don't set
    public const int SEGMOD_KEEPSEL = 0x0010; //< do not try to delete unused selector
    public const int SEGMOD_NOMOVE = 0x0020; //< don't move info from the start of segment to the new start address
    public const int SEGMOD_SPARSE = 0x0040; //< use sparse storage if extending the segment
    public const int MSF_SILENT = 0x0001; //< don't display a "please wait" box on the screen
    public const int MSF_NOFIX = 0x0002; //< don't call the loader to fix relocations
    public const int MSF_LDKEEP = 0x0004; //< keep the loader in the memory (optimization)
    public const int MSF_FIXONCE = 0x0008; //< call loader only once with the special calling method.
    public const int MSF_PRIORITY = 0x0020; //< loader segments will overwrite any existing debugger segments when moved.
    public const int MSF_NETNODES = 0x0080; //< move netnodes instead of changing inf.netdelta (this is slower)
    public const int MOVE_SEGM_OK = 0; //< all ok
    public const int MOVE_SEGM_PARAM = -1; //< The specified segment does not exist
    public const int MOVE_SEGM_ROOM = -2; //< Not enough free room at the target address
    public const int MOVE_SEGM_IDP = -3; //< IDP module forbids moving the segment
    public const int MOVE_SEGM_CHUNK = -4; //< Too many chunks are defined, can't move
    public const int MOVE_SEGM_LOADER = -5; //< The segment has been moved but the loader complained
    public const int MOVE_SEGM_ODD = -6; //< Cannot move segments by an odd number of bytes
    public const int MOVE_SEGM_ORPHAN = -7; //< Orphan bytes hinder segment movement
    public const int MOVE_SEGM_DEBUG = -8; //< Debugger segments cannot be moved
    public const int CSS_OK = 0; //< ok
    public const int CSS_NODBG = -1; //< debugger is not running
    public const int CSS_NORANGE = -2; //< could not find corresponding memory range
    public const int CSS_NOMEM = -3; //< not enough memory (might be because the segment
    public const int CSS_BREAK = -4; //< memory reading process stopped by user
    public const int MAX_GROUPS = 8; //< max number of segment groups
    public const int MAX_SEGM_TRANSLATIONS = 64; //< max number of segment translations

    public const int GN_VISIBLE = 0x0001; ///< replace forbidden characters by SUBSTCHAR
	public const int GN_COLORED = 0x0002; ///< return colored name
	public const int GN_DEMANGLED = 0x0004; ///< return demangled name
	public const int GN_STRICT = 0x0008; ///< fail if cannot demangle
	public const int GN_SHORT = 0x0010; ///< use short form of demangled name
	public const int GN_LONG = 0x0020; ///< use long form of demangled name
	public const int GN_LOCAL = 0x0040; ///< try to get local name first; if failed, get global
	public const int GN_ISRET = 0x0080; ///< for dummy names: use retloc
	public const int GN_NOT_ISRET = 0x0100; ///< for dummy names: do not use retloc
	public const int GN_NOT_DUMMY = 0x0200; ///< do not return a dummy name

    public const int M_COMPILER = 0x70000000;// Compiler mask (0-unknown)
    public const int MT_MSCOMP = 0x10000000;  // 1 - microsoft/symantec
    public const int MT_BORLAN = 0x20000000;  // 2 - borland
    public const int MT_WATCOM = 0x30000000;  // 3 - watcom
    public const int MT_OTHER = 0x40000000;  // 4 - digital mars D language (start: _D)
                                             //   - apple Swift language (start: [_]_T)
                                             // !!! The following definitions must be last and in this order!
    public const int MT_GNU = 0x50000000;  // 5 - GNU - (over VA for autodetection)
    public const int MT_GCC3 = 0x60000000; // 6 - gcc-v3
                                           // In the short form this answer is possible
                                           // for GNU/VA as well, but gcc3 can be
                                           // explicitly requested only with it.
                                           // Autodetection works but not very reliable.
    public const int MT_VISAGE = 0x70000000;  // 7 - Visual Age - never autodetected
                                              // In the short form this answer means VA
                                              // or GNU. In the automatic mode GNU will
                                              // be used!

    // Flags to inhibit different parts of the demangled name
    public const int MNG_PTRMSK = 0x7;  // Memory model mask
                                        // DO NOT change order in this group (PtrType)
    public const int MNG_DEFNEAR = 0x0; // inhibit near, display everything else
    public const int MNG_DEFNEARANY = 0x1; // inhibit near/__ptr64, display everything else
    public const int MNG_DEFFAR = 0x2; // inhibit far, display everything else
    public const int MNG_NOPTRTYP16 = 0x3; // inhibit everything (disables vc7-extensions)
    public const int MNG_DEFHUGE = 0x4; // inhibit huge, display everything else
    public const int MNG_DEFPTR64 = 0x5; // inhibit __pt64, display everything else
                                         // ATT: in 64bit must be + MNG_NOTYPE|MNG_NOCALLC
    public const int MNG_DEFNONE = 0x6; // display everything
    public const int MNG_NOPTRTYP = 0x7; // inhibit everything
                                         //
    public const int MNG_NODEFINIT = 0x00000008; // Inhibit everything except the main name
                                                 // This flag is not recommended
                                                 // for __fastcall/__stdcall GCC3 names
                                                 // because there is a high probablity of
                                                 // incorrect demangling. Use it only when
                                                 // you are sure that the input is a
                                                 // cygwin/mingw function name
                                                 //
    public const int MNG_NOUNDERSCORE = 0x00000010; // Inhibit underscores in __ccall, __pascal... +
    public const int MNG_NOTYPE = 0x00000020; // Inhibit callc&based
    public const int MNG_NORETTYPE = 0x00000040; // Inhibit return type of functions
    public const int MNG_NOBASEDT = 0x00000080; // Inhibit base types
                                                //   NOTE: also inhibits "__linkproc__"
                                                //   NOTE: -"- 'implicit self types' (Swift)
    public const int MNG_NOCALLC = 0x00000100; // Inhibit __pascal/__ccall/etc
                                               //   NOTE: also inhibits "extern (cc)" (D)
    public const int MNG_NOPOSTFC = 0x00000200; // Inhibit postfix const
    public const int MNG_NOSCTYP = 0x00000400; // Inhibit public/private/protected
                                               //   NOTE: also inhibits in/out/lazy for args (D)
                                               //   NOTE: -"- dynamic/super/override/... (Swift)
    public const int MNG_NOTHROW = 0x00000800; // Inhibit throw description
                                               //   NOTE: also inhibits all funcattr (D)
    public const int MNG_NOSTVIR = 0x00001000; // Inhibit "static" & "virtual"
                                               //   NOTE: also inhibits (D) top-level procs (<=)
    public const int MNG_NOECSU = 0x00002000; // Inhibit class/struct/union/enum[/D:typedef]
    public const int MNG_NOCSVOL = 0x00004000; // Inhibit const/volatile/restrict
                                               //   NOTE: also inhibits __unaligned (vc)
                                               //   NOTE: also inhibits transaction_safe(gcc)
                                               //   NOTE: also inhibits shared/immutable (D)
                                               //   NOTE: also inhibits prefix/postfix/infix/inout (Swift)
    public const int MNG_NOCLOSUR = 0x00008000; // Inhibit __closure for borland
                                                //         'reabstract thunk' description (Swift)
    public const int MNG_NOUNALG = 0x00010000;// Inhibit __unaligned (see NOCSVOL)
                                              //   NOTE: also inhibit transaction_safe (see NOCSVOL)
    public const int MNG_NOMANAGE = 0x00020000; // Inhibit __pin/__box/__gc for ms(.net)
                                                //   NOTE: also inhibit archetype/witness (Swift)
                                                //   NOTE: also ingibit [abi:xxxx] (gcc3)
    public const int MNG_NOMODULE = 0x00040000;// Inhibit module names (Swift)
                                               //                       0x00080000
                                               //
    public const int MNG_SHORT_S = 0x00100000; // signed (int) is displayed as s(int)
    public const int MNG_SHORT_U = 0x00200000; // unsigned (int) is displayed as u(int)
    public const int MNG_ZPT_SPACE = 0x00400000; // Display space after comma in the arglist
                                                 //   NOTE: also spaces in name:type pair (Swift)
                                                 //         and around Swift return clause ->
    public const int MNG_DROP_IMP = 0x00800000;// Inhibit __declspec(dllimport)
                                               //
                                               //                       0x01000000
    public const int MNG_IGN_ANYWAY = 0x02000000; // Ingore '_nn' at the end of name
    public const int MNG_IGN_JMP = 0x04000000;// Ingore 'j_'  at the beginning of name
    public const int MNG_MOVE_JMP = 0x08000000; // Move 'j_' prefix to the demangled name
                                                // If both MNG_IGN_JMP and MNG_MOVE_JMP
                                                // are set then move the prefix only if
                                                // the name was not truncated
                                                //
    public const int MNG_COMPILER_MSK = 0x70000000; // Compiler mask (0-autodetect)

    public const int MNG_SHORT_FORM = (MNG_NOTYPE | MNG_NORETTYPE | MNG_NOPOSTFC | MNG_NOPTRTYP
      | MNG_NOSCTYP | MNG_NOTHROW | MNG_NOSTVIR | MNG_NOECSU | MNG_NOCLOSUR
      | MNG_SHORT_U | MNG_DROP_IMP | MNG_NOUNALG | MNG_NOMANAGE
      | MNG_IGN_JMP | MNG_MOVE_JMP | MNG_IGN_ANYWAY);
    public const int MNG_LONG_FORM = (MNG_ZPT_SPACE | MNG_IGN_JMP | MNG_IGN_ANYWAY | MNG_NOPTRTYP);

    // The description of the following symbol is in the notes
    public const int MNG_CALC_VALID = (MNG_COMPILER_MSK | MNG_IGN_JMP | MNG_IGN_ANYWAY);

    public const uint CHD_MULTINH = 0x01;    // Multiple inheritance
    public const uint CHD_VIRTINH = 0x02;    // Virtual inheritance
    public const uint CHD_AMBIGUOUS = 0x04;    // Ambiguous inheritance

    public const uint DEFCOLOR = 0xffffffff;
    public const ulong BADADDR = 0xffffffffffffffffUl;

    public const int E_PREV = 1000;
    public const int E_NEXT = 2000;
}
