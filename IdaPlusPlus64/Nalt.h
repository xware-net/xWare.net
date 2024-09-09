#pragma once

// complete

#define AFL_LINNUM      0x00000001L     ///< has line number info
#define AFL_USERSP      0x00000002L     ///< user-defined SP value
#define AFL_PUBNAM      0x00000004L     ///< name is public (inter-file linkage)
#define AFL_WEAKNAM     0x00000008L     ///< name is weak
#define AFL_HIDDEN      0x00000010L     ///< the item is hidden completely
#define AFL_MANUAL      0x00000020L     ///< the instruction/data is specified by the user
#define AFL_NOBRD       0x00000040L     ///< the code/data border is hidden
#define AFL_ZSTROFF     0x00000080L     ///< display struct field name at 0 offset when displaying an offset.
///< example:
///<   \v{offset somestruct.field_0}
///< if this flag is clear, then
///<   \v{offset somestruct}
#define AFL_BNOT0       0x00000100L     ///< the 1st operand is bitwise negated
#define AFL_BNOT1       0x00000200L     ///< the 2nd operand is bitwise negated
#define AFL_LIB         0x00000400L     ///< item from the standard library.
										///< low level flag, is used to set
										///< #FUNC_LIB of ::func_t
#define AFL_TI          0x00000800L     ///< has typeinfo? (#NSUP_TYPEINFO); used only for addresses, not for member_t
#define AFL_TI0         0x00001000L     ///< has typeinfo for operand 0? (#NSUP_OPTYPES)
#define AFL_TI1         0x00002000L     ///< has typeinfo for operand 1? (#NSUP_OPTYPES+1)
#define AFL_LNAME       0x00004000L     ///< has local name too (#FF_NAME should be set)
#define AFL_TILCMT      0x00008000L     ///< has type comment? (such a comment may be changed by IDA)
#define AFL_LZERO0      0x00010000L     ///< toggle leading zeroes for the 1st operand
#define AFL_LZERO1      0x00020000L     ///< toggle leading zeroes for the 2nd operand
#define AFL_COLORED     0x00040000L     ///< has user defined instruction color?
#define AFL_TERSESTR    0x00080000L     ///< terse structure variable display?
#define AFL_SIGN0       0x00100000L     ///< code: toggle sign of the 1st operand
#define AFL_SIGN1       0x00200000L     ///< code: toggle sign of the 2nd operand
#define AFL_NORET       0x00400000L     ///< for imported function pointers: doesn't return.
										///< this flag can also be used for any instruction
										///< which halts or finishes the program execution
#define AFL_FIXEDSPD    0x00800000L     ///< sp delta value is fixed by analysis.
										///< should not be modified by modules
#define AFL_ALIGNFLOW   0x01000000L     ///< the previous insn was created for alignment purposes only
#define AFL_USERTI      0x02000000L     ///< the type information is definitive.
										///< (comes from the user or type library)
										///< if not set see #AFL_TYPE_GUESSED
#define AFL_RETFP       0x04000000L     ///< function returns a floating point value
#define AFL_USEMODSP    0x08000000L     ///< insn modifes SP and uses the modified value;
										///< example: pop [rsp+N]
#define AFL_NOTCODE     0x10000000L     ///< autoanalysis should not create code here
#define AFL_NOTPROC     0x20000000L     ///< autoanalysis should not create proc here
#define AFL_TYPE_GUESSED    0xC2000000L ///< who guessed the type information?
#define AFL_IDA_GUESSED     0x00000000L ///< the type is guessed by IDA
#define AFL_HR_GUESSED_FUNC 0x40000000L ///< the function type is guessed by the decompiler
#define AFL_HR_GUESSED_DATA 0x80000000L ///< the data type is guessed by the decompiler
#define AFL_HR_DETERMINED   0xC0000000L ///< the type is definitely guessed by the decompiler

#define  NALT_ENUM      uval_t(-2) ///< reserved for enums, see enum.hpp
#define  NALT_WIDE      uval_t(-1) ///< 16-bit byte value
#define  NALT_SWITCH    1          ///< switch idiom address (used at jump targets)
//#define  NALT_OBASE1    2        // offset base 2
#define  NALT_STRUCT    3          ///< struct id
//#define  NALT_SEENF     4        // 'seen' flag (used in structures)
//#define  NALT_OOBASE0   5        // outer offset base 1
//#define  NALT_OOBASE1   6        // outer offset base 2
//#define  NALT_XREFPOS   7        // saved xref address in the xrefs window
#define  NALT_AFLAGS    8          ///< additional flags for an item
#define  NALT_LINNUM    9          ///< source line number
#define  NALT_ABSBASE  10          ///< absolute segment location
#define  NALT_ENUM0    11          ///< enum id for the first operand
#define  NALT_ENUM1    12          ///< enum id for the second operand
//#define  NALT_STROFF0  13        // struct offset, struct id for the first operand
//#define  NALT_STROFF1  14        // struct offset, struct id for the second operand
#define  NALT_PURGE    15          ///< number of bytes purged from the stack when a function is called indirectly
#define  NALT_STRTYPE  16          ///< type of string item
#define  NALT_ALIGN    17          ///< alignment value if the item is #FF_ALIGN
								   ///< (should by equal to power of 2)
//#define  NALT_HIGH0    18        // linear address of byte referenced by
//                                 // high 16 bits of an offset (FF_0HIGH)
//#define  NALT_HIGH1    19        // linear address of byte referenced by
//                                 // high 16 bits of an offset (FF_1HIGH)
#define  NALT_COLOR    20          ///< instruction/data background color

#define  NSUP_CMT       0       ///< regular comment
#define  NSUP_REPCMT    1       ///< repeatable comment
#define  NSUP_FOP1      2       ///< forced operand 1
#define  NSUP_FOP2      3       ///< forced operand 2
#define  NSUP_JINFO     4       ///< jump table info
#define  NSUP_ARRAY     5       ///< array parameters
#define  NSUP_OMFGRP    6       ///< OMF: group of segments (not used anymore)
#define  NSUP_FOP3      7       ///< forced operand 3
#define  NSUP_SWITCH    8       ///< switch information
#define  NSUP_REF0      9       ///< complex reference information for operand 1
#define  NSUP_REF1      10      ///< complex reference information for operand 2
#define  NSUP_REF2      11      ///< complex reference information for operand 3
#define  NSUP_OREF0     12      ///< outer complex reference information for operand 1
#define  NSUP_OREF1     13      ///< outer complex reference information for operand 2
#define  NSUP_OREF2     14      ///< outer complex reference information for operand 3
#define  NSUP_STROFF0   15      ///< stroff: struct path for the first operand
#define  NSUP_STROFF1   16      ///< stroff: struct path for the second operand
#define  NSUP_SEGTRANS  17      ///< segment translations
#define  NSUP_FOP4      18      ///< forced operand 4
#define  NSUP_FOP5      19      ///< forced operand 5
#define  NSUP_FOP6      20      ///< forced operand 6
#define  NSUP_REF3      21      ///< complex reference information for operand 4
#define  NSUP_REF4      22      ///< complex reference information for operand 5
#define  NSUP_REF5      23      ///< complex reference information for operand 6
#define  NSUP_OREF3     24      ///< outer complex reference information for operand 4
#define  NSUP_OREF4     25      ///< outer complex reference information for operand 5
#define  NSUP_OREF5     26      ///< outer complex reference information for operand 6
#define  NSUP_XREFPOS   27      ///< saved xref address and type in the xrefs window
#define  NSUP_CUSTDT    28      ///< custom data type id
#define  NSUP_GROUPS    29      ///< SEG_GRP: pack_dd encoded list of selectors
#define  NSUP_ARGEAS    30      ///< instructions that initialize call arguments
#define  NSUP_FOP7      31      ///< forced operand 7
#define  NSUP_FOP8      32      ///< forced operand 8
#define  NSUP_REF6      33      ///< complex reference information for operand 7
#define  NSUP_REF7      34      ///< complex reference information for operand 8
#define  NSUP_OREF6     35      ///< outer complex reference information for operand 7
#define  NSUP_OREF7     36      ///< outer complex reference information for operand 8

// values E_PREV..E_NEXT+1000 are reserved (1000..2000..3000 decimal)

/// SP change points blob (see funcs.cpp).
/// values NSUP_POINTS..NSUP_POINTS+0x1000 are reserved
#define  NSUP_POINTS    0x1000

/// manual instruction.
/// values NSUP_MANUAL..NSUP_MANUAL+0x1000 are reserved
#define  NSUP_MANUAL    0x2000

/// type information.
/// values NSUP_TYPEINFO..NSUP_TYPEINFO+0x1000 are reserved
#define  NSUP_TYPEINFO  0x3000

/// register variables.
/// values NSUP_REGVAR..NSUP_REGVAR+0x1000 are reserved
#define  NSUP_REGVAR    0x4000

/// local labels.
/// values NSUP_LLABEL..NSUP_LLABEL+0x1000 are reserved
#define  NSUP_LLABEL    0x5000

/// register argument type/name descriptions
/// values NSUP_REGARG..NSUP_REGARG+0x1000 are reserved
#define  NSUP_REGARG    0x6000

/// function tails or tail referers
/// values NSUP_FTAILS..NSUP_FTAILS+0x1000 are reserved
#define  NSUP_FTAILS    0x7000

/// graph group information
/// values NSUP_GROUP..NSUP_GROUP+0x1000 are reserved
#define  NSUP_GROUP     0x8000

/// operand type information.
/// values NSUP_OPTYPES..NSUP_OPTYPES+0x100000 are reserved
#define  NSUP_OPTYPES   0x9000

/// function metadata before lumina information was applied
/// values NSUP_ORIGFMD..NSUP_ORIGFMD+0x1000 are reserved
#define  NSUP_ORIGFMD   0x109000

//@}

/// \defgroup NALT_X Netnode xref tags
/// Tag values to store xrefs (see cref.cpp)
//@{
#define NALT_CREF_TO         'X'     ///< code xref to, idx: target address
#define NALT_CREF_FROM       'x'     ///< code xref from, idx: source address
#define NALT_DREF_TO         'D'     ///< data xref to, idx: target address
#define NALT_DREF_FROM       'd'     ///< data xref from, idx: source address
//@}

/// \defgroup N_TAG Netnode graph tags
/// Tag values to store graph info
//@{
#define NSUP_GR_INFO         'g'     ///< group node info: color, ea, text
#define NALT_GR_LAYX         'p'     ///< group layout ptrs, hash: md5 of 'belongs'
#define NSUP_GR_LAYT         'l'     ///< group layouts, idx: layout pointer
//@}

/// Patch netnode tag
#define PATCH_TAG 'P'

static nodeidx_t ida_ea2node(ea_t ea)
{
	return ea2node(ea);
}

static ea_t ida_node2ea(nodeidx_t ndx)
{
	return node2ea(ndx);
}

static netnode ida_getnode(ea_t ea)
{
	return netnode(ea2node(ea));
}

static tid_t ida_get_strid(ea_t ea)
{
	return get_strid(ea);
}

static ssize_t ida_get_xrefpos(IntPtr out, ea_t ea)
{
	return get_xrefpos((::xrefpos_t*)(out.ToPointer()), ea);
}

static void ida_set_xrefpos(ea_t ea, IntPtr in)
{
	return set_xrefpos(ea, (const ::xrefpos_t*)(in.ToPointer()));
}

static void ida_del_xrefpos(ea_t ea)
{
	getnode(ea).supdel(NSUP_XREFPOS);
}

static void ida_set_aflags(ea_t ea, aflags_t flags)
{
	return set_aflags(ea, flags);
}

static void ida_upd_abits(ea_t ea, aflags_t clr_bits, aflags_t set_bits)
{
	return upd_abits(ea, clr_bits, set_bits);
}

static void ida_set_abits(ea_t ea, aflags_t bits)
{
	return set_abits(ea, bits);
}

static void ida_clr_abits(ea_t ea, aflags_t bits)
{
	return clr_abits(ea, bits);
}

static aflags_t ida_get_aflags(ea_t ea)
{
	return get_aflags(ea);
}

static void ida_del_aflags(ea_t ea)
{
	return del_aflags(ea);
}

static bool ida_has_aflag_linnum(aflags_t flags)
{
	return (flags & AFL_LINNUM) != 0;
}

static bool ida_is_aflag_usersp(aflags_t flags)
{
	return (flags & AFL_USERSP) != 0;
}

static bool ida_is_aflag_public_name(aflags_t flags)
{
	return (flags & AFL_PUBNAM) != 0;
}

static bool ida_is_aflag_weak_name(aflags_t flags)
{
	return (flags & AFL_WEAKNAM) != 0;
}

static bool ida_is_aflag_hidden_item(aflags_t flags)
{
	return (flags & AFL_HIDDEN) != 0;
}

static bool ida_is_aflag_manual_insn(aflags_t flags)
{
	return (flags & AFL_MANUAL) != 0;
}

static bool ida_is_aflag_hidden_border(aflags_t flags)
{
	return (flags & AFL_NOBRD) != 0;
}

static bool ida_is_aflag_zstroff(aflags_t flags)
{
	return (flags & AFL_ZSTROFF) != 0;
}

static bool ida_is_aflag__bnot0(aflags_t flags)
{
	return (flags & AFL_BNOT0) != 0;
}

static bool ida_is_aflag__bnot1(aflags_t flags)
{
	return (flags & AFL_BNOT1) != 0;
}

static bool ida_is_aflag_libitem(aflags_t flags)
{
	return (flags & AFL_LIB) != 0;
}

static bool ida_has_aflag_ti(aflags_t flags)
{
	return (flags & AFL_TI) != 0;
}

static bool ida_has_aflag_ti0(aflags_t flags)
{
	return (flags & AFL_TI0) != 0;
}

static bool ida_has_aflag_ti1(aflags_t flags)
{
	return (flags & AFL_TI1) != 0;
}

static bool ida_has_aflag_lname(aflags_t flags)
{
	return (flags & AFL_LNAME) != 0;
}

static bool ida_is_aflag_tilcmt(aflags_t flags)
{
	return (flags & AFL_TILCMT) != 0;
}

static bool ida_is_aflag_lzero0(aflags_t flags)
{
	return (flags & AFL_LZERO0) != 0;
}

static bool ida_is_aflag_lzero1(aflags_t flags)
{
	return (flags & AFL_LZERO1) != 0;
}

static bool ida_is_aflag_colored_item(aflags_t flags)
{
	return (flags & AFL_COLORED) != 0;
}

static bool ida_is_aflag_terse_struc(aflags_t flags)
{
	return (flags & AFL_TERSESTR) != 0;
}

static bool ida_is_aflag__invsign0(aflags_t flags)
{
	return (flags & AFL_SIGN0) != 0;
}

static bool ida_is_aflag__invsign1(aflags_t flags)
{
	return (flags & AFL_SIGN1) != 0;
}

static bool ida_is_aflag_noret(aflags_t flags)
{
	return (flags & AFL_NORET) != 0;
}

static bool ida_is_aflag_fixed_spd(aflags_t flags)
{
	return (flags & AFL_FIXEDSPD) != 0;
}

static bool ida_is_aflag_align_flow(aflags_t flags)
{
	return (flags & AFL_ALIGNFLOW) != 0;
}

static bool ida_is_aflag_userti(aflags_t flags)
{
	return (flags & AFL_USERTI) != 0;
}

static bool ida_is_aflag_retfp(aflags_t flags)
{
	return (flags & AFL_RETFP) != 0;
}

static bool ida_uses_aflag_modsp(aflags_t flags)
{
	return (flags & AFL_USEMODSP) != 0;
}

static bool ida_is_aflag_notcode(aflags_t flags)
{
	return (flags & AFL_NOTCODE) != 0;
}

static bool ida_is_aflag_notproc(aflags_t flags)
{
	return (flags & AFL_NOTPROC) != 0;
}

static bool ida_is_aflag_type_guessed_by_ida(aflags_t flags)
{
	return (flags & AFL_TYPE_GUESSED) == AFL_IDA_GUESSED;
}

static bool ida_is_aflag_func_guessed_by_hexrays(aflags_t flags)
{
	return (flags & AFL_TYPE_GUESSED) == AFL_HR_GUESSED_FUNC;
}

static bool ida_is_aflag_data_guessed_by_hexrays(aflags_t flags)
{
	return (flags & AFL_TYPE_GUESSED) == AFL_HR_GUESSED_DATA;
}

static bool ida_is_aflag_type_determined_by_hexrays(aflags_t flags)
{
	return (flags & AFL_TYPE_GUESSED) == AFL_HR_DETERMINED;
}

static bool ida_is_aflag_type_guessed_by_hexrays(aflags_t flags)
{
	flags = flags & AFL_TYPE_GUESSED;
	return flags == AFL_HR_GUESSED_FUNC
		|| flags == AFL_HR_GUESSED_DATA
		|| flags == AFL_HR_DETERMINED;
}

static bool ida_is_hidden_item(ea_t ea)
{
	return is_aflag_hidden_item(get_aflags(ea));
}

static void ida_hide_item(ea_t ea)
{
	set_abits(ea, AFL_HIDDEN);
}

static void ida_unhide_item(ea_t ea)
{
	clr_abits(ea, AFL_HIDDEN);
}

static bool ida_is_hidden_border(ea_t ea)
{
	return is_aflag_hidden_border(get_aflags(ea));
}

static void ida_hide_border(ea_t ea)
{
	set_abits(ea, AFL_NOBRD);
}

static void ida_unhide_border(ea_t ea)
{
	clr_abits(ea, AFL_NOBRD);
}

static bool ida_uses_modsp(ea_t ea)
{
	return uses_aflag_modsp(get_aflags(ea));
}

static void ida_set_usemodsp(ea_t ea)
{
	set_abits(ea, AFL_USEMODSP);
}

static void ida_clr_usemodsp(ea_t ea)
{
	clr_abits(ea, AFL_USEMODSP);
}

static bool ida_is_zstroff(ea_t ea)
{
	return is_aflag_zstroff(get_aflags(ea));
}

static void ida_set_zstroff(ea_t ea)
{
	set_abits(ea, AFL_ZSTROFF);
}

static void ida_clr_zstroff(ea_t ea)
{
	clr_abits(ea, AFL_ZSTROFF);
}

static bool ida_is__bnot0(ea_t ea)
{
	return is_aflag__bnot0(get_aflags(ea));
}

static void ida_set__bnot0(ea_t ea)
{
	set_abits(ea, AFL_BNOT0);
}

static void ida_clr__bnot0(ea_t ea)
{
	clr_abits(ea, AFL_BNOT0);
}

static bool ida_is__bnot1(ea_t ea)
{
	return is_aflag__bnot1(get_aflags(ea));
}

static void ida_set__bnot1(ea_t ea)
{
	set_abits(ea, AFL_BNOT1);
}

static void ida_clr__bnot1(ea_t ea)
{
	clr_abits(ea, AFL_BNOT1);
}

static bool ida_is_libitem(ea_t ea)
{
	return is_aflag_libitem(get_aflags(ea));
}

static void ida_set_libitem(ea_t ea)
{
	set_abits(ea, AFL_LIB);
}

static void ida_clr_libitem(ea_t ea)
{
	clr_abits(ea, AFL_LIB);
}

static bool ida_has_ti(ea_t ea)
{
	return has_aflag_ti(get_aflags(ea));
}

static void ida_set_has_ti(ea_t ea)
{
	set_abits(ea, AFL_TI);
}

static void ida_clr_has_ti(ea_t ea)
{
	clr_abits(ea, AFL_TI);
}

static bool ida_has_ti0(ea_t ea)
{
	return has_aflag_ti0(get_aflags(ea));
}

static void ida_set_has_ti0(ea_t ea)
{
	set_abits(ea, AFL_TI0);
}

static void ida_clr_has_ti0(ea_t ea)
{
	clr_abits(ea, AFL_TI0);
}

static bool ida_has_ti1(ea_t ea)
{
	return has_aflag_ti1(get_aflags(ea));
}

static void ida_set_has_ti1(ea_t ea)
{
	set_abits(ea, AFL_TI1);
}

static void ida_clr_has_ti1(ea_t ea)
{
	clr_abits(ea, AFL_TI1);
}

static bool ida_has_lname(ea_t ea)
{
	return has_aflag_lname(get_aflags(ea));
}

static void ida_set_has_lname(ea_t ea)
{
	set_abits(ea, AFL_LNAME);
}

static void ida_clr_has_lname(ea_t ea)
{
	clr_abits(ea, AFL_LNAME);
}

static bool ida_is_tilcmt(ea_t ea)
{
	return is_aflag_tilcmt(get_aflags(ea));
}

static void ida_set_tilcmt(ea_t ea)
{
	set_abits(ea, AFL_TILCMT);
}

static void ida_clr_tilcmt(ea_t ea)
{
	clr_abits(ea, AFL_TILCMT);
}

static bool ida_is_usersp(ea_t ea)
{
	return is_aflag_usersp(get_aflags(ea));
}

static void ida_set_usersp(ea_t ea)
{
	set_abits(ea, AFL_USERSP);
}

static void ida_clr_usersp(ea_t ea)
{
	clr_abits(ea, AFL_USERSP);
}

static bool ida_is_lzero0(ea_t ea)
{
	return is_aflag_lzero0(get_aflags(ea));
}

static void ida_set_lzero0(ea_t ea)
{
	set_abits(ea, AFL_LZERO0);
}

static void ida_clr_lzero0(ea_t ea)
{
	clr_abits(ea, AFL_LZERO0);
}

static bool ida_is_lzero1(ea_t ea)
{
	return is_aflag_lzero1(get_aflags(ea));
}

static void ida_set_lzero1(ea_t ea)
{
	set_abits(ea, AFL_LZERO1);
}

static void ida_clr_lzero1(ea_t ea)
{
	clr_abits(ea, AFL_LZERO1);
}

static bool ida_is_colored_item(ea_t ea)
{
	return is_aflag_colored_item(get_aflags(ea));
}

static void ida_set_colored_item(ea_t ea)
{
	set_abits(ea, AFL_COLORED); // use set_item_color()
}

static void ida_clr_colored_item(ea_t ea)
{
	clr_abits(ea, AFL_COLORED); // use del_item_color()
}

static bool ida_is_terse_struc(ea_t ea)
{
	return is_aflag_terse_struc(get_aflags(ea));
}

static void ida_set_terse_struc(ea_t ea)
{
	set_abits(ea, AFL_TERSESTR);
}

static void ida_clr_terse_struc(ea_t ea)
{
	clr_abits(ea, AFL_TERSESTR);
}

static bool ida_is__invsign0(ea_t ea)
{
	return is_aflag__invsign0(get_aflags(ea));
}

static void ida_set__invsign0(ea_t ea)
{
	set_abits(ea, AFL_SIGN0);
}

static void ida_clr__invsign0(ea_t ea)
{
	clr_abits(ea, AFL_SIGN0);
}

static bool ida_is__invsign1(ea_t ea)
{
	return is_aflag__invsign1(get_aflags(ea));
}

static void ida_set__invsign1(ea_t ea)
{
	set_abits(ea, AFL_SIGN1);
}

static void ida_clr__invsign1(ea_t ea)
{
	clr_abits(ea, AFL_SIGN1);
}

static bool ida_is_noret(ea_t ea)
{
	return is_aflag_noret(get_aflags(ea));
}

static void ida_set_noret(ea_t ea)
{
	set_abits(ea, AFL_NORET);
}

static void ida_clr_noret(ea_t ea)
{
	clr_abits(ea, AFL_NORET);
}

static bool ida_is_fixed_spd(ea_t ea)
{
	return is_aflag_fixed_spd(get_aflags(ea));
}

static void ida_set_fixed_spd(ea_t ea)
{
	set_abits(ea, AFL_FIXEDSPD);
}

static void ida_clr_fixed_spd(ea_t ea)
{
	clr_abits(ea, AFL_FIXEDSPD);
}

static bool ida_is_align_flow(ea_t ea)
{
	return is_aflag_align_flow(get_aflags(ea));
}

static void ida_set_align_flow(ea_t ea)
{
	set_abits(ea, AFL_ALIGNFLOW);
}

static void ida_clr_align_flow(ea_t ea)
{
	clr_abits(ea, AFL_ALIGNFLOW);
}

static bool ida_is_userti(ea_t ea)
{
	return is_aflag_userti(get_aflags(ea));
}

static void ida_set_userti(ea_t ea)
{
	upd_abits(ea, AFL_TYPE_GUESSED, AFL_USERTI);
}

static void ida_clr_userti(ea_t ea)
{
	clr_abits(ea, AFL_TYPE_GUESSED); // use set_ida_guessed_type()
}

static bool ida_is_retfp(ea_t ea)
{
	return is_aflag_retfp(get_aflags(ea));
}

static void ida_set_retfp(ea_t ea)
{
	set_abits(ea, AFL_RETFP);
}

static void ida_clr_retfp(ea_t ea)
{
	clr_abits(ea, AFL_RETFP);
}

static bool ida_is_notproc(ea_t ea)
{
	return is_aflag_notproc(get_aflags(ea));
}

static void ida_set_notproc(ea_t ea)
{
	set_abits(ea, AFL_NOTPROC);
}

static void ida_clr_notproc(ea_t ea)
{
	clr_abits(ea, AFL_NOTPROC);
}

static bool ida_is_type_guessed_by_ida(ea_t ea)
{
	return is_aflag_type_guessed_by_ida(get_aflags(ea));
}

static bool ida_is_func_guessed_by_hexrays(ea_t ea)
{
	return is_aflag_func_guessed_by_hexrays(get_aflags(ea));
}

static bool ida_is_data_guessed_by_hexrays(ea_t ea)
{
	return is_aflag_data_guessed_by_hexrays(get_aflags(ea));
}

static bool ida_is_type_determined_by_hexrays(ea_t ea)
{
	return is_aflag_type_determined_by_hexrays(get_aflags(ea));
}

static bool ida_is_type_guessed_by_hexrays(ea_t ea)
{
	return is_aflag_type_guessed_by_hexrays(get_aflags(ea));
}

static void ida_set_type_guessed_by_ida(ea_t ea)
{
	upd_abits(ea, AFL_TYPE_GUESSED, AFL_IDA_GUESSED);
}

static void ida_set_func_guessed_by_hexrays(ea_t ea)
{
	upd_abits(ea, AFL_TYPE_GUESSED, AFL_HR_GUESSED_FUNC);
}

static void ida_set_data_guessed_by_hexrays(ea_t ea)
{
	upd_abits(ea, AFL_TYPE_GUESSED, AFL_HR_GUESSED_DATA);
}

static void ida_set_type_determined_by_hexrays(ea_t ea)
{
	upd_abits(ea, AFL_TYPE_GUESSED, AFL_HR_DETERMINED);
}

static void ida_set_notcode(ea_t ea)
{
	return set_notcode(ea);
}

static void ida_clr_notcode(ea_t ea)
{
	clr_abits(ea, AFL_NOTCODE);
}

static bool ida_is_notcode(ea_t ea)
{
	return is_aflag_notcode(get_aflags(ea));
}

static void ida_set_visible_item(ea_t ea, bool visible)
{
	if (visible)
		unhide_item(ea);
	else
		hide_item(ea);
}

static bool ida_is_visible_item(ea_t ea)
{
	return !is_hidden_item(ea);
}

static bool ida_is_finally_visible_item(ea_t ea)
{
	return (inf_get_cmtflg() & SCF_SHHID_ITEM) != 0 || is_visible_item(ea);
}

static void ida_set_source_linnum(ea_t ea, uval_t lnnum)
{
	return set_source_linnum(ea, lnnum);
}

static uval_t ida_get_source_linnum(ea_t ea)
{
	return get_source_linnum(ea);
}

static void ida_del_source_linnum(ea_t ea)
{
	return del_source_linnum(ea);
}

static ea_t ida_get_absbase(ea_t ea)
{
	ea_t x;
	return getnode(ea).supval(NALT_ABSBASE, &x, sizeof(x), atag) > 0 ? ea_t(x - 1) : ea_t(-1);
}

static void ida_set_absbase(ea_t ea, ea_t x)
{
	x++;
	getnode(ea).supset(NALT_ABSBASE, &x, sizeof(x), atag);
}

static void ida_del_absbase(ea_t ea)
{
	getnode(ea).supdel(NALT_ABSBASE, atag);
}

static ea_t ida_get_ind_purged(ea_t ea)
{
	ea_t x;
	return getnode(ea).supval(NALT_PURGE, &x, sizeof(x), atag) > 0 ? ea_t(x - 1) : ea_t(-1);
}

static void ida_set_ind_purged(ea_t ea, ea_t x)
{
	x++;
	getnode(ea).supset(NALT_PURGE, &x, sizeof(x), atag);
}

static void ida_del_ind_purged(ea_t ea)
{
	getnode(ea).supdel(NALT_PURGE, atag);
}

static uint32 ida_get_str_type(ea_t ea)
{
	return get_str_type(ea);
}

static void ida_set_str_type(ea_t ea, uint32 x)
{
	set_str_type(ea, x);
}

static void ida_del_str_type(ea_t ea)
{
	del_str_type(ea);
}

static uchar ida_get_str_type_code(int32 strtype)
{
	return uchar(strtype);
}

static char ida_get_str_term1(int32 strtype)
{
	return char(strtype >> 8);
}

static char ida_get_str_term2(int32 strtype)
{
	return char(strtype >> 16);
}

static uchar ida_get_str_encoding_idx(int32 strtype)
{
	return uchar(strtype >> 24);
}

static int32 ida_set_str_encoding_idx(int32 strtype, int encoding_idx)
{
	return (strtype & 0xFFFFFF) | ((uchar)encoding_idx << 24);
}

static int32 ida_make_str_type(uchar type_code, int encoding_idx, uchar term1, uchar term2)
{
	return type_code
		| (term1 << 8)
		| (term2 << 16)
		| ((uchar)encoding_idx << 24);
}

static bool ida_is_pascal(int32 strtype)
{
	int lyt = get_str_type_code(strtype) >> STRLYT_SHIFT;
	return lyt >= STRLYT_PASCAL1 && lyt <= STRLYT_PASCAL4;
}

static size_t ida_get_str_type_prefix_length(int32 strtype)
{
	switch (get_str_type_code(strtype))
	{
	case STRTYPE_LEN4_16:
	case STRTYPE_LEN4:
		return 4;
	case STRTYPE_LEN2_16:
	case STRTYPE_LEN2:
		return 2;
	case STRTYPE_PASCAL_16:
	case STRTYPE_PASCAL:
		return 1;
	}
	return 0;
}

static uint32 ida_get_alignment(ea_t ea)
{
	uint32 x;
	return getnode(ea).supval(NALT_ALIGN, &x, sizeof(x), atag) > 0 ? uint32(x - 1) : uint32(-1);
}

static void ida_set_alignment(ea_t ea, uint32 x)
{
	x++;
	getnode(ea).supset(NALT_ALIGN, &x, sizeof(x), atag);
}

static void ida_del_alignment(ea_t ea)
{
	getnode(ea).supdel(NALT_ALIGN, atag);
}

static void ida_set_item_color(ea_t ea, bgcolor_t color)
{
	return set_item_color(ea, color);
}

static bgcolor_t ida_get_item_color(ea_t ea)
{
	return get_item_color(ea);
}

static bool ida_del_item_color(ea_t ea)
{
	return del_item_color(ea);
}

static ssize_t ida_get_array_parameters(IntPtr out, ea_t ea)
{
	return get_array_parameters((array_parameters_t*)(out.ToPointer()), ea);
}

static void ida_set_array_parameters(ea_t ea, IntPtr in)
{
	set_array_parameters(ea, (array_parameters_t*)(in.ToPointer()));
}

static void ida_del_array_parameters(ea_t ea)
{
	getnode(ea).supdel(NSUP_ARRAY);
}

static ssize_t ida_get_switch_info(IntPtr out, ea_t ea)
{
	return get_switch_info((switch_info_t*)(out.ToPointer()), ea);
}

static void ida_set_switch_info(ea_t ea, IntPtr in)
{
	set_switch_info(ea, *(const ::switch_info_t*)(in.ToPointer()));
}

static void ida_del_switch_info(ea_t ea)
{
	del_switch_info(ea);
}

static unsigned long long ida_get_switch_parent(unsigned long long ea)
{
	ea_t x;
	return getnode(ea).supval(NALT_SWITCH, &x, sizeof(x), atag) > 0 ? ea_t(x - 1) : ea_t(-1);
}

static void ida_set_switch_parent(unsigned long long ea, unsigned long long x)
{
	x++;
	getnode(ea).supset(NALT_SWITCH, &x, sizeof(x), atag);
}

static void ida_del_switch_parent(unsigned long long ea)
{
	getnode(ea).supdel(NALT_SWITCH, atag);
}

static int ida_get_custom_data_type_ids(IntPtr cdis, unsigned long long ea)
{
	return get_custom_data_type_ids((::custom_data_type_ids_t*)(cdis.ToPointer()), ea);
}

static void ida_set_custom_data_type_ids(unsigned long long ea, IntPtr cdis)
{
	return set_custom_data_type_ids(ea, (const ::custom_data_type_ids_t*)(cdis.ToPointer()));
}

static void ida_del_custom_data_type_ids(unsigned long long ea)
{
	getnode(ea).supdel(NSUP_CUSTDT);
}

static bool ida_is_reftype_target_optional(unsigned char type)
{
	if ((type & REFINFO_CUSTOM) != 0)
	{
		const custom_refinfo_handler_t* cfh = get_custom_refinfo(type);
		if (cfh == nullptr)
			return false;
		return (cfh->props & RHF_TGTOPT) != 0;
	}
	switch (type)
	{
	case REF_OFF8:
	case REF_OFF16:
	case REF_OFF32:
	case REF_OFF64:
		return true;
	}
	return false;
}

static reftype_t ida_get_reftype_by_size(size_t size)
{
	return get_reftype_by_size(size);
}

static int ida_register_custom_refinfo(IntPtr crh)
{
	return register_custom_refinfo((const ::custom_refinfo_handler_t*)(crh.ToPointer()));
}

static bool ida_unregister_custom_refinfo(int crid)
{
	return unregister_custom_refinfo(crid);
}

static int ida_find_custom_refinfo(IntPtr name)
{
	return find_custom_refinfo((const char*)(name.ToPointer()));
}

static IntPtr ida_get_custom_refinfo(int crid)
{
	return IntPtr((void*)get_custom_refinfo(crid));
}

static IntPtr ida_get_custom_refinfo_handler(IntPtr ri)
{
	const refinfo_t* rip = (const refinfo_t*)(ri.ToPointer());
	return IntPtr((void*)(rip->is_custom() ? get_custom_refinfo(rip->type()) : nullptr));
}

static void ida_get_refinfo_descs(IntPtr descs)
{
	return get_refinfo_descs((::qvector<::refinfo_desc_t>*)(descs.ToPointer()));
}

static bool ida_set_refinfo_ex(unsigned long long ea, int n, IntPtr ri)
{
	return set_refinfo_ex(ea, n, (const ::refinfo_t*)(ri.ToPointer()));
}

static bool ida_set_refinfo(ea_t ea, int n, reftype_t type, ea_t target, ea_t base, adiff_t tdelta)
{
	return set_refinfo(ea, n, type, target, base, tdelta);
}

static bool ida_del_refinfo(ea_t ea, int n)
{
	return del_refinfo(ea, n);
}

static void ida_write_struc_path(unsigned long long ea, int idx, IntPtr path, int plen, long long delta)
{
	return write_struc_path(ea, idx, (const unsigned long long*)(path.ToPointer()), plen, delta);
}

static int ida_read_struc_path(IntPtr path, IntPtr delta, unsigned long long ea, int idx)
{
	return read_struc_path((unsigned long long*)(path.ToPointer()), (long long*)(delta.ToPointer()), ea, idx);
}

static bool ida_get_tinfo(IntPtr tif, unsigned long long ea)
{
	return get_tinfo((::tinfo_t*)(tif.ToPointer()), ea);
}

static bool ida_set_tinfo(unsigned long long ea, IntPtr tif)
{
	return set_tinfo(ea, (const ::tinfo_t*)(tif.ToPointer()));
}

static void ida_del_tinfo(ea_t ea)
{
	set_tinfo(ea, nullptr);
}

static bool ida_get_op_tinfo(IntPtr tif, unsigned long long ea, int n)
{
	return get_op_tinfo((::tinfo_t*)(tif.ToPointer()), ea, n);
}

static bool ida_set_op_tinfo(unsigned long long ea, int n, IntPtr tif)
{
	return set_op_tinfo(ea, n, (const ::tinfo_t*)(tif.ToPointer()));
}

static void ida_del_op_tinfo(ea_t ea, int n)
{
	set_op_tinfo(ea, n, nullptr);
}

static long long ida_get_root_filename(IntPtr buf, unsigned long long bufsize)
{
	return get_root_filename((char*)(buf.ToPointer()), bufsize);
}

static long long ida_dbg_get_input_path(IntPtr buf, unsigned long long bufsize)
{
	return dbg_get_input_path((char*)(buf.ToPointer()), bufsize);
}

static ssize_t ida_get_input_file_path(IntPtr buf, size_t bufsize)
{
	return getinf_buf(INF_INPUT_FILE_PATH, (char*)(buf.ToPointer()), bufsize);
}

static void ida_set_root_filename(IntPtr file)
{
	setinf_buf(INF_INPUT_FILE_PATH, (char*)(file.ToPointer()));
}

static size_t ida_retrieve_input_file_size()
{
	return getinf(INF_FSIZE);
}

static uint32 ida_retrieve_input_file_crc32()
{
	return uint32(getinf(INF_CRC32));
}

static bool ida_retrieve_input_file_md5(cli::array<unsigned char>^ hash)
{
	pin_ptr<unsigned char> hashPtr = &hash[0];
	return getinf_buf(INF_MD5, (void*)(hashPtr), 16) == 16;
}

static bool ida_retrieve_input_file_sha256(cli::array<unsigned char>^ hash)
{
	pin_ptr<unsigned char> hashPtr = &hash[0];
	return getinf_buf(INF_SHA256, (void*)(hashPtr), 32) == 32;
}


static ssize_t ida_get_asm_inc_file(IntPtr buf)
{
	qstring qstr;
	auto len = getinf_str(&qstr, INF_INCLUDE);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}


static bool ida_set_asm_inc_file(IntPtr file)
{
	return setinf_buf(INF_INCLUDE, (const char*)(file.ToPointer()));
}


static ea_t ida_get_imagebase()
{
	return getinf(INF_IMAGEBASE);
}


static void ida_set_imagebase(ea_t base)
{
	setinf(INF_IMAGEBASE, base);
}

static netnode ida_get_ids_modnode()
{
	return getinf(INF_IDSNODE);
}

static void ida_set_ids_modnode(netnode id)
{
	setinf(INF_IDSNODE, id);
}


static ssize_t ida_get_archive_path(IntPtr buf)
{
	qstring qstr;
	auto len = get_archive_path(&qstr);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static bool ida_set_archive_path(IntPtr file)
{
	return setinf_buf(INF_ARCHIVE_PATH, (const char*)(file.ToPointer()));
}


static ssize_t ida_get_loader_format_name(IntPtr buf)
{
	qstring qstr;
	auto len = get_loader_format_name(&qstr);
	if (buf == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, buf, len);
	return len;
}

static void ida_set_loader_format_name(IntPtr name)
{
	setinf_buf(INF_FILE_FORMAT_NAME, (const char*)(name.ToPointer()));
}


static ssize_t ida_get_initial_ida_version(IntPtr ver)
{
	qstring qstr;
	auto len = get_loader_format_name(&qstr);
	if (ver == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, ver, len);
	return len;
}

static ssize_t ida_get_ida_notepad_text(IntPtr text)
{
	qstring qstr;
	auto len = get_loader_format_name(&qstr);
	if (text == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, text, len);
	return len;
}

static void ida_set_ida_notepad_text(IntPtr text, size_t size)
{
	setinf_buf(INF_NOTEPAD, (const char*)(text.ToPointer()), size);
}

static ssize_t ida_get_srcdbg_paths(IntPtr paths)
{
	qstring qstr;
	auto len = get_loader_format_name(&qstr);
	if (paths == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, paths, len);
	return len;
}

static void ida_set_srcdbg_paths(IntPtr paths)
{
	setinf_buf(INF_SRCDBG_PATHS, (const char*)(paths.ToPointer()));
}

static ssize_t ida_get_srcdbg_undesired_paths(IntPtr paths)
{
	qstring qstr;
	auto len = get_loader_format_name(&qstr);
	if (paths == IntPtr::Zero)
	{
		return len;
	}

	::ConvertQstringToIntPtr(qstr, paths, len);
	return len;
}

static void ida_set_srcdbg_undesired_paths(IntPtr paths)
{
	setinf_buf(INF_SRCDBG_UNDESIRED, (const char*)(paths.ToPointer()));
}


static size_t ida_get_initial_idb_version()
{
	return getinf(INF_INITIAL_VERSION);
}

static time_t ida_get_idb_ctime()
{
	return getinf(INF_CTIME);
}

static size_t ida_get_elapsed_secs()
{
	return getinf(INF_ELAPSED);
}

static size_t ida_get_idb_nopens()
{
	return getinf(INF_NOPENS);
}

static int ida_get_encoding_qty()
{
	return get_encoding_qty();
}

static IntPtr ida_get_encoding_name(int idx)
{
	return IntPtr((void*)get_encoding_name(idx));
}

static int ida_add_encoding(IntPtr encname)
{
	return add_encoding((const char*)(encname.ToPointer()));
}

static bool ida_del_encoding(int idx)
{
	return del_encoding(idx);
}

static bool ida_rename_encoding(int idx, IntPtr encname)
{
	return rename_encoding(idx, (const char*)(encname.ToPointer()));
}

static int ida_get_encoding_bpu(int idx)
{
	return get_encoding_bpu(idx);
}

static int ida_get_encoding_bpu_by_name(IntPtr encname)
{
	return get_encoding_bpu_by_name((const char*)(encname.ToPointer()));
}

static int ida_get_strtype_bpu(int32 strtype)
{
	int w = get_str_type_code(strtype) & STRWIDTH_MASK;
	return w == STRWIDTH_2B ? BPU_2B
		: w == STRWIDTH_4B ? BPU_4B
		: BPU_1B;
}

static int ida_get_default_encoding_idx(int bpu)
{
	return get_default_encoding_idx(bpu);
}

static bool ida_set_default_encoding_idx(int bpu, int idx)
{
	return set_default_encoding_idx(bpu, idx);
}

static IntPtr ida_encoding_from_strtype(int32 strtype)
{
	uchar enc = get_str_encoding_idx(strtype);
	if (enc == STRENC_DEFAULT)
		enc = get_default_encoding_idx(get_strtype_bpu(strtype));
	return IntPtr(((void*)get_encoding_name(enc)));
}

static int ida_get_outfile_encoding_idx()
{
	return get_outfile_encoding_idx();
}

static bool ida_set_outfile_encoding_idx(int idx)
{
	return set_outfile_encoding_idx(idx);
}

static uint ida_get_import_module_qty()
{
	return get_import_module_qty();
}

static bool ida_get_import_module_name(IntPtr buf, int mod_index)
{
	qstring qstr;
	auto ret = get_import_module_name(&qstr, mod_index);
	if (buf == IntPtr::Zero)
	{
		return ret;
	}

	::ConvertQstringToIntPtr(qstr, buf, qstr.size() - 1);
	return ret;
}

static int ida_enum_import_names(int mod_index, IntPtr callback, IntPtr param)
{
	return enum_import_names(mod_index, (int (__stdcall*)(ea_t, const char*, uval_t, void*))(callback.ToPointer()), (void*)(param.ToPointer()));
}

static void ida_delete_imports()
{
	return delete_imports();
}

static int ida_validate_idb_names2(bool do_repair)
{
	return validate_idb_names2(do_repair);
}

static void ida_init_ignore_micro()
{
	im.ignore_micro.create("$ ignore micro");
}

static void ida_term_ignore_micro()
{
	im.ignore_micro = BADNODE;
}

static char ida_get_ignore_micro(ea_t ea)
{
	return im.ignore_micro.charval_ea(ea, 0);
}

static void ida_set_ignore_micro(ea_t ea, uchar im_type)
{
	im.ignore_micro.charset_ea(ea, im_type, 0);
}

static void ida_clr_ignore_micro(ea_t ea)
{
	im.ignore_micro.chardel_ea(ea, 0);
}

static ea_t ida_next_marked_insn(ea_t ea)
{
	return node2ea(im.ignore_micro.charnext(ea2node(ea), 0));
}

static void ida_mark_prolog_insn(ea_t ea)
{
	im.set_ignore_micro(ea, IM_PROLOG);
}

static void ida_mark_epilog_insn(ea_t ea)
{
	im.set_ignore_micro(ea, IM_EPILOG);
}

static void ida_mark_switch_insn(ea_t ea)
{
	im.set_ignore_micro(ea, IM_SWITCH);
}

static bool ida_is_prolog_insn(ea_t ea)
{
	return im.get_ignore_micro(ea) == IM_PROLOG;
}

static bool ida_is_epilog_insn(ea_t ea)
{
	return im.get_ignore_micro(ea) == IM_EPILOG;
}

static bool ida_is_switch_insn(ea_t ea)
{
	return im.get_ignore_micro(ea) == IM_SWITCH;
}

static bool ida_should_ignore_micro(ea_t ea)
{
	return im.get_ignore_micro(ea) != IM_NONE;
}

static void ida_set_gotea(ea_t gotea)
{
	netnode n;
	n.create("$ got");
	n.altset(0, ea2node(gotea) + 1);
}

static ea_t ida_get_gotea()
{
	netnode n("$ got");
	return exist(n) ? node2ea(n.altval(0) - 1) : BADADDR;
}

#ifdef OBSOLETE_FUNCS
static int ida_validate_idb_names()
{
	return validate_idb_names();
}
#endif
