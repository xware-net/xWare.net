#pragma once

#define MS_CLS  0x00000600LU             ///< Mask for typing
#define FF_CODE 0x00000600LU             ///< Code ?
#define FF_DATA 0x00000400LU             ///< Data ?
#define FF_TAIL 0x00000200LU             ///< Tail ?
#define FF_UNK  0x00000000LU             ///< Unknown ?

#define MS_VAL  0x000000FFLU             ///< Mask for byte value
#define FF_IVL  0x00000100LU             ///< Byte has value ?

#define MS_COMM  0x000FF800            ///< Mask of common bits
#define FF_COMM  0x00000800            ///< Has comment ?
#define FF_REF   0x00001000            ///< has references
#define FF_LINE  0x00002000            ///< Has next or prev lines ?
#define FF_NAME  0x00004000            ///< Has name ?
#define FF_LABL  0x00008000            ///< Has dummy name?
#define FF_FLOW  0x00010000            ///< Exec flow from prev instruction
#define FF_SIGN  0x00020000            ///< Inverted sign of operands
#define FF_BNOT  0x00040000            ///< Bitwise negation of operands
#define FF_UNUSED 0x00080000           ///< unused bit (was used for variable bytes)

#define FF_ANYNAME      (FF_LABL|FF_NAME)

#define MS_0TYPE 0x00F00000LU            ///< Mask for 1st arg typing
#define FF_0VOID 0x00000000LU            ///< Void (unknown)?
#define FF_0NUMH 0x00100000LU            ///< Hexadecimal number?
#define FF_0NUMD 0x00200000LU            ///< Decimal number?
#define FF_0CHAR 0x00300000LU            ///< Char ('x')?
#define FF_0SEG  0x00400000LU            ///< Segment?
#define FF_0OFF  0x00500000LU            ///< Offset?
#define FF_0NUMB 0x00600000LU            ///< Binary number?
#define FF_0NUMO 0x00700000LU            ///< Octal number?
#define FF_0ENUM 0x00800000LU            ///< Enumeration?
#define FF_0FOP  0x00900000LU            ///< Forced operand?
#define FF_0STRO 0x00A00000LU            ///< Struct offset?
#define FF_0STK  0x00B00000LU            ///< Stack variable?
#define FF_0FLT  0x00C00000LU            ///< Floating point number?
#define FF_0CUST 0x00D00000LU            ///< Custom representation?

#define MS_1TYPE 0x0F000000LU            ///< Mask for the type of other operands
#define FF_1VOID 0x00000000LU            ///< Void (unknown)?
#define FF_1NUMH 0x01000000LU            ///< Hexadecimal number?
#define FF_1NUMD 0x02000000LU            ///< Decimal number?
#define FF_1CHAR 0x03000000LU            ///< Char ('x')?
#define FF_1SEG  0x04000000LU            ///< Segment?
#define FF_1OFF  0x05000000LU            ///< Offset?
#define FF_1NUMB 0x06000000LU            ///< Binary number?
#define FF_1NUMO 0x07000000LU            ///< Octal number?
#define FF_1ENUM 0x08000000LU            ///< Enumeration?
#define FF_1FOP  0x09000000LU            ///< Forced operand?
#define FF_1STRO 0x0A000000LU            ///< Struct offset?
#define FF_1STK  0x0B000000LU            ///< Stack variable?
#define FF_1FLT  0x0C000000LU            ///< Floating point number?
#define FF_1CUST 0x0D000000LU            ///< Custom representation?

#define DT_TYPE 0xF0000000             ///< Mask for DATA typing

#define FF_BYTE     0x00000000         ///< byte
#define FF_WORD     0x10000000         ///< word
#define FF_DWORD    0x20000000         ///< double word
#define FF_QWORD    0x30000000         ///< quadro word
#define FF_TBYTE    0x40000000         ///< tbyte
#define FF_STRLIT   0x50000000         ///< string literal
#define FF_STRUCT   0x60000000         ///< struct variable
#define FF_OWORD    0x70000000         ///< octaword/xmm word (16 bytes/128 bits)
#define FF_FLOAT    0x80000000         ///< float
#define FF_DOUBLE   0x90000000         ///< double
#define FF_PACKREAL 0xA0000000         ///< packed decimal real
#define FF_ALIGN    0xB0000000         ///< alignment directive
//                  0xC0000000         ///< reserved
#define FF_CUSTOM   0xD0000000         ///< custom data type
#define FF_YWORD    0xE0000000         ///< ymm word (32 bytes/256 bits)
#define FF_ZWORD    0xF0000000         ///< zmm word (64 bytes/512 bits)

#define MS_CODE 0xF0000000LU             ///< Mask for code bits
#define FF_FUNC 0x10000000LU             ///< function start?
//              0x20000000LU             // not used
#define FF_IMMD 0x40000000LU             ///< Has Immediate value ?
#define FF_JUMP 0x80000000LU             ///< Has jump table or switch_info?

static size_t ida_get_strlit_contents(ea_t ea, size_t len, Int32 strtype, Int32 flags)
{
	qstring buffer;
	return get_strlit_contents(&buffer, ea, len, strtype, nullptr, flags);
}

static size_t ida_get_ida_string(IntPtr buffer, ea_t ea)
{
	if (buffer == IntPtr::Zero)
	{
		size_t bufferSize = 0;
		size_t len = get_max_strlit_length(ea, STRTYPE_C, ALOPT_IGNHEADS);
		if (len > 0)
		{
			bufferSize = len;
			qstring str;
			size_t len2 = get_strlit_contents(&str, ea, len, STRTYPE_C);
			if (len2 > 0)
			{
				if (len2 > bufferSize)
					bufferSize = len2;
			}
		}

		return bufferSize;
	}
	else
	{
		size_t bufferSize;
		size_t len = get_max_strlit_length(ea, STRTYPE_C, ALOPT_IGNHEADS);
		if (len > 0)
		{
			bufferSize = len;
			qstring str;
			size_t len2 = get_strlit_contents(&str, ea, len, STRTYPE_C);
			if (len2 > 0)
			{
				if (len2 > bufferSize)
					bufferSize = len2;

				::ConvertQstringToIntPtr(str, buffer, bufferSize);
			}
		}

		return bufferSize;
	}
}

//static flags_t ida_get_flags(ea_t ea)
//{
//	return get_flags_ex(ea, 0);
//}

//static bool ida_has_name(flags_t F)
//{
//	return has_name(F);
//}

//static bool ida_has_cmt(flags_t F)
//{
//	return has_cmt(F);
//}

static bool ida_set_cmt(ea_t ea, IntPtr comment, bool rptble)
{
	return set_cmt(ea, (char*)comment.ToPointer(), rptble);
}

static bool ida_create_dword(ea_t ea, bool force)
{
	return create_dword(ea, sizeof(DWORD), force);
}

static bool ida_create_qword(ea_t ea, bool force)
{
	return create_qword(ea, sizeof(ea_t), force);
}

static bool ida_del_items(ea_t ea, int flags, asize_t nbytes)
{
	return del_items(ea, flags, nbytes, nullptr);
}

// generated

static error_t ida_enable_flags(ea_t start_ea, ea_t end_ea, storage_type_t stt)
{
	return enable_flags(start_ea, end_ea, stt);
}

static error_t ida_disable_flags(ea_t start_ea, ea_t end_ea)
{
	return disable_flags(start_ea, end_ea);
}

static error_t ida_change_storage_type(ea_t start_ea, ea_t end_ea, storage_type_t stt)
{
	return change_storage_type(start_ea, end_ea, stt);
}

static ea_t ida_next_addr(ea_t ea)
{
	return next_addr(ea);
}

static ea_t ida_prev_addr(ea_t ea)
{
	return prev_addr(ea);
}

static ea_t ida_next_chunk(ea_t ea)
{
	return next_chunk(ea);
}

static ea_t ida_prev_chunk(ea_t ea)
{
	return prev_chunk(ea);
}

static ea_t ida_chunk_start(ea_t ea)
{
	return chunk_start(ea);
}

static asize_t ida_chunk_size(ea_t ea)
{
	return chunk_size(ea);
}

//idaman ea_t ida_export next_that(
//	ea_t ea,
//	ea_t maxea,
//	testf_t* testf,
//	void* ud = nullptr);
//
//idaman ea_t ida_export prev_that(
//	ea_t ea,
//	ea_t minea,
//	testf_t* testf,
//	void* ud = nullptr);


static ea_t ida_next_unknown(ea_t ea, ea_t maxea)
{
	return next_that(ea, maxea, nullptr);
}

static ea_t ida_prev_unknown(ea_t ea, ea_t minea)
{
	return prev_that(ea, minea, nullptr);
}

static ea_t ida_prev_head(ea_t ea, ea_t minea)
{
	return prev_head(ea, minea);
}

static ea_t ida_next_head(ea_t ea, ea_t maxea)
{
	return next_head(ea, maxea);
}

static ea_t ida_prev_not_tail(ea_t ea)
{
	return prev_not_tail(ea);
}

static ea_t ida_next_not_tail(ea_t ea)
{
	return next_not_tail(ea);
}

static ea_t ida_prev_visea(ea_t ea)
{
	return prev_visea(ea);
}

static ea_t ida_next_visea(ea_t ea)
{
	return next_visea(ea);
}

static ea_t ida_get_item_head(ea_t ea)
{
	return get_item_head(ea);
}

static ea_t ida_get_item_end(ea_t ea)
{
	return get_item_end(ea);
}

static ea_t ida_calc_max_item_end(ea_t ea, int how)
{
	return calc_max_item_end(ea, how);
}

static asize_t ida_get_item_size(ea_t ea)
{
	return get_item_end(ea) - ea;
}

static bool ida_is_mapped(ea_t ea)
{
	return is_mapped(ea);
}

static flags_t ida_get_flags_ex(ea_t ea, int how)
{
	return get_flags_ex(ea, how);
}

static flags_t ida_get_flags(ea_t ea)
{
	return get_flags_ex(ea, 0);
}

static flags_t ida_get_full_flags(ea_t ea)
{
	return get_flags_ex(ea, GFE_VALUE);
}

static flags_t ida_get_item_flag(ea_t from, int n, ea_t ea, bool appzero)
{
	return get_item_flag(from, n, ea, appzero);
}

static bool ida_has_value(flags_t F)
{
	return (F & FF_IVL) != 0;
}

static void ida_del_value(ea_t ea)
{
	return del_value(ea);
}

static bool ida_is_loaded(ea_t ea)
{
	return is_loaded(ea);
}

static int ida_nbits(ea_t ea)
{
	return nbits(ea);
}

static int ida_bytesize(ea_t ea)
{
	return (nbits(ea) + 7) / 8;
}

static byte ida_get_byte(ea_t ea)
{
	return get_byte(ea);
}

static uchar ida_get_db_byte(ea_t ea)
{
	return get_db_byte(ea);
}

static ushort ida_get_word(ea_t ea)
{
	return get_word(ea);
}

static uint32 ida_get_dword(ea_t ea)
{
	return get_dword(ea);
}

static uint64 ida_get_qword(ea_t ea)
{
	return get_qword(ea);
}

static uint64 ida_get_wide_byte(ea_t ea)
{
	return get_wide_byte(ea);
}

static uint64 ida_get_wide_word(ea_t ea)
{
	return get_wide_word(ea);
}

static uint64 ida_get_wide_dword(ea_t ea)
{
	return get_wide_dword(ea);
}

//uchar ida_export get_octet(ea_t *ea, uint64 *v, int *nbit)

static uint32 ida_get_16bit(ea_t ea)
{
	return get_16bit(ea);
}

static uint32 ida_get_32bit(ea_t ea)
{
	return get_32bit(ea);
}

static uint64 ida_get_64bit(ea_t ea)
{
	return get_64bit(ea);
}

//bool ida_export get_data_value(uval_t *v, ea_t ea, asize_t size)

//int ida_export visit_patched_bytes(
//	ea_t ea1,
//	ea_t ea2,
//	int (idaapi* cb)(ea_t ea, qoff64_t fpos, uint64 o, uint64 v, void* ud),
//	void* ud = nullptr)

static uint64 ida_get_original_byte(ea_t ea)
{
	return get_original_byte(ea);
}

static uint64 ida_get_original_word(ea_t ea)
{
	return get_original_word(ea);
}

static uint64 ida_get_original_dword(ea_t ea)
{
	return get_original_dword(ea);
}

static uint64 ida_get_original_qword(ea_t ea)
{
	return get_original_qword(ea);
}

static bool ida_put_byte(ea_t ea, uint64 x)
{
	return put_byte(ea, x);
}

static void ida_put_word(ea_t ea, uint64 x)
{
	return put_word(ea, x);
}

static void ida_put_dword(ea_t ea, uint64 x)
{
	return put_dword(ea, x);
}

static void ida_put_qword(ea_t ea, uint64 x)
{
	return put_qword(ea, x);
}

static bool ida_patch_byte(ea_t ea, uint64 x)
{
	return patch_byte(ea, x);
}

static bool ida_patch_word(ea_t ea, uint64 x)
{
	return patch_word(ea, x);
}

static bool ida_patch_dword(ea_t ea, uint64 x)
{
	return patch_dword(ea, x);
}

static bool ida_patch_qword(ea_t ea, uint64 x)
{
	return patch_qword(ea, x);
}

static bool ida_revert_byte(ea_t ea)
{
	return revert_byte(ea);
}

static void ida_add_byte(ea_t ea, uint32 value)
{
	return add_byte(ea, value);
}

static void ida_add_word(ea_t ea, uint64 value)
{
	return add_word(ea, value);
}

static void ida_add_dword(ea_t ea, uint64 value)
{
	return add_dword(ea, value);
}

static void ida_add_qword(ea_t ea, uint64 value)
{
	return add_qword(ea, value);
}

// bool ida_export get_zero_ranges(rangeset_t *zranges, const range_t *range)

static ssize_t ida_get_bytes(IntPtr buffer, ssize_t size, ea_t ea, int gmb_flafs, IntPtr mask)
{
	return get_bytes(buffer.ToPointer(), size, ea, gmb_flafs, mask.ToPointer());
}

static void ida_put_bytes(ea_t ea, IntPtr ptr, size_t size)
{
	void* buf = (void*)(ptr.ToPointer());
	put_bytes(ea, buf, size);
}

static void ida_patch_bytes(ea_t ea, IntPtr ptr, size_t size)
{
	void* buf = (void*)(ptr.ToPointer());
	patch_bytes(ea, buf, size);
}

static bool ida_is_code(flags_t F) 
{ 
	return (F & MS_CLS) == FF_CODE; 
}

static bool ida_f_is_code(flags_t F, IntPtr ptr) 
{ 
	return is_code(F); 
}

static bool ida_is_tail(flags_t F) 
{ 
	return (F & MS_CLS) == FF_TAIL; 
}

static bool ida_f_is_tail(flags_t F, IntPtr ptr) 
{ 
	return is_tail(F); 
}

static bool ida_is_not_tail(flags_t F) 
{ 
	return !is_tail(F); 
}

static bool ida_f_is_not_tail(flags_t F,IntPtr ptr) 
{ 
	return is_not_tail(F); 
}

static bool ida_is_unknown(flags_t F) 
{ 
	return (F & MS_CLS) == FF_UNK; 
}

static bool ida_is_head(flags_t F) 
{ 
	return (F & FF_DATA) != 0; 
}

static bool ida_f_is_head(flags_t F, IntPtr ptr) 
{ 
	return is_head(F); 
}

// typedef bool idaapi may_destroy_cb_t(ea_t)
//bool ida_export del_items(
//	ea_t ea,
//	int flags = 0,
//	asize_t nbytes = 1,
//	may_destroy_cb_t* may_destroy = nullptr)

static bool ida_is_manual_insn(ea_t ea)
{
	return is_manual_insn(ea);
}

// ssize_t ida_export get_manual_insn(qstring *buf, ea_t ea)

// void ida_export set_manual_insn(ea_t ea, const char *manual_insn)

static bool ida_is_flow(flags_t F)
{
	return (F & FF_FLOW) != 0;
}

static bool ida_has_extra_cmts(flags_t F)
{
	return (F & FF_LINE) != 0;
}

static bool ida_f_has_extra_cmts(flags_t f, IntPtr ptr)
{
	return has_extra_cmts(f);
}

static bool ida_has_cmt(flags_t F)
{
	return (F & FF_COMM) != 0;
}

static bool ida_f_has_cmt(flags_t f, IntPtr ptr)
{
	return has_cmt(f);
}

static bool ida_has_xref(flags_t F)
{
	return (F & FF_REF) != 0;
}

static bool ida_f_has_xref(flags_t f, IntPtr ptr)
{
	return has_xref(f);
}

static bool ida_has_name(flags_t F)
{
	return (F & FF_NAME) != 0;
}

static bool ida_f_has_name(flags_t f, IntPtr ptr)
{
	return has_name(f);
}

static bool ida_has_dummy_name(flags_t F)
{
	return (F & FF_ANYNAME) == FF_LABL;
}

static bool ida_f_has_dummy_name(flags_t f, IntPtr ptr)
{
	return has_dummy_name(f);
}

static bool ida_has_auto_name(flags_t F)
{
	return (F & FF_ANYNAME) == FF_ANYNAME;
}

static bool ida_has_any_name(flags_t F)
{
	return (F & FF_ANYNAME) != 0;
}

static bool ida_has_user_name(flags_t F)
{
	return (F & FF_ANYNAME) == FF_NAME;
}

static bool ida_f_has_user_name(flags_t F, IntPtr ptr)
{
	return has_user_name(F);
}

static bool ida_is_invsign(ea_t ea, flags_t F, int n)
{
	return is_invsign(ea, F, n);
}

static bool ida_toggle_sign(ea_t ea, int n)
{
	return toggle_sign(ea, n);
}

static bool ida_is_bnot(ea_t ea, flags_t F, int n)
{
	return is_bnot(ea, F, n);
}

static bool ida_toggle_bnot(ea_t ea, int n)
{
	return toggle_bnot(ea, n);
}

static bool ida_is_lzero(ea_t ea, int n)
{
	return is_lzero(ea, n);
}

static bool ida_set_lzero(ea_t ea, int n)
{
	return set_lzero(ea, n);
}

static bool ida_clr_lzero(ea_t ea, int n)
{
	return clr_lzero(ea, n);
}

static bool ida_toggle_lzero(ea_t ea, int n)  
{
	return (is_lzero(ea, n) ? clr_lzero : set_lzero)(ea, n);
}

static bool ida_leading_zero_important(ea_t ea, int n)
{
	return leading_zero_important(ea, n);
}

static bool ida_is_defarg0(flags_t F)
{
	return (F & MS_0TYPE) != FF_0VOID;
}

static bool ida_is_defarg1(flags_t F)
{
	return (F & MS_1TYPE) != FF_1VOID;
}

static bool ida_is_off0(flags_t F)
{
	return (F & MS_0TYPE) == FF_0OFF;
}

static bool ida_is_off1(flags_t F)
{
	return (F & MS_1TYPE) == FF_1OFF;
}

static bool ida_is_char0(flags_t F)
{
	return (F & MS_0TYPE) == FF_0CHAR;
}

static bool ida_is_char1(flags_t F)
{
	return (F & MS_1TYPE) == FF_1CHAR;
}

static bool ida_is_seg0(flags_t F)
{
	return (F & MS_0TYPE) == FF_0SEG;
}

static bool ida_is_seg1(flags_t F)
{
	return (F & MS_1TYPE) == FF_1SEG;
}

static bool ida_is_enum0(flags_t F)
{
	return (F & MS_0TYPE) == FF_0ENUM;
}

static bool ida_is_enum1(flags_t F)
{
	return (F & MS_1TYPE) == FF_1ENUM;
}

static bool ida_is_stroff0(flags_t F)
{
	return (F & MS_0TYPE) == FF_0STRO;
}

static bool ida_is_stroff1(flags_t F)
{
	return (F & MS_1TYPE) == FF_1STRO;
}

static bool ida_is_stkvar0(flags_t F)
{
	return (F & MS_0TYPE) == FF_0STK;
}

static bool ida_is_stkvar1(flags_t F)
{
	return (F & MS_1TYPE) == FF_1STK;
}

static bool ida_is_float0(flags_t F)
{
	return (F & MS_0TYPE) == FF_0FLT;
}

static bool ida_is_float1(flags_t F)
{
	return (F & MS_1TYPE) == FF_1FLT;
}

static bool ida_is_custfmt0(flags_t F)
{
	return (F & MS_0TYPE) == FF_0CUST;
}

static bool ida_is_custfmt1(flags_t F)
{
	return (F & MS_1TYPE) == FF_1CUST;
}

static bool ida_is_numop0(flags_t F)
{
	return is_numop0(F);
}

static bool ida_is_numop1(flags_t F)
{
	return is_numop1(F);
}

static flags_t ida_get_optype_flags0(flags_t F) 
{ 
	return F & MS_0TYPE; 
}

static flags_t ida_get_optype_flags1(flags_t F) 
{ 
	return F & MS_1TYPE; 
}

static bool ida_is_defarg(flags_t F, int n)
{
	return is_defarg(F, n);
}

static bool ida_is_off(flags_t F, int n)
{
	return is_off(F, n);
}

static bool ida_is_char(flags_t F, int n)
{
	return is_char(F, n);
}

static bool ida_is_seg(flags_t F, int n)
{
	return is_seg(F, n);
}

static bool ida_is_enum(flags_t F, int n)
{
	return is_enum(F, n);
}

static bool ida_is_manual(flags_t F, int n)
{
	return is_manual(F, n);
}

static bool ida_is_stroff(flags_t F, int n)
{
	return is_stroff(F, n);
}

static bool ida_is_stkvar(flags_t F, int n)
{
	return is_stkvar(F, n);
}

static bool ida_is_fltnum(flags_t F, int n)
{
	return is_fltnum(F, n);
}

static bool ida_is_custfmt(flags_t F, int n)
{
	return is_custfmt(F, n);
}

static bool ida_is_numop(flags_t F, int n)
{
	return is_numop(F, n);
}

static bool ida_is_suspop(ea_t ea, flags_t F, int n)
{
	return is_suspop(ea, F, n);
}

static bool ida_op_adds_xrefs(flags_t F, int n)
{
	return op_adds_xrefs(F, n);
}

static bool ida_set_op_type(ea_t ea, flags_t type, int n)
{
	return set_op_type(ea, type, n);
}

static bool ida_op_seg(ea_t ea, int n)
{
	return op_seg(ea, n);
}

static bool ida_op_enum(ea_t ea, int n, enum_t id, uchar serial)
{
	return op_enum(ea, n, id, serial);
}

// enum_t ida_export get_enum_id(uchar *serial, ea_t ea, int n)

//bool ida_export op_stroff(
//	const insn_t& insn,
//	int n,
//	const tid_t* path,
//	int path_len,
//	adiff_t delta)

//int ida_export get_stroff_path(tid_t *path, adiff_t *delta, ea_t ea, int n)

static bool ida_op_stkvar(ea_t ea, int n)
{
	return op_stkvar(ea, n);
}

// bool ida_export set_forced_operand(ea_t ea, int n, const char *op)

// ssize_t ida_export get_forced_operand(qstring *buf, ea_t ea, int n)

static bool ida_is_forced_operand(ea_t ea, int n)
{
	return is_forced_operand(ea, n);
}

static flags_t ida_char_flag()
{
	return FF_1CHAR | FF_0CHAR;
}

static flags_t ida_off_flag()
{
	return FF_1OFF | FF_0OFF;
}

static flags_t ida_enum_flag()
{
	return FF_1ENUM | FF_0ENUM;
}

static flags_t ida_stroff_flag()
{
	return FF_1STRO | FF_0STRO;
}

static flags_t ida_stkvar_flag()
{
	return FF_1STK | FF_0STK;
}

static flags_t ida_flt_flag()
{
	return FF_1FLT | FF_0FLT;
}

static flags_t ida_custfmt_flag()
{
	return FF_1CUST | FF_0CUST;
}

static flags_t ida_seg_flag()
{
	return FF_1SEG | FF_0SEG;
}

static flags_t ida_num_flag()
{
	return num_flag();
}

static flags_t ida_hex_flag()
{
	return FF_1NUMH | FF_0NUMH;
}

static flags_t ida_dec_flag()
{
	return FF_1NUMD | FF_0NUMD;
}

static flags_t ida_oct_flag()
{
	return FF_1NUMO | FF_0NUMO;
}

static flags_t ida_bin_flag()
{
	return FF_1NUMB | FF_0NUMB;
}

static bool ida_op_chr(ea_t ea, int n)
{
	return set_op_type(ea, char_flag(), n);
}

static bool ida_op_num(ea_t ea, int n)
{
	return set_op_type(ea, num_flag(), n);
}

static bool ida_op_hex(ea_t ea, int n)
{
	return set_op_type(ea, hex_flag(), n);
}

static bool ida_op_dec(ea_t ea, int n)
{
	return set_op_type(ea, dec_flag(), n);
}

static bool ida_op_oct(ea_t ea, int n)
{
	return set_op_type(ea, oct_flag(), n);
}

static bool ida_op_bin(ea_t ea, int n)
{
	return set_op_type(ea, bin_flag(), n);
}

static bool ida_op_flt(ea_t ea, int n)
{
	return set_op_type(ea, flt_flag(), n);
}

static bool ida_op_custfmt(ea_t ea, int n, int fid)
{
	return op_custfmt(ea, n, fid);
}

static bool ida_clr_op_type(ea_t ea, int n)
{
	return clr_op_type(ea, n);
}

static int ida_get_default_radix()
{
	return get_default_radix();
}

static int ida_get_radix(flags_t F, int n)
{
	return get_radix(F, n);
}

static flags_t ida_code_flag()
{
	return FF_CODE;
}

static flags_t ida_byte_flag()
{
	return FF_DATA | FF_BYTE;
}

static flags_t ida_word_flag()
{
	return FF_DATA | FF_WORD;
}

static flags_t ida_dword_flag()
{
	return FF_DATA | FF_DWORD;
}

static flags_t ida_qword_flag()
{
	return FF_DATA | FF_QWORD;
}

static flags_t ida_oword_flag()
{
	return FF_DATA | FF_OWORD;
}

static flags_t ida_yword_flag()
{
	return FF_DATA | FF_YWORD;
}

static flags_t ida_zword_flag()
{
	return FF_DATA | FF_ZWORD;
}

static flags_t ida_tbyte_flag()
{
	return FF_DATA | FF_TBYTE;
}

static flags_t ida_strlit_flag()
{
	return FF_DATA | FF_STRLIT;
}

static flags_t ida_stru_flag()
{
	return FF_DATA | FF_STRUCT;
}

static flags_t ida_cust_flag()
{
	return FF_DATA | FF_CUSTOM;
}

static flags_t ida_align_flag()
{
	return FF_DATA | FF_ALIGN;
}

static flags_t ida_float_flag()
{
	return FF_DATA | FF_FLOAT;
}

static flags_t ida_double_flag()
{
	return FF_DATA | FF_DOUBLE;
}

static flags_t ida_packreal_flag()
{
	return FF_DATA | FF_PACKREAL;
}

static bool ida_is_byte(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_BYTE;
}

static bool ida_is_word(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_WORD;
}

static bool ida_is_dword(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_DWORD;
}

static bool ida_is_qword(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_QWORD;
}

static bool ida_is_oword(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_OWORD;
}

static bool ida_is_yword(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_YWORD;
}

static bool ida_is_zword(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_ZWORD;
}

static bool ida_is_tbyte(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_TBYTE;
}

static bool ida_is_float(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_FLOAT;
}

static bool ida_is_double(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_DOUBLE;
}

static bool ida_is_pack_real(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_PACKREAL;
}

static bool ida_is_strlit(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_STRLIT;
}

static bool ida_is_struct(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_STRUCT;
}

static bool ida_is_align(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_ALIGN;
}

static bool ida_is_custom(flags_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_CUSTOM;
}

static bool ida_f_is_byte(flags_t F, IntPtr ptr)
{
	return is_byte(F);
}

static bool ida_f_is_word(flags_t F, IntPtr ptr)
{
	return is_word(F);
}

static bool ida_f_is_dword(flags_t F, IntPtr ptr)
{
	return is_dword(F);
}

static bool ida_f_is_qword(flags_t F, IntPtr ptr)
{
	return is_qword(F);
}

static bool ida_f_is_oword(flags_t F, IntPtr ptr)
{
	return is_oword(F);
}

static bool ida_f_is_yword(flags_t F, IntPtr ptr)
{
	return is_yword(F);
}

static bool ida_f_is_tbyte(flags_t F, IntPtr ptr)
{
	return is_tbyte(F);
}

static bool ida_f_is_float(flags_t F, IntPtr ptr)
{
	return is_float(F);
}

static bool ida_f_is_double(flags_t F, IntPtr ptr)
{
	return is_double(F);
}

static bool ida_f_is_pack_real(flags_t F, IntPtr ptr)
{
	return is_pack_real(F);
}

static bool ida_f_is_strlit(flags_t F, IntPtr ptr)
{
	return is_strlit(F);
}

static bool ida_f_is_struct(flags_t F, IntPtr ptr)
{
	return is_struct(F);
}

static bool ida_f_is_align(flags_t F, IntPtr ptr)
{
	return is_align(F);
}

static bool ida_f_is_custom(flags_t F, IntPtr ptr)
{
	return is_custom(F);
}

static bool ida_is_same_data_type(flags_t F1, flags_t F2)
{
	return ((F1 ^ F2) & DT_TYPE) == 0;
}

static flags_t ida_get_flags_by_size(size_t size)
{
	return get_flags_by_size(size);
}

static bool ida_create_data(ea_t ea, flags_t dataflag, asize_t size, tid_t tid)
{
	return create_data(ea, dataflag, size, tid);
}

static flags_t ida_calc_dflags(flags_t f, bool force)
{
	return f | (force ? FF_COMM : 0);
}

static bool ida_create_byte(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_BYTE, force), length, BADNODE);
}

static bool ida_create_word(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_WORD, force), length, BADNODE);
}

static bool ida_create_dword(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_DWORD, force), length, BADNODE);
}

static bool ida_create_qword(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_QWORD, force), length, BADNODE);
}

static bool ida_create_oword(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_OWORD, force), length, BADNODE);
}

static bool ida_create_yword(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_YWORD, force), length, BADNODE);
}

static bool ida_create_zword(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_ZWORD, force), length, BADNODE);
}

static bool ida_create_tbyte(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_TBYTE, force), length, BADNODE);
}

static bool ida_create_float(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_FLOAT, force), length, BADNODE);
}

static bool ida_create_double(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_DOUBLE, force), length, BADNODE);
}

static bool ida_create_packed_real(ea_t ea, asize_t length, bool force)
{
	return create_data(ea, calc_dflags(FF_PACKREAL, force), length, BADNODE);
}

static bool ida_create_struct(ea_t ea, asize_t length, tid_t tid, bool force)
{
	return create_data(ea, calc_dflags(FF_STRUCT, force), length, tid);
}

static bool ida_create_custdata(ea_t ea, asize_t length, int dtid, int fid, bool force)
{
	return create_data(ea, calc_dflags(FF_CUSTOM, force), length, dtid | (fid << 16));
}

static bool ida_create_align(ea_t ea, asize_t length, int alignment)
{
	return create_align(ea, length, alignment);
}

static int ida_calc_min_align(asize_t length)
{
	return calc_min_align(length);
}

static int ida_calc_max_align(ea_t endea)
{
	return calc_max_align(endea);
}

static int ida_calc_def_align(ea_t ea, int mina, int maxa)
{
	return calc_def_align(ea, mina, maxa);
}

static bool ida_create_16bit_data(ea_t ea, asize_t length)
{
	return create_16bit_data(ea, length);
}

static bool ida_create_32bit_data(ea_t ea, asize_t length)
{
	return create_32bit_data(ea, length);
}

static size_t ida_get_max_strlit_length(ea_t ea, int32 strtype, int options)
{
	return get_max_strlit_length(ea, strtype, options);
}

//idaman ssize_t ida_export get_strlit_contents(
//	qstring* utf8,
//	ea_t ea,
//	size_t len,
//	int32 type,
//	size_t* maxcps = nullptr,
//	int flags = 0);


static bool ida_create_strlit(ea_t start, size_t len, int32 strtype)
{
	return create_strlit(start, len, strtype);
}

// to continue
static bool ida_can_define_item(ea_t ea, asize_t length, flags_t flags)
{
	return can_define_item(ea, length, flags);
}

static bool ida_has_immd(flags_t F)
{
	return is_code(F) && (F & FF_IMMD) != 0;
}

static bool ida_is_func(flags_t F)
{
	return is_code(F) && (F & FF_FUNC) != 0;
}

static bool ida_set_immd(ea_t ea)
{
	return set_immd(ea);
}

static bool ida_unregister_custom_data_type(int dtid)
{
	return unregister_custom_data_type(dtid);
}

static bool ida_unregister_custom_data_format(int dfid)
{
	return unregister_custom_data_format(dfid);
}

static bool ida_attach_custom_data_format(int dtid, int dfid)
{
	return attach_custom_data_format(dtid, dfid);
}

static bool ida_detach_custom_data_format(int dtid, int dfid)
{
	return detach_custom_data_format(dtid, dfid);
}

static bool ida_is_attached_custom_data_format(int dtid, int dfid)
{
	return is_attached_custom_data_format(dtid, dfid);
}

//idaman int ida_export get_custom_data_types(
//	intvec_t* out,
//	asize_t min_size = 0,
//  asize_t max_size = BADADDR);

// idaman int ida_export get_custom_data_formats(intvec_t *out, int dtid);

// idaman int ida_export find_custom_data_type(const char *name);

// idaman int ida_export find_custom_data_format(const char *name);

// idaman bool ida_export set_cmt(ea_t ea, const char *comm, bool rptble);

// idaman ssize_t ida_export get_cmt(qstring *buf, ea_t ea, bool rptble);

// idaman bool ida_export append_cmt(ea_t ea, const char *str, bool rptble);

//idaman ssize_t ida_export get_predef_insn_cmt(
//	qstring* buf,
//	const insn_t& ins);

static ea_t ida_find_byte(ea_t sEA, asize_t size, uchar value, int bin_search_flags)
{
	return find_byte(sEA, size, value, bin_search_flags);
}

static ea_t ida_find_byter(ea_t sEA, asize_t size, uchar value, int bin_search_flags)
{
	return find_byter(sEA, size, value, bin_search_flags);
}

static bool ida_update_hidden_range(IntPtr ha)
{
	return update_hidden_range((const hidden_range_t*)(ha.ToPointer()));
}

static bool ida_add_hidden_range(ea_t ea1, ea_t ea2, IntPtr description, IntPtr header, IntPtr footer, bgcolor_t color)
{
	return add_hidden_range(ea1, ea2, (const char*)(description.ToPointer()), (const char*)(header.ToPointer()), (const char*)(footer.ToPointer()), color);
}

static IntPtr ida_get_hidden_range(ea_t ea)
{
	return IntPtr((void*)get_hidden_range(ea));
}

static IntPtr ida_getn_hidden_range(int n)
{
	return IntPtr((void*)getn_hidden_range(n));
}

static int ida_get_hidden_range_qty()
{
	return get_hidden_range_qty();
}

static int ida_get_hidden_range_num(ea_t ea)
{
	return get_hidden_range_num(ea);
}

static IntPtr ida_get_prev_hidden_range(ea_t ea)
{
	return IntPtr((void*)get_prev_hidden_range(ea));
}

static IntPtr ida_get_next_hidden_range(ea_t ea)
{
	return IntPtr((void*)get_next_hidden_range(ea));
}

static IntPtr ida_get_first_hidden_range()
{
	return IntPtr((void*)get_first_hidden_range());
}

static IntPtr ida_get_last_hidden_range()
{
	return IntPtr((void*)get_last_hidden_range());
}

static bool ida_del_hidden_range(ea_t ea)
{
	return del_hidden_range(ea);
}

static bool ida_add_mapping(ea_t from, ea_t to, asize_t size)
{
	return add_mapping(from, to, size);
}

static void ida_del_mapping(ea_t ea)
{
	return del_mapping(ea);
}

static ea_t ida_use_mapping(ea_t ea)
{
	return use_mapping(ea);
}

static size_t ida_get_mappings_qty()
{
	return get_mappings_qty();
}

static bool ida_get_mapping(IntPtr from, IntPtr to, IntPtr size, size_t n)
{
	return get_mapping((ea_t*)(from.ToPointer()), (ea_t*)(to.ToPointer()), (asize_t*)(size.ToPointer()), n);
}

#ifdef OBSOLETE_FUNCS
static uchar ida_get_8bit(IntPtr ea, IntPtr v, IntPtr nbit)
{
	return get_8bit((ea_t*)(ea.ToPointer()), (uint32*)(v.ToPointer()), (int*)(nbit.ToPointer()));
}

static uchar ida_get_octet(IntPtr ea, IntPtr v, IntPtr nbit)
{
	return get_octet((ea_t*)(ea.ToPointer()), (uint64*)(v.ToPointer()), (int*)(nbit.ToPointer()));
}

static ea_t ida_free_chunk(ea_t bottom, asize_t size, int32 step)
{
	return free_chunk(bottom, size, step);
}
#endif

// binpat
static ea_t ida_find_binary2(ea_t start_ea, ea_t end_ea, IntPtr pattern, IntPtr errorString)
{
	compiled_binpat_vec_t searchVec;
	qstring errorStr;
	if (parse_binpat_str(&searchVec, start_ea, (char*)(pattern.ToPointer()), 16, PBSENC_DEF1BPU, &errorStr))
	{
		if (errorString != IntPtr::Zero)
		{
			::ConvertQstringToIntPtr(errorStr, errorString, 1024);
		}

		return bin_search2(start_ea, end_ea, searchVec, (BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW));
	}
	else
		return BADADDR;
}


