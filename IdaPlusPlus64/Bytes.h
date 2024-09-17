#pragma once

// complete

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate int Func_int_UInt64_long_UInt64_UInt64___IntPtr(unsigned long long ea, long long fpos, unsigned long long o, unsigned long long v, ::System::IntPtr ud);

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

static ea_t ida_next_that(ea_t ea, ea_t maxea, IntPtr testf, IntPtr ud)
{
	return next_that(ea, maxea, (testf_t*)(testf.ToPointer()), (void*)(ud.ToPointer()));
}

static ea_t ida_next_unknown(ea_t ea, ea_t maxea)
{
	return next_that(ea, maxea, nullptr);
}

static ea_t ida_prev_that(ea_t ea, ea_t minea, IntPtr testf, IntPtr ud)
{
	return prev_that(ea, minea, (testf_t*)(testf.ToPointer()), (void*)(ud.ToPointer()));
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

static flags64_t ida_get_flags_ex(ea_t ea, int how)
{
	return get_flags_ex(ea, how);
}

static flags64_t ida_get_flags(ea_t ea)
{
	return get_flags_ex(ea, 0);
}

static flags64_t ida_get_full_flags(ea_t ea)
{
	return get_flags_ex(ea, GFE_VALUE);
}

static flags64_t ida_get_item_flag(ea_t from, int n, ea_t ea, bool appzero)
{
	return get_item_flag(from, n, ea, appzero);
}

static bool ida_has_value(flags64_t F)
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

static bool ida_get_octet2(IntPtr out, IntPtr ogen)
{
	return get_octet2((uchar*)(out.ToPointer()), (octet_generator_t*)(ogen.ToPointer()));
}

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

static bool ida_get_data_value(IntPtr v, ea_t ea, asize_t size)
{
	return get_data_value((uval_t*)(v.ToPointer()), ea, size);
}

static int ida_visit_patched_bytes(ea_t ea1, ea_t ea2, Func_int_UInt64_long_UInt64_UInt64___IntPtr^ cb, IntPtr ud)
{
	return visit_patched_bytes(ea1, ea2, static_cast<int (*)(ea_t, int64, uint64, uint64, void*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(cb).ToPointer()), (void*)(ud.ToPointer()));
}

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

static bool ida_get_zero_ranges(IntPtr zranges, IntPtr range)
{
	return get_zero_ranges((rangeset_t*)(zranges.ToPointer()), (const range_t*)(range.ToPointer()));
}

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

static bool ida_is_code(flags64_t F)
{
	return (F & MS_CLS) == FF_CODE;
}

static bool ida_f_is_code(flags64_t F, IntPtr ptr)
{
	return is_code(F);
}

static bool ida_is_data(flags64_t F)
{
	return (F & MS_CLS) == FF_DATA;
}

static bool ida_f_is_data(flags64_t F, IntPtr ptr)
{
	return is_data(F);
}

static bool ida_is_tail(flags64_t F)
{
	return (F & MS_CLS) == FF_TAIL;
}

static bool ida_f_is_tail(flags64_t F, IntPtr ptr)
{
	return is_tail(F);
}

static bool ida_is_not_tail(flags64_t F)
{
	return !is_tail(F);
}

static bool ida_f_is_not_tail(flags64_t F, IntPtr ptr)
{
	return is_not_tail(F);
}

static bool ida_is_unknown(flags64_t F)
{
	return (F & MS_CLS) == FF_UNK;
}

static bool ida_is_head(flags64_t F)
{
	return (F & FF_DATA) != 0;
}

static bool ida_f_is_head(flags64_t F, IntPtr ptr)
{
	return is_head(F);
}

static bool ida_del_items(ea_t ea, int flags, asize_t nbytes, System::Func<bool, unsigned long long>^ may_destroy)
{
	return del_items(ea, flags, nbytes, static_cast<may_destroy_cb_t*>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(may_destroy).ToPointer()));
}

static bool ida_is_manual_insn(ea_t ea)
{
	return is_manual_insn(ea);
}

static ssize_t ida_get_manual_insn(IntPtr buf, ea_t ea)
{
	qstring out;
	ssize_t len = get_manual_insn(&out, ea);
	if (buf != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, len);
	}
	return len;
}

static void ida_set_manual_insn(ea_t ea, IntPtr manual_insn)
{
	set_manual_insn(ea, (const char*)(manual_insn.ToPointer()));
}

static bool ida_is_flow(flags64_t F)
{
	return (F & FF_FLOW) != 0;
}

static bool ida_has_extra_cmts(flags64_t F)
{
	return (F & FF_LINE) != 0;
}

static bool ida_f_has_extra_cmts(flags64_t f, IntPtr ptr)
{
	return has_extra_cmts(f);
}

static bool ida_has_cmt(flags64_t F)
{
	return (F & FF_COMM) != 0;
}

static bool ida_f_has_cmt(flags64_t f, IntPtr ptr)
{
	return has_cmt(f);
}

static bool ida_has_xref(flags64_t F)
{
	return (F & FF_REF) != 0;
}

static bool ida_f_has_xref(flags64_t f, IntPtr ptr)
{
	return has_xref(f);
}

static bool ida_has_name(flags64_t F)
{
	return (F & FF_NAME) != 0;
}

static bool ida_f_has_name(flags64_t f, IntPtr ptr)
{
	return has_name(f);
}

static bool ida_has_dummy_name(flags64_t F)
{
	return (F & FF_ANYNAME) == FF_LABL;
}

static bool ida_f_has_dummy_name(flags64_t f, IntPtr ptr)
{
	return has_dummy_name(f);
}

static bool ida_has_auto_name(flags64_t F)
{
	return (F & FF_ANYNAME) == FF_ANYNAME;
}

static bool ida_has_any_name(flags64_t F)
{
	return (F & FF_ANYNAME) != 0;
}

static bool ida_has_user_name(flags64_t F)
{
	return (F & FF_ANYNAME) == FF_NAME;
}

static bool ida_f_has_user_name(flags64_t F, IntPtr ptr)
{
	return has_user_name(F);
}

static bool ida_is_invsign(ea_t ea, flags64_t F, int n)
{
	return is_invsign(ea, F, n);
}

static bool ida_toggle_sign(ea_t ea, int n)
{
	return toggle_sign(ea, n);
}

static bool ida_is_bnot(ea_t ea, flags64_t F, int n)
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

static int ida_get_operand_type_shift(uint32 n)
{
	return 20 + (4 * (n + (n > 1)));
}

static flags64_t ida_get_operand_flag(uint8 typebits, int n)
{
	return n >= 0 && n < UA_MAXOP ? flags64_t(typebits) << get_operand_type_shift(n) : 0;
}

static bool ida_is_flag_for_operand(flags64_t F, uint8 typebits, int n)
{
	return n < UA_MAXOP && (F & get_operand_flag(15ULL, n)) == get_operand_flag(typebits, n);
}

static bool ida_is_defarg0(flags64_t F)
{
	return !is_flag_for_operand(F, FF_N_VOID, 0);
}

static bool ida_is_defarg1(flags64_t F)
{
	return !is_flag_for_operand(F, FF_N_VOID, 1);
}

static bool ida_is_off0(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_OFF, 0);
}

static bool ida_is_off1(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_OFF, 1);
}

static bool ida_is_char0(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_CHAR, 0);
}

static bool ida_is_char1(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_CHAR, 1);
}

static bool ida_is_seg0(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_SEG, 0);
}

static bool ida_is_seg1(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_SEG, 1);
}

static bool ida_is_enum0(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_ENUM, 0);
}

static bool ida_is_enum1(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_ENUM, 1);
}

static bool ida_is_stroff0(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_STRO, 0);
}

static bool ida_is_stroff1(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_STRO, 1);
}

static bool ida_is_stkvar0(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_STK, 0);
}

static bool ida_is_stkvar1(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_STK, 1);
}

static bool ida_is_float0(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_FLT, 0);
}

static bool ida_is_float1(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_FLT, 1);
}

static bool ida_is_custfmt0(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_CUST, 0);
}

static bool ida_is_custfmt1(flags64_t F)
{
	return is_flag_for_operand(F, FF_N_CUST, 1);
}

static bool ida_is_numop0(flags64_t F)
{
	return is_numop0(F);
}

static bool ida_is_numop1(flags64_t F)
{
	return is_numop1(F);
}

static flags64_t ida_get_optype_flags0(flags64_t F)
{
	return F & (MS_N_TYPE << get_operand_type_shift(0));
}

static flags64_t ida_get_optype_flags1(flags64_t F)
{
	return F & (MS_N_TYPE << get_operand_type_shift(1));
}

static bool ida_is_defarg(flags64_t F, int n)
{
	return is_defarg(F, n);
}

static bool ida_is_off(flags64_t F, int n)
{
	return is_off(F, n);
}

static bool ida_is_char(flags64_t F, int n)
{
	return is_char(F, n);
}

static bool ida_is_seg(flags64_t F, int n)
{
	return is_seg(F, n);
}

static bool ida_is_enum(flags64_t F, int n)
{
	return is_enum(F, n);
}

static bool ida_is_manual(flags64_t F, int n)
{
	return is_manual(F, n);
}

static bool ida_is_stroff(flags64_t F, int n)
{
	return is_stroff(F, n);
}

static bool ida_is_stkvar(flags64_t F, int n)
{
	return is_stkvar(F, n);
}

static bool ida_is_fltnum(flags64_t F, int n)
{
	return is_fltnum(F, n);
}

static bool ida_is_custfmt(flags64_t F, int n)
{
	return is_custfmt(F, n);
}

static bool ida_is_numop(flags64_t F, int n)
{
	return is_numop(F, n);
}

static bool ida_is_suspop(ea_t ea, flags64_t F, int n)
{
	return is_suspop(ea, F, n);
}

static bool ida_op_adds_xrefs(flags64_t F, int n)
{
	return op_adds_xrefs(F, n);
}

static bool ida_set_op_type(ea_t ea, flags64_t type, int n)
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

static enum_t ida_get_enum_id(IntPtr serial, ea_t ea, int n)
{
	return get_enum_id((uchar*)(serial.ToPointer()), ea, n);
}

static bool ida_op_stroff(IntPtr insn, int n, IntPtr path, int path_len, adiff_t delta)
{
	return op_stroff(*(insn_t*)(insn.ToPointer()), n, (tid_t*)(path.ToPointer()), path_len, delta);
}

static int ida_get_stroff_path(IntPtr path, IntPtr delta, ea_t ea, int n)
{
	return get_stroff_path((tid_t*)(path.ToPointer()), (adiff_t*)(delta.ToPointer()), ea, n);
}

static bool ida_op_stkvar(ea_t ea, int n)
{
	return op_stkvar(ea, n);
}

static bool ida_set_forced_operand(ea_t ea, int n, IntPtr op)
{
	return set_forced_operand(ea, n, (const char*)(op.ToPointer()));
}

static ssize_t ida_get_forced_operand(IntPtr buf, ea_t ea, int n)
{
	qstring out;
	ssize_t len = get_forced_operand(&out, ea, n);
	if (buf != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, len);
	}
	return len;
}

static bool ida_is_forced_operand(ea_t ea, int n)
{
	return is_forced_operand(ea, n);
}

static flags64_t ida_combine_flags(flags64_t F)
{
	return (F << get_operand_type_shift(0))
		| (F << get_operand_type_shift(1))
		| (F << get_operand_type_shift(2))
		| (F << get_operand_type_shift(3))
		| (F << get_operand_type_shift(4))
		| (F << get_operand_type_shift(5))
		| (F << get_operand_type_shift(6))
		| (F << get_operand_type_shift(7));
}

static flags64_t ida_char_flag()
{
	return combine_flags(3);
}

static flags64_t ida_off_flag()
{
	return combine_flags(5);
}

static flags64_t ida_enum_flag()
{
	return combine_flags(8);
}

static flags64_t ida_stroff_flag()
{
	return combine_flags(10);
}

static flags64_t ida_stkvar_flag()
{
	return combine_flags(11);
}

static flags64_t ida_flt_flag()
{
	return combine_flags(12);
}

static flags64_t ida_custfmt_flag()
{
	return combine_flags(13);
}

static flags64_t ida_seg_flag()
{
	return combine_flags(4);
}

static flags64_t ida_num_flag()
{
	return num_flag();
}

static flags64_t ida_hex_flag()
{
	return combine_flags(1);
}

static flags64_t ida_dec_flag()
{
	return combine_flags(2);
}

static flags64_t ida_oct_flag()
{
	return combine_flags(7);
}

static flags64_t ida_bin_flag()
{
	return combine_flags(6);
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

static int ida_get_radix(flags64_t F, int n)
{
	return get_radix(F, n);
}

static flags64_t ida_code_flag()
{
	return FF_CODE;
}

static flags64_t ida_byte_flag()
{
	return FF_DATA | FF_BYTE;
}

static flags64_t ida_word_flag()
{
	return FF_DATA | FF_WORD;
}

static flags64_t ida_dword_flag()
{
	return FF_DATA | FF_DWORD;
}

static flags64_t ida_qword_flag()
{
	return FF_DATA | FF_QWORD;
}

static flags64_t ida_oword_flag()
{
	return FF_DATA | FF_OWORD;
}

static flags64_t ida_yword_flag()
{
	return FF_DATA | FF_YWORD;
}

static flags64_t ida_zword_flag()
{
	return FF_DATA | FF_ZWORD;
}

static flags64_t ida_tbyte_flag()
{
	return FF_DATA | FF_TBYTE;
}

static flags64_t ida_strlit_flag()
{
	return FF_DATA | FF_STRLIT;
}

static flags64_t ida_stru_flag()
{
	return FF_DATA | FF_STRUCT;
}

static flags64_t ida_cust_flag()
{
	return FF_DATA | FF_CUSTOM;
}

static flags64_t ida_align_flag()
{
	return FF_DATA | FF_ALIGN;
}

static flags64_t ida_float_flag()
{
	return FF_DATA | FF_FLOAT;
}

static flags64_t ida_double_flag()
{
	return FF_DATA | FF_DOUBLE;
}

static flags64_t ida_packreal_flag()
{
	return FF_DATA | FF_PACKREAL;
}

static bool ida_is_byte(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_BYTE;
}

static bool ida_is_word(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_WORD;
}

static bool ida_is_dword(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_DWORD;
}

static bool ida_is_qword(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_QWORD;
}

static bool ida_is_oword(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_OWORD;
}

static bool ida_is_yword(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_YWORD;
}

static bool ida_is_zword(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_ZWORD;
}

static bool ida_is_tbyte(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_TBYTE;
}

static bool ida_is_float(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_FLOAT;
}

static bool ida_is_double(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_DOUBLE;
}

static bool ida_is_pack_real(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_PACKREAL;
}

static bool ida_is_strlit(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_STRLIT;
}

static bool ida_is_struct(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_STRUCT;
}

static bool ida_is_align(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_ALIGN;
}

static bool ida_is_custom(flags64_t F)
{
	return is_data(F) && (F & DT_TYPE) == FF_CUSTOM;
}

static bool ida_f_is_byte(flags64_t F, IntPtr ptr)
{
	return is_byte(F);
}

static bool ida_f_is_word(flags64_t F, IntPtr ptr)
{
	return is_word(F);
}

static bool ida_f_is_dword(flags64_t F, IntPtr ptr)
{
	return is_dword(F);
}

static bool ida_f_is_qword(flags64_t F, IntPtr ptr)
{
	return is_qword(F);
}

static bool ida_f_is_oword(flags64_t F, IntPtr ptr)
{
	return is_oword(F);
}

static bool ida_f_is_yword(flags64_t F, IntPtr ptr)
{
	return is_yword(F);
}

static bool ida_f_is_tbyte(flags64_t F, IntPtr ptr)
{
	return is_tbyte(F);
}

static bool ida_f_is_float(flags64_t F, IntPtr ptr)
{
	return is_float(F);
}

static bool ida_f_is_double(flags64_t F, IntPtr ptr)
{
	return is_double(F);
}

static bool ida_f_is_pack_real(flags64_t F, IntPtr ptr)
{
	return is_pack_real(F);
}

static bool ida_f_is_strlit(flags64_t F, IntPtr ptr)
{
	return is_strlit(F);
}

static bool ida_f_is_struct(flags64_t F, IntPtr ptr)
{
	return is_struct(F);
}

static bool ida_f_is_align(flags64_t F, IntPtr ptr)
{
	return is_align(F);
}

static bool ida_f_is_custom(flags64_t F, IntPtr ptr)
{
	return is_custom(F);
}

static bool ida_is_same_data_type(flags64_t F1, flags64_t F2)
{
	return ((F1 ^ F2) & DT_TYPE) == 0;
}

static flags64_t ida_get_flags_by_size(size_t size)
{
	return get_flags_by_size(size);
}

static bool ida_create_data(ea_t ea, flags64_t dataflag, asize_t size, tid_t tid)
{
	return create_data(ea, dataflag, size, tid);
}

static flags64_t ida_calc_dflags(flags64_t f, bool force)
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

static ssize_t ida_get_strlit_contents(IntPtr utf8, ea_t ea, size_t len, int32 type, IntPtr maxcps, int flags)
{
	qstring out;
	auto len2 = get_strlit_contents(&out, ea, len, type, (size_t*)(maxcps.ToPointer()), flags);
	if (utf8 != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, utf8, len2);
	}
	return len2;
}

static bool ida_create_strlit(ea_t start, size_t len, int32 strtype)
{
	return create_strlit(start, len, strtype);
}

static bool ida_print_strlit_type(IntPtr out, int32 strtype, IntPtr out_tooltip, int flags)
{
	return print_strlit_type((qstring*)(out.ToPointer()), strtype, (qstring*)(out_tooltip.ToPointer()), flags);
}

static IntPtr ida_get_opinfo(IntPtr buf, ea_t ea, int n, flags64_t flags)
{
	return IntPtr((void*)get_opinfo((opinfo_t*)(buf.ToPointer()), ea, n, flags));
}

static bool ida_set_opinfo(ea_t ea, int n, flags64_t flag, IntPtr ti, bool suppress_events)
{
	return set_opinfo(ea, n, flag, (const opinfo_t*)(ti.ToPointer()), suppress_events);
}

static asize_t ida_get_data_elsize(ea_t ea, flags64_t F, IntPtr ti)
{
	return get_data_elsize(ea, F, (const opinfo_t*)(ti.ToPointer()));
}

static asize_t ida_get_full_data_elsize(ea_t ea, flags64_t F, IntPtr ti)
{
	asize_t nbytes = get_data_elsize(ea, F, (const opinfo_t*)(ti.ToPointer()));
	return nbytes * bytesize(ea);
}

static int ida_is_varsize_item(ea_t ea, flags64_t F, IntPtr ti, IntPtr itemsize)
{
	return is_varsize_item(ea, F, (const opinfo_t*)(ti.ToPointer()), (asize_t*)(itemsize.ToPointer()));
}

static bool ida_can_define_item(ea_t ea, asize_t length, flags64_t flags)
{
	return can_define_item(ea, length, flags);
}

static bool ida_has_immd(flags64_t F)
{
	return is_code(F) && (F & FF_IMMD) != 0;
}

static bool ida_is_func(flags64_t F)
{
	return is_code(F) && (F & FF_FUNC) != 0;
}

static bool ida_set_immd(ea_t ea)
{
	return set_immd(ea);
}

static int ida_register_custom_data_type(IntPtr dtinfo)
{
	return register_custom_data_type((const data_type_t*)(dtinfo.ToPointer()));
}

static bool ida_unregister_custom_data_type(int dtid)
{
	return unregister_custom_data_type(dtid);
}

static int ida_register_custom_data_format(IntPtr dtform)
{
	return register_custom_data_format((const data_format_t*)(dtform.ToPointer()));
}

static bool ida_unregister_custom_data_format(int dfid)
{
	return unregister_custom_data_format(dfid);
}

static IntPtr ida_get_custom_data_type(int dtid)
{
	return IntPtr((void*)get_custom_data_type(dtid));
}

static IntPtr ida_get_custom_data_format(int dfid)
{
	return IntPtr((void*)get_custom_data_format(dfid));
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

static int ida_get_custom_data_types(IntPtr out, asize_t min_size, asize_t max_size)
{
	return get_custom_data_types((intvec_t*)(out.ToPointer()), min_size, max_size);
}

static int ida_get_custom_data_formats(IntPtr out, int dtid)
{
	return get_custom_data_formats((intvec_t*)(out.ToPointer()), dtid);
}

static int ida_find_custom_data_type(IntPtr name)
{
	return find_custom_data_type((const char*)(name.ToPointer()));
}

static int ida_find_custom_data_format(IntPtr name)
{
	return find_custom_data_format((const char*)(name.ToPointer()));
}

static bool ida_set_cmt(ea_t ea, IntPtr comm, bool rptble)
{
	return set_cmt(ea, (const char*)(comm.ToPointer()), rptble);
}

static ssize_t ida_get_cmt(IntPtr buf, ea_t ea, bool rptble)
{
	qstring out;
	ssize_t len = get_cmt(&out, ea, rptble);
	if (buf != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, len);
	}
	return len;
}

static bool ida_append_cmt(ea_t ea, IntPtr str, bool rptble)
{
	return append_cmt(ea, (const char*)(str.ToPointer()), rptble);
}

static ssize_t ida_get_predef_insn_cmt(IntPtr buf, IntPtr ins)
{
	qstring out;
	ssize_t len = get_predef_insn_cmt(&out, *(const insn_t*)(ins.ToPointer()));
	if (buf != IntPtr::Zero)
	{
		::ConvertQstringToIntPtr(out, buf, len);
	}
	return len;
}

static ea_t ida_find_byte(ea_t sEA, asize_t size, uchar value, int bin_search_flags)
{
	return find_byte(sEA, size, value, bin_search_flags);
}

static ea_t ida_find_byter(ea_t sEA, asize_t size, uchar value, int bin_search_flags)
{
	return find_byter(sEA, size, value, bin_search_flags);
}

static bool ida_parse_binpat_str(IntPtr out, ea_t ea, IntPtr in, int radix, int strlits_encoding, IntPtr errbuf)
{
	return parse_binpat_str((compiled_binpat_vec_t*)(out.ToPointer()), ea, (const char*)(in.ToPointer()), radix, strlits_encoding, (qstring*)(errbuf.ToPointer()));
}

// bin_search2
static ea_t ida_bin_search2(ea_t start_ea, ea_t end_ea, IntPtr image, IntPtr mask, size_t len, int flags)
{
	compiled_binpat_vec_t bbv;
	compiled_binpat_t& bv = bbv.push_back();
	bv.bytes.append((const uchar*)(image.ToPointer()), len);
	if (mask != nullptr)
		bv.mask.append((const uchar*)(mask.ToPointer()), len);
	return bin_search2(start_ea, end_ea, bbv, flags);
}

// bin_search3
static ea_t ida_bin_search3(IntPtr out_matched_idx, ea_t start_ea, ea_t end_ea, IntPtr data, int flags)
{
	return bin_search3((size_t*)(out_matched_idx.ToPointer()), start_ea, end_ea, *(const compiled_binpat_vec_t*)(data.ToPointer()), flags);
}

static ea_t ida_next_inited(ea_t ea, ea_t maxea) 
{
	if (ea >= maxea)
		return ea_t(-1);
	++ea;
	return find_byte(ea, maxea - ea, 0, 4);
}

static ea_t ida_prev_inited(ea_t ea, ea_t minea) 
{
	if (ea <= minea)
		return ea_t(-1);
	--ea;
	return find_byter(minea, ea - minea, 0, 4);
}

static bool ida_equal_bytes(ea_t ea, IntPtr image, IntPtr mask, size_t len, int bin_search_flags)
{
	return equal_bytes(ea, (const uchar*)(image.ToPointer()), (const uchar*)(mask.ToPointer()), len, bin_search_flags);
}

static bool ida_bytes_match_for_bin_search(uchar c1, uchar c2, IntPtr maskPtr, int i, int bin_search_flags)
{
	auto mask = (const uchar*)(maskPtr.ToPointer());

	if ((bin_search_flags & BIN_SEARCH_CASE) == 0) {
		c1 = qtoupper(c1);
		c2 = qtoupper(c2);
	}
	if (mask != nullptr) {
		if ((bin_search_flags & BIN_SEARCH_BITMASK) != 0)
			return ((c1 ^ c2) & mask[i]) == 0;
		if (mask == ((const uchar*)SKIP_FF_MASK)) 
		{
			if (c2 == 0xff)
				return true;
		}
		else if (mask[i] == 0) {
			return true;
		}
	}
	return c1 == c2;
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
static ea_t ida_bin_search(ea_t _0, ea_t _1, IntPtr _2, IntPtr _3, size_t _4, int _5, int _6)
{
	return bin_search(_0, _1, (const char*)(_2.ToPointer()), (const char*)(_3.ToPointer()), _4, _5, _6);
}

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


