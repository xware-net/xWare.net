#pragma once

static void ida_check_spoiled_jpt(IntPtr _this, IntPtr _regs)
{
	return check_spoiled_jpt((const jump_pattern_t*)(_this.ToPointer()), (qvector<op_t>*)(_regs.ToPointer()));
}

static bool ida_match_jpt(IntPtr _this)
{
	return match_jpt((jump_pattern_t*)(_this.ToPointer()));
}

static bool ida_same_value_jpt(IntPtr _this, IntPtr op, int r_i)
{
	return same_value_jpt((jump_pattern_t*)(_this.ToPointer()), *(const op_t*)(op.ToPointer()), r_i);
}

static bool ida_track_value_until_address_jpt(IntPtr _this, IntPtr op, ea_t ea)
{
	return track_value_until_address_jpt((jump_pattern_t*)(_this.ToPointer()), (op_t*)(op.ToPointer()), ea);
}

static void ida_combine_regs_jpt(IntPtr _this, IntPtr dst, IntPtr src, ea_t ea)
{
	return combine_regs_jpt((jump_pattern_t*)(_this.ToPointer()), (tracked_regs_t*)(dst.ToPointer()), *(const tracked_regs_t*)(src.ToPointer()), ea);
}

static void ida_mark_switch_insns_jpt(IntPtr _this, int last, int p_2)
{
	return mark_switch_insns_jpt((const jump_pattern_t*)(_this.ToPointer()), last, p_2);
}

static bool ida_set_moved_jpt(IntPtr _this, IntPtr dst, IntPtr src, IntPtr _regs, op_dtype_t real_dst_dtype, op_dtype_t real_src_dtype)
{
	return set_moved_jpt((const jump_pattern_t*)(_this.ToPointer()), *(const op_t*)(dst.ToPointer()), *(const op_t*)(src.ToPointer()), *(tracked_regs_t*)(_regs.ToPointer()), real_dst_dtype, real_src_dtype);
}

static int ida_check_flat_jump_table(IntPtr si, ea_t jump_ea, int is_pattern_res)
{
	return check_flat_jump_table((switch_info_t*)(si.ToPointer()), jump_ea, is_pattern_res);
}

//static bool ida_check_for_table_jump(IntPtr si, IntPtr insn, cli::array<System::Func<int, switch_info_t^, insn_t^, procmod_t^>^>^ patterns, unsigned long long qty, IntPtr check_table, IntPtr name)
//{
//	return check_for_table_jump((switch_info_t*)(si.ToPointer()), (const insn_t&)(insn.ToPointer()), patterns, qty, (int (*)(switch_info_t*, unsigned long long, int, procmod_t*))(check_table.ToPointer()), (const char*)(name.ToPointer()));
//}
//
static void ida_trim_jtable(IntPtr si, ea_t jump_ea, bool ignore_refs)
{
	return trim_jtable((switch_info_t*)(si.ToPointer()), jump_ea, ignore_refs);
}

static bool ida_find_jtable_size(IntPtr si)
{
	return find_jtable_size((switch_info_t*)(si.ToPointer()));
}

static ea_t ida_find_defjump_from_table(ea_t jump_ea, IntPtr si)
{
	return find_defjump_from_table(jump_ea, *(const switch_info_t*)(si.ToPointer()));
}

static ea_t ida_get_jtable_target(ea_t jump_ea, IntPtr si, int i)
{
	return get_jtable_target(jump_ea, *(const switch_info_t*)(si.ToPointer()), i);
}

