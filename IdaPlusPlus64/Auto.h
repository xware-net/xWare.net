#pragma once

// complete

static atype_t ida_get_auto_state()
{
	return get_auto_state();
}

static atype_t ida_set_auto_state(atype_t new_state)
{
	return set_auto_state(new_state);
}

static bool ida_get_auto_display(IntPtr auto_display)
{
	return get_auto_display((auto_display_t*)(auto_display.ToPointer()));
}

static void ida_show_auto(ea_t ea, atype_t type)
{
	show_auto(ea, type);
}

static void ida_show_addr(ea_t ea)
{
	show_auto(ea);
}

static idastate_t ida_set_ida_state(idastate_t st)
{
	return set_ida_state(st);
}

static bool ida_may_create_stkvars()
{
	return inf_should_create_stkvars() && get_auto_state() == AU_USED;
}

static bool ida_may_trace_sp()
{
	if (inf_should_trace_sp()) 
	{
		atype_t auto_state = get_auto_state();
		return auto_state == AU_USED;
	}

	return false;
}

static void ida_auto_mark_range(ea_t start, ea_t end, atype_t type)
{
	auto_mark_range(start, end, type);
}

static void ida_auto_mark(ea_t ea, atype_t type)
{
	auto_mark_range(ea, ea + 1, type);
}

static void ida_auto_unmark(ea_t start, ea_t end, atype_t type)
{
	auto_unmark(start, end, type);
}

static void ida_plan_ea(ea_t ea)
{
	auto_mark(ea, AU_USED);
}

static void ida_plan_range(ea_t sEA, ea_t eEA)
{
	auto_mark_range(sEA, eEA, AU_USED);
}

static void ida_auto_make_code(ea_t ea)
{
	auto_mark(ea, AU_CODE);
}

static void ida_auto_make_proc(ea_t ea)
{
	auto_make_code(ea);
	auto_mark(ea, AU_PROC);
}

static void ida_reanalyze_callers(ea_t ea, bool noret)
{
	reanalyze_callers(ea, noret);
}

static void ida_revert_ida_decisions(ea_t ea1, ea_t ea2)
{
	revert_ida_decisions(ea1, ea2);
}

static void ida_auto_apply_type(ea_t caller, ea_t callee)
{
	auto_apply_type(caller, callee);
}

static void ida_auto_apply_tail(ea_t tail_ea, ea_t parent_ea)
{
	auto_apply_tail(tail_ea, parent_ea);
}

static int ida_plan_and_wait(ea_t ea1, ea_t ea2, bool final_pass)
{
	return plan_and_wait(ea1, ea2, final_pass);
}

static bool ida_auto_wait()
{
	return auto_wait();
}

static ssize_t ida_auto_wait_range(ea_t ea1, ea_t ea2)
{
	return auto_wait_range(ea1, ea2);
}

static bool ida_auto_make_step(ea_t ea1, ea_t ea2)
{
	return auto_make_step(ea1, ea2);
}

static void ida_auto_cancel(ea_t ea1, ea_t ea2)
{
	auto_cancel(ea1, ea2);
}

static bool ida_auto_is_ok()
{
	return auto_is_ok();
}

static ea_t ida_peek_auto_queue(ea_t low_ea, atype_t type)
{
	return peek_auto_queue(low_ea, type);
}

static ea_t ida_auto_get(IntPtr type, ea_t lowEA, ea_t highEA)
{
	return auto_get((atype_t*)(type.ToPointer()), lowEA, highEA);
}

static int ida_auto_recreate_insn(ea_t ea)
{
	return auto_recreate_insn(ea);
}

static bool ida_is_auto_enabled()
{
	return is_auto_enabled();
}

static bool ida_enable_auto(bool enable)
{
	return enable_auto(enable);
}

