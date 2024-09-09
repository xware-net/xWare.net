#pragma once

// complete

static sel_t ida_get_sreg(ea_t ea, int rg)
{
	return get_sreg(ea, rg);
}

static bool ida_split_sreg_range(ea_t ea, int rg, sel_t v, uchar tag, bool silent)
{
	return split_sreg_range(ea, rg, v, tag, silent);
}

static bool ida_set_default_sreg_value(IntPtr sg, int rg, sel_t value)
{
	return set_default_sreg_value((::segment_t*)(sg.ToPointer()), rg, value);
}

static void ida_set_sreg_at_next_code(ea_t ea1, ea_t ea2, int rg, sel_t value)
{
	return set_sreg_at_next_code(ea1, ea2, rg, value);
}

static bool ida_get_sreg_range(IntPtr out, ea_t ea, int rg)
{
	return get_sreg_range((::sreg_range_t*)(out.ToPointer()), ea, rg);
}

static bool ida_get_prev_sreg_range(IntPtr out, ea_t ea, int rg)
{
	return get_prev_sreg_range((::sreg_range_t*)(out.ToPointer()), ea, rg);
}

static void ida_set_default_dataseg(sel_t ds_sel)
{
	return set_default_dataseg(ds_sel);
}

static size_t ida_get_sreg_ranges_qty(int rg)
{
	return get_sreg_ranges_qty(rg);
}

static bool ida_getn_sreg_range(IntPtr out, int rg, int n)
{
	return getn_sreg_range((::sreg_range_t*)(out.ToPointer()), rg, n);
}

static int ida_get_sreg_range_num(ea_t ea, int rg)
{
	return get_sreg_range_num(ea, rg);
}

static bool ida_del_sreg_range(ea_t ea, int rg)
{
	return del_sreg_range(ea, rg);
}

static void ida_copy_sreg_ranges(int dst_rg, int src_rg, bool map_selector)
{
	return copy_sreg_ranges(dst_rg, src_rg, map_selector);
}

