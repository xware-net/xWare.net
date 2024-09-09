#pragma once

// complete

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate unsigned int Func_uint_int(int color);

static IntPtr ida_node_iterator_goup(IntPtr p_0)
{
	return IntPtr((void *)node_iterator_goup((::node_iterator*)(p_0.ToPointer())));
}

static void ida_create_qflow_chart(IntPtr p_0)
{
	return create_qflow_chart(*(::qflow_chart_t*)(p_0.ToPointer()));
}

static bool ida_append_to_flowchart(IntPtr p_0, ea_t p_1, ea_t p_2)
{
	return append_to_flowchart(*(::qflow_chart_t*)(p_0.ToPointer()), p_1, p_2);
}

static fc_block_type_t ida_fc_calc_block_type(IntPtr p_0, size_t p_1)
{
	return fc_calc_block_type(*(const ::qflow_chart_t*)(p_0.ToPointer()), p_1);
}

static bool ida_create_multirange_qflow_chart(IntPtr p_0, IntPtr p_1)
{
	return create_multirange_qflow_chart(*(::qflow_chart_t*)(p_0.ToPointer()), *(const ::rangevec_t*)(p_1.ToPointer()));
}

static void ida_gen_gdl(IntPtr g, IntPtr fname)
{
	return gen_gdl((const ::gdl_graph_t*)(g.ToPointer()), (const char*)(fname.ToPointer()));
}

static int ida_display_gdl(IntPtr fname)
{
	return display_gdl((const char*)(fname.ToPointer()));
}

static bool ida_gen_flow_graph(IntPtr filename, IntPtr title, IntPtr pfn, ea_t ea1, ea_t ea2, int gflags)
{
	return gen_flow_graph((const char*)(filename.ToPointer()), (const char*)(title.ToPointer()), (::func_t*)(pfn.ToPointer()), ea1, ea2, gflags);
}

static bool ida_gen_simple_call_chart(IntPtr filename, IntPtr wait, IntPtr title, int gflags)
{
	return gen_simple_call_chart((const char*)(filename.ToPointer()), (const char*)(wait.ToPointer()), (const char*)(title.ToPointer()), gflags);
}

static bool ida_gen_complex_call_chart(IntPtr filename, IntPtr wait, IntPtr title, ea_t ea1, ea_t ea2, int flags, int recursion_depth)
{
	return gen_complex_call_chart((const char*)(filename.ToPointer()), (const char*)(wait.ToPointer()), (const char*)(title.ToPointer()), ea1, ea2, flags, recursion_depth);
}

static void ida_setup_graph_subsystem(IntPtr _grapher, Func_uint_int^ get_graph_color)
{
	return setup_graph_subsystem((const char*)(_grapher.ToPointer()), static_cast<unsigned int (__stdcall*)(int)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(get_graph_color).ToPointer()));
}

static bool ida_is_noret_block(fc_block_type_t btype)
{
	return btype == fcb_noret || btype == fcb_enoret;
}

static bool ida_is_ret_block(fc_block_type_t btype)
{
	return btype == fcb_ret || btype == fcb_cndret;
}

