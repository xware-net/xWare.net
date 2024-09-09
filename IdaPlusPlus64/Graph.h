#pragma once

static bool ida_get_node_info(IntPtr out, graph_id_t gid, int node)
{
	return get_node_info((::node_info_t*)(out.ToPointer()), gid, node);
}

static void ida_set_node_info(graph_id_t gid, int node, IntPtr ni, unsigned int flags)
{
	return set_node_info(gid, node, *(const ::node_info_t*)(ni.ToPointer()), flags);
}

static void ida_del_node_info(graph_id_t gid, int node)
{
	return del_node_info(gid, node);
}

static void ida_clr_node_info(graph_id_t gid, int node, uint32 flags)
{
	return clr_node_info(gid, node, flags);
}

static double ida_calc_dist(point_t p, point_t q)
{
	double dx = q.x - p.x;
	double dy = q.y - p.y;
	return sqrt(dx * dx + dy * dy);
}

//static long long ida_graph_dispatcher(IntPtr p_0, int code, char* va)
//{
//	return graph_dispatcher((void*)(p_0.ToPointer()), code, va);
//}

static ssize_t ida_grentry(graph_notification_t event_code)
{
	ssize_t code = invoke_callbacks(HT_GRAPH, event_code, nullptr);
	return code;
}

/*
static IntPtr ida_create_graph_viewer(IntPtr title, uval_t id, IntPtr callback, IntPtr ud, int title_height, IntPtr parent)
{
	graph_viewer_t* gv = nullptr;
	grentry(grcode_create_graph_viewer, title, &gv, id, callback, ud, title_height, parent);
	return IntPtr((void*)gv);
}

static IntPtr ida_get_graph_viewer(IntPtr parent)
{
	graph_viewer_t* gv = nullptr; 
	grentry(grcode_get_graph_viewer, parent, &gv); 
	return IntPtr((void*)gv);
}

static IntPtr ida_create_mutable_graph(uval_t id)
{
	mutable_graph_t* g = nullptr; 
	grentry(grcode_create_mutable_graph, id, &g); 
	return IntPtr((void*)g);
}

static IntPtr ida_create_disasm_graph(ea_t ea)
{
	mutable_graph_t* g = nullptr; 
	grentry(grcode_create_disasm_graph1, ea, &g); 
	return IntPtr((void*)g);
}

static IntPtr ida_create_disasm_graph(IntPtr ranges)
{
	mutable_graph_t* g = nullptr; 
	grentry(grcode_create_disasm_graph2, &ranges, &g); 
	return IntPtr((void*)g);
}

static IntPtr ida_get_viewer_graph(IntPtr gv)
{
	mutable_graph_t* g = nullptr; 
	grentry(grcode_get_viewer_graph, gv, &g); 
	return IntPtr((void*)g);
}

static void ida_set_viewer_graph(IntPtr gv, IntPtr g) 
{
	grentry(grcode_set_viewer_graph, gv, g);
}

static void ida_refresh_viewer(IntPtr gv) // inline
{
	...
}

static void ida_viewer_fit_window(IntPtr gv) // inline
{
	...
}

static int ida_viewer_get_curnode(IntPtr gv) // inline
{
	...
}

static void ida_viewer_center_on(IntPtr gv, int node) // inline
{
	...
}

static void ida_viewer_set_gli(IntPtr gv, IntPtr gli, unsigned int flags) // inline
{
	...
}

static bool ida_viewer_get_gli(IntPtr out, IntPtr gv, unsigned int flags) // inline
{
	...
}

static void ida_viewer_set_node_info(IntPtr gv, int n, IntPtr ni, unsigned int flags) // inline
{
	...
}

static bool ida_viewer_get_node_info(IntPtr gv, IntPtr out, int n) // inline
{
	...
}

static void ida_viewer_del_node_info(IntPtr gv, int n) // inline
{
	...
}

static bool ida_viewer_create_groups(IntPtr gv, IntPtr out_group_nodes, IntPtr gi) // inline
{
	...
}

static bool ida_viewer_delete_groups(IntPtr gv, IntPtr groups, int new_current) // inline
{
	...
}

static bool ida_viewer_set_groups_visibility(IntPtr gv, IntPtr groups, bool expand, int new_current) // inline
{
	...
}

static bool ida_viewer_attach_menu_item(IntPtr g, IntPtr name) // inline
{
	...
}

static bool ida_viewer_get_selection(IntPtr gv, IntPtr sgs) // inline
{
	...
}

static int ida_viewer_set_titlebar_height(IntPtr gv, int height) // inline
{
	...
}

static void ida_delete_mutable_graph(IntPtr g) // inline
{
	...
}

static IntPtr ida_create_user_graph_place(int node, int lnnum) // inline
{
	...
}

*/