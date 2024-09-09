#pragma once

// complete

static IntPtr ida_cfg_get_cc_parm(comp_t compid, IntPtr name)
{
	return IntPtr((void*)cfg_get_cc_parm(compid, (const char*)(name.ToPointer())));
}

static IntPtr ida_cfg_get_cc_header_path(comp_t compid)
{
	return IntPtr((void*)(cfg_get_cc_parm(compid, "HEADER_PATH")));
}

static IntPtr ida_cfg_get_cc_predefined_macros(comp_t compid)
{
	return IntPtr((void*)(cfg_get_cc_parm(compid, "PREDEFINED_MACROS")));
}

static void ida_process_config_directive(IntPtr directive, int priority)
{
	process_config_directive((const char*)(directive.ToPointer()), priority);
}

