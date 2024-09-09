#pragma once

static bool ida_reg_bin_op(IntPtr name, bool save, IntPtr data, size_t datalen, IntPtr subkey, int mode)
{
	return reg_bin_op((const char*)(name.ToPointer()), save, (void*)(data.ToPointer()), datalen, (const char*)(subkey.ToPointer()), mode);
}

static bool ida_reg_str_get(IntPtr buf, IntPtr name, IntPtr subkey) // ???
{
	return reg_str_get((::qstring*)(buf.ToPointer()), (const char*)(name.ToPointer()), (const char*)(subkey.ToPointer()));
}

static void ida_reg_str_set(IntPtr name, IntPtr subkey, IntPtr buf)
{
	return reg_str_set((const char*)(name.ToPointer()), (const char*)(subkey.ToPointer()), (const char*)(buf.ToPointer()));
}

static int ida_reg_int_op(IntPtr name, bool save, int value, IntPtr subkey)
{
	return reg_int_op((const char*)(name.ToPointer()), save, value, (const char*)(subkey.ToPointer()));
}

static bool ida_reg_delete_subkey(IntPtr name)
{
	return reg_delete_subkey((const char*)(name.ToPointer()));
}

static bool ida_reg_delete_tree(IntPtr name)
{
	return reg_delete_tree((const char*)(name.ToPointer()));
}

static bool ida_reg_delete(IntPtr name, IntPtr subkey)
{
	return reg_delete((const char*)(name.ToPointer()), (const char*)(subkey.ToPointer()));
}

static bool ida_reg_subkey_exists(IntPtr name)
{
	return reg_subkey_exists((const char*)(name.ToPointer()));
}

static bool ida_reg_exists(IntPtr name, IntPtr subkey)
{
	return reg_exists((const char*)(name.ToPointer()), (const char*)(subkey.ToPointer()));
}

static bool ida_reg_subkey_children(IntPtr out, IntPtr name, bool subkeys) // ???
{
	return reg_subkey_children((::qstrvec_t*)(out.ToPointer()), (const char*)(name.ToPointer()), subkeys);
}

static bool ida_reg_data_type(IntPtr out, IntPtr name, IntPtr subkey)
{
	return reg_data_type((::regval_type_t*)(out.ToPointer()), (const char*)(name.ToPointer()), (const char*)(subkey.ToPointer()));
}

static void ida_reg_read_strlist(IntPtr list, IntPtr subkey) // ???
{
	return reg_read_strlist((::qstrvec_t*)(list.ToPointer()), (const char*)(subkey.ToPointer()));
}

static void ida_reg_update_strlist(IntPtr subkey, IntPtr add, size_t maxrecs, IntPtr rem, bool ignorecase)
{
	return reg_update_strlist((const char*)(subkey.ToPointer()), (const char*)(add.ToPointer()), maxrecs, (const char*)(rem.ToPointer()), ignorecase);
}

static void ida_reg_write_binary(IntPtr name, IntPtr data, size_t datalen, IntPtr subkey)
{
	reg_bin_op((const char*)(name.ToPointer()), true, (void*)(data.ToPointer()), datalen, (const char*)(subkey.ToPointer()));
}

static bool ida_reg_read_binary(IntPtr name, IntPtr data, size_t datalen, IntPtr subkey)
{
	return reg_bin_op((const char*)(name.ToPointer()), false, (void*)(data.ToPointer()), datalen, (const char*)(subkey.ToPointer()));
}

static bool ida_reg_read_binary_part(IntPtr name, IntPtr data, size_t datalen, IntPtr subkey)
{
	return reg_bin_op((const char*)(name.ToPointer()), false, (void*)(data.ToPointer()), datalen, (const char*)(subkey.ToPointer()), 1);
}

static bool ida_reg_read_binary(IntPtr name, IntPtr data, IntPtr subkey)
{
	return reg_bin_op((const char*)(name.ToPointer()), false, (void*)(data.ToPointer()), 0, (const char*)(subkey.ToPointer()), 2);
}

static void ida_reg_write_string(IntPtr name, IntPtr utf8, IntPtr subkey)
{
	reg_str_set((const char*)(name.ToPointer()), (const char*)(subkey.ToPointer()), (const char*)(utf8.ToPointer()));
}

static bool ida_reg_read_string(IntPtr utf8, IntPtr name, IntPtr subkey) // ???
{
	return reg_str_get((qstring*)(utf8.ToPointer()), (const char*)(name.ToPointer()), (const char*)(subkey.ToPointer()));
}

static int ida_reg_read_int(IntPtr name, int defval, IntPtr subkey)
{
	return reg_int_op((const char*)(name.ToPointer()), false, defval, (const char*)(subkey.ToPointer()));
}

static void ida_reg_write_int(IntPtr name, int value, IntPtr subkey)
{
	reg_int_op((const char*)(name.ToPointer()), true, value, (const char*)(subkey.ToPointer()));
}

static bool ida_reg_read_bool(IntPtr name, bool defval, IntPtr subkey)
{
	return reg_int_op((const char*)(name.ToPointer()), false, int(defval), (const char*)(subkey.ToPointer())) != 0;
}

static void ida_reg_write_bool(IntPtr name, int value, IntPtr subkey)
{
	reg_int_op((const char*)(name.ToPointer()), true, value != 0, (const char*)(subkey.ToPointer()));
}

static bool ida_reg_subkey_subkeys(IntPtr out, IntPtr name) // ???
{
	return reg_subkey_children((::qstrvec_t*)(out.ToPointer()), (const char*)(name.ToPointer()), true);

}

static bool ida_reg_subkey_values(IntPtr out, IntPtr name) // ???
{
	return reg_subkey_children((::qstrvec_t*)(out.ToPointer()), (const char*)(name.ToPointer()), false);
}

static void ida_reg_update_filestrlist(IntPtr subkey, IntPtr add, size_t maxrecs, IntPtr rem)
{
	reg_update_strlist((const char*)(subkey.ToPointer()), (const char*)(add.ToPointer()), maxrecs, (const char*)(rem.ToPointer()), true);
}

#ifdef OBSOLETE_FUNCS
static void ida_reg_load()
{
	return reg_load();
}

static void ida_reg_flush()
{
	return reg_flush();
}
#endif

static void ida_regget_history(IntPtr list) // ???
{
#ifdef DEMO
	qnotused(list);
#else
	//reg_read_strlist((::qstrvec_t*)(list.ToPointer()), regkey_history);
#endif
}

static void ida_reg_update_history(IntPtr addfile, IntPtr removefile)
{
#ifdef DEMO
	qnotused(addfile);
	qnotused(removefile);
#else
	//reg_update_filestrlist(regkey_history, (const char*)(addfile.ToPointer()), max_history_files, (const char*)(removefile.ToPointer()));
#endif
}

static void ida_reg_history_size_truncate()
{
#ifndef DEMO
	//reg_update_strlist(regkey_history, nullptr, max_history_files, nullptr);
#endif
}
