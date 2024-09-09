#pragma once

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate int Func_int___IntPtr___IntPtr(snapshot_t* ss, System::IntPtr ud);

static void ida_vloader_failure(IntPtr format)
{
	vloader_failure((const char*)(format.ToPointer()), nullptr);
}

static void ida_loader_failure(IntPtr format)
{
	ida_vloader_failure(format);
}

static IntPtr ida_build_loaders_list(IntPtr li, IntPtr filename)
{
	return IntPtr((void*)build_loaders_list((linput_t*)(li.ToPointer()), (const char*)(filename.ToPointer())));
}

static void ida_free_loaders_list(IntPtr list)
{
	free_loaders_list((load_info_t*)(list.ToPointer()));
}

static IntPtr ida_get_loader_name_from_dll(IntPtr dllname)
{
	return IntPtr((void*)get_loader_name_from_dll((char*)(dllname.ToPointer())));
}

static long long ida_get_loader_name(IntPtr buf, size_t bufsize)
{
	return get_loader_name((char*)(buf.ToPointer()), bufsize);
}

static bool ida_load_binary_file(IntPtr filename, IntPtr li, unsigned short _neflags, qoff64_t fileoff, ea_t basepara, ea_t binoff, unsigned long long nbytes)
{
	return load_binary_file((const char*)(filename.ToPointer()), (linput_t*)(li.ToPointer()), _neflags, fileoff, basepara, binoff, nbytes);
}

static bool ida_load_nonbinary_file(IntPtr filename, IntPtr li, IntPtr sysdlldir, unsigned short _neflags, IntPtr loader)
{
	return load_nonbinary_file((const char*)(filename.ToPointer()), (linput_t*)(li.ToPointer()), (const char*)(sysdlldir.ToPointer()), _neflags, (load_info_t*)(loader.ToPointer()));
}

//static int ida_process_archive(IntPtr temp_file, IntPtr li, IntPtr module_name, IntPtr neflags, IntPtr defmember, IntPtr loader, IntPtr errbuf)
//{
//	return process_archive((_qstring<char>*)(temp_file.ToPointer()), (linput_t*)(li.ToPointer()), (qstring*)(module_name.ToPointer()), (unsigned short*)(neflags.ToPointer()), (const char*)(defmember.ToPointer()), (const load_info_t*)(loader.ToPointer()), (_qstring<char>*)(errbuf.ToPointer()));
//}

static int ida_gen_file(ofile_type_t otype, IntPtr fp, ea_t ea1, ea_t ea2, int flags)
{
	return gen_file(otype, (FILE*)(fp.ToPointer()), ea1, ea2, flags);
}

static int ida_file2base(IntPtr li, qoff64_t pos, ea_t ea1, ea_t ea2, int patchable)
{
	return file2base((linput_t*)(li.ToPointer()), pos, ea1, ea2, patchable);
}

static int ida_mem2base(IntPtr memptr, ea_t ea1, ea_t ea2, qoff64_t fpos)
{
	return mem2base((const void*)(memptr.ToPointer()), ea1, ea2, fpos);
}

static int ida_base2file(IntPtr fp, qoff64_t pos, ea_t ea1, ea_t ea2)
{
	return base2file((FILE*)(fp.ToPointer()), pos, ea1, ea2);
}

static bool ida_extract_module_from_archive(IntPtr filename, size_t bufsize, IntPtr temp_file_ptr, bool is_remote)
{
	return extract_module_from_archive((char*)(filename.ToPointer()), bufsize, (char**)(temp_file_ptr.ToPointer()), is_remote);
}

static void ida_create_filename_cmt()
{
	create_filename_cmt();
}

static filetype_t ida_get_basic_file_type(IntPtr li)
{
	return get_basic_file_type((linput_t*)(li.ToPointer()));
}

static size_t ida_get_file_type_name(IntPtr buf, size_t bufsize)
{
	return get_file_type_name((char*)(buf.ToPointer()), bufsize);
}

static void ida_import_module(IntPtr module, IntPtr windir, uval_t modnode, IntPtr importer, IntPtr ostype)
{
	import_module((const char*)(module.ToPointer()), (const char*)(windir.ToPointer()), modnode, (int (*)(linput_t*, impinfo_t*))(importer.ToPointer()), (const char*)(ostype.ToPointer()));
}

static void ida_set_import_ordinal(uval_t modnode, ea_t ea, uval_t ord)
{
	set_import_ordinal(modnode, ea, ord);
}

static void ida_set_import_name(uval_t modnode, ea_t ea, IntPtr name)
{
	set_import_name(modnode, ea, (const char*)(name.ToPointer()));
}

static int ida_load_ids_module(IntPtr fname)
{
	return load_ids_module((char*)(fname.ToPointer()));
}

static IntPtr ida_get_plugin_options(IntPtr plugin)
{
	return IntPtr((void*)get_plugin_options((const char*)(plugin.ToPointer())));
}

static bool ida_load_core_module(IntPtr dllmem, IntPtr file, IntPtr entry)
{
	return load_core_module((idadll_t*)(dllmem.ToPointer()), (const char*)(file.ToPointer()), (const char*)(entry.ToPointer()));
}

static void ida_free_dll(IntPtr dllmem)
{
	free_dll((idadll_t*)(dllmem.ToPointer()));
}

static IntPtr ida_get_idp_descs()
{
	return IntPtr((void*)get_idp_descs());
}

static IntPtr ida_get_plugins()
{
	return IntPtr((void*)get_plugins());
}

static IntPtr ida_find_plugin(IntPtr name, bool load_if_needed)
{
	return IntPtr((void*)find_plugin((const char*)(name.ToPointer()), load_if_needed));
}

static IntPtr ida_load_plugin(IntPtr name)
{
	return ida_find_plugin(name, true);
}

static bool ida_run_plugin(IntPtr ptr, size_t arg)
{
	return run_plugin((const plugin_t*)(ptr.ToPointer()), arg);
}

static bool ida_load_and_run_plugin(IntPtr name, size_t arg)
{
	return ida_run_plugin(ida_load_plugin(name), arg);
}

static bool ida_invoke_plugin(IntPtr ptr)
{
	return invoke_plugin((plugin_info_t*)(ptr.ToPointer()));
}

static unsigned long long ida_get_debugger_plugins(IntPtr array)
{
	return get_debugger_plugins((const dbg_info_t**)(array.ToPointer()));
}

static void ida_init_plugins(int flag)
{
	init_plugins(flag);
}

static void ida_term_plugins(int flag)
{
	return term_plugins(flag);
}

static int64 ida_get_fileregion_offset(ea_t ea)
{
	return get_fileregion_offset(ea);
}

static ea_t ida_get_fileregion_ea(int64 offset)
{
	return get_fileregion_ea(offset);
}

static int ida_gen_exe_file(IntPtr fp)
{
	return gen_exe_file((_iobuf*)(fp.ToPointer()));
}

static bool ida_reload_file(IntPtr file, bool is_remote)
{
	return reload_file((const char*)(file.ToPointer()), is_remote);
}

static bool ida_build_snapshot_tree(IntPtr root)
{
	return build_snapshot_tree((snapshot_t*)(root.ToPointer()));
}

static bool ida_update_snapshot_attributes(IntPtr filename, IntPtr root, IntPtr attr, int uf)
{
	return update_snapshot_attributes((const char*)(filename.ToPointer()), (const snapshot_t*)(root.ToPointer()), (const snapshot_t*)(attr.ToPointer()), uf);
}

static int ida_visit_snapshot_tree(IntPtr root, Func_int___IntPtr___IntPtr^ callback, IntPtr ud)
{
	return visit_snapshot_tree((snapshot_t*)(root.ToPointer()), static_cast<int (__stdcall*)(snapshot_t*, void*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(callback).ToPointer()), (void*)(ud.ToPointer()));
}

static int ida_flush_buffers()
{
	return flush_buffers();
}

static bool ida_is_trusted_idb()
{
	return is_trusted_idb();
}

static bool ida_save_database(IntPtr outfile, unsigned int flags, IntPtr root, IntPtr attr)
{
	return save_database((const char*)(outfile.ToPointer()), flags, (const snapshot_t*)(root.ToPointer()), (const snapshot_t*)(attr.ToPointer()));
}

static bool ida_is_database_flag(uint32 dbfl)
{
	return is_database_flag(dbfl);
}

static void ida_set_database_flag(uint32 dbfl, bool cnd)
{
	set_database_flag(dbfl, cnd);
}

static void ida_clr_database_flag(unsigned int dbfl)
{
	set_database_flag(dbfl, false);
}

static bool ida_is_temp_database()
{
	return is_database_flag(DBFL_TEMP);
}

static IntPtr ida_get_path(path_type_t pt)
{
	return IntPtr((void*)get_path(pt));
}

static void ida_set_path(path_type_t pt, IntPtr path)
{
	set_path(pt, (const char*)(path.ToPointer()));
}

static bool ida_is_database_ext(IntPtr ext)
{
	return is_database_ext((const char*)(ext.ToPointer()));
}

static IntPtr ida_get_elf_debug_file_directory()
{
	return IntPtr((void*)get_elf_debug_file_directory());
}
