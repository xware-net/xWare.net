#pragma once

// complete

static bool ida_select_parser_by_name(IntPtr name)
{
	return select_parser_by_name((const char*)(name.ToPointer()));
}

static bool ida_select_parser_by_srclang(srclang_t lang)
{
	return select_parser_by_srclang(lang);
}

static int ida_set_parser_argv(IntPtr parser_name, IntPtr argv)
{
	return set_parser_argv((const char*)(parser_name.ToPointer()), (const char*)(argv.ToPointer()));
}

static int ida_parse_decls_for_srclang(srclang_t lang, IntPtr til, IntPtr input, bool is_path)
{
	return parse_decls_for_srclang(lang, (til_t*)(til.ToPointer()), (const char*)(input.ToPointer()), is_path);
}

static int ida_parse_decls_with_parser(IntPtr parser_name, IntPtr til, IntPtr input, bool is_path)
{
	return parse_decls_with_parser((const char*)(parser_name.ToPointer()), (til_t*)(til.ToPointer()), (const char*)(input.ToPointer()), is_path);
}

