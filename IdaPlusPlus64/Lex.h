#pragma once

// complete

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate int lx_resolver_t(lexer_t* lx, ::System::IntPtr ud, token_t* curtok, long long* res);

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate int lx_parse_cast_t(lexer_t* lx, cast_t* cast, token_t* ct);

[::System::Runtime::InteropServices::UnmanagedFunctionPointer(::System::Runtime::InteropServices::CallingConvention::Cdecl)]
delegate int Func_int_string8_string8_int_bool___IntPtr(::System::String^ name, ::System::String^ body, int nargs, bool isfunc, ::System::IntPtr ud);


static IntPtr ida_create_lexer(IntPtr keys, unsigned long long size, IntPtr ud)
{
	return IntPtr((void *)create_lexer((const char* const*)(keys.ToPointer()), size, (void*)(ud.ToPointer())));
}

static void ida_destroy_lexer(IntPtr lx)
{
	destroy_lexer((lexer_t*)(lx.ToPointer()));
}

static error_t ida_lex_define_macro(IntPtr lx, IntPtr macro, IntPtr body, int nargs, bool isfunc)
{
	return lex_define_macro((lexer_t*)(lx.ToPointer()), (const char*)(macro.ToPointer()), (const char*)(body.ToPointer()), nargs, isfunc);
}

static void ida_lex_undefine_macro(IntPtr lx, IntPtr macro)
{
	lex_undefine_macro((lexer_t*)(lx.ToPointer()), (const char*)(macro.ToPointer()));
}

static int ida_lex_set_options(IntPtr lx, int options)
{
	return lex_set_options((lexer_t*)(lx.ToPointer()), options);
}

static error_t ida_lex_get_token(IntPtr lx, IntPtr t)
{
	return lex_get_token((lexer_t*)(lx.ToPointer()), (token_t*)(t.ToPointer()));
}

static error_t ida_lex_get_token2(IntPtr lx, IntPtr t, IntPtr p_lnnum)
{
	return lex_get_token2((lexer_t*)(lx.ToPointer()), (token_t*)(t.ToPointer()), (int32*)(p_lnnum.ToPointer()));
}

static int ida_lex_enum_macros(IntPtr lx, Func_int_string8_string8_int_bool___IntPtr^ cb, IntPtr ud)
{
	return lex_enum_macros((const ::lexer_t*)(lx.ToPointer()), static_cast<int (*)(const char*, const char*, int, bool, void*)>(::System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(cb).ToPointer()), (void*)(ud.ToPointer()));
}

static IntPtr ida_lex_print_token(IntPtr buf, IntPtr t)
{
	return IntPtr((void*)lex_print_token((qstring*)(buf.ToPointer()), (const token_t*)(t.ToPointer())));
}

static error_t ida_lex_init_string(IntPtr lx, IntPtr line, IntPtr macros)
{
	return lex_init_string((lexer_t*)(lx.ToPointer()), (const char*)(line.ToPointer()), (void*)(macros.ToPointer()));
}

static error_t ida_lex_init_file(IntPtr lx, IntPtr file)
{
	return lex_init_file((lexer_t*)(lx.ToPointer()), (const char*)(file.ToPointer()));
}

static IntPtr ida_lex_get_file_line(IntPtr lx, IntPtr linenum, IntPtr lineptr, int level)
{
	return IntPtr((void*)lex_get_file_line((lexer_t*)(lx.ToPointer()), (int32*)(linenum.ToPointer()), (const char**)(lineptr.ToPointer()), level));
}

static void ida_lex_term_file(IntPtr lx, bool del_macros)
{
	lex_term_file((lexer_t*)(lx.ToPointer()), del_macros);
}

static bool ida_get_token(IntPtr t, IntPtr lx, IntPtr buf)
{
	auto tokenstack = (tokenstack_t*)(buf.ToPointer());
	if (!tokenstack->empty())
	{
		*(token_t*)(t.ToPointer()) = tokenstack->pop();
	}
	else if (lex_get_token((lexer_t*)(lx.ToPointer()), (token_t*)(t.ToPointer())) != eOk)
		return false;
	return true;
}

static void ida_unget_token(IntPtr t, IntPtr buf)
{
	auto tokenstack = (tokenstack_t*)(buf.ToPointer());
	tokenstack->push(*(const token_t*)(t.ToPointer()));
}

