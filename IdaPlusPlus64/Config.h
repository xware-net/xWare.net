#pragma once

// complete

typedef void config_changed_cb_t(const cfgopt_t& opt, int vtype, const void* vdata);

static bool ida_parse_config_value(IntPtr out, IntPtr lx, IntPtr value)
{
	return parse_config_value((::idc_value_t*)(out.ToPointer()), (::lexer_t*)(lx.ToPointer()), *(const ::token_t*)(value.ToPointer()));
}

static IntPtr ida_cfgopt_t__apply(IntPtr _this, int vtype, IntPtr vdata)
{
	return IntPtr((void *)cfgopt_t__apply((const ::cfgopt_t*)(_this.ToPointer()), vtype, (const void*)(vdata.ToPointer())));
}

static IntPtr ida_cfgopt_t__apply2(IntPtr _this, int vtype, IntPtr vdata, IntPtr obj)
{
	return IntPtr((void *)cfgopt_t__apply2((const ::cfgopt_t*)(_this.ToPointer()), vtype, (const void*)(vdata.ToPointer()), (void*)(obj.ToPointer())));
}

static IntPtr ida_cfgopt_t__apply3(IntPtr _this, IntPtr lx, int vtype, IntPtr vdata, IntPtr obj)
{
	return IntPtr((void *)cfgopt_t__apply3((const ::cfgopt_t*)(_this.ToPointer()), (::lexer_t*)(lx.ToPointer()), vtype, (const void*)(vdata.ToPointer()), (void*)(obj.ToPointer())));
}

static bool ida_read_config(IntPtr input, cfg_input_kind_t is_file, cli::array<cfgopt_t*>^ opts, size_t nopts, IntPtr defhdlr, IntPtr defines, size_t ndefines)
{ 
	pin_ptr<cfgopt_t*> optsPtr = &opts[0];
	return read_config((const char*)(input.ToPointer()), is_file, (const cfgopt_t*)(optsPtr), nopts, (const char* (*)(::lexer_t*, const ::token_t&, const ::token_t&))(defhdlr.ToPointer()), (const char* const*)(defines.ToPointer()), ndefines);
}

static bool ida_read_config2(IntPtr input, cfg_input_kind_t is_file, cli::array<cfgopt_t*>^ opts, size_t nopts, IntPtr defhdlr, IntPtr defines, size_t ndefines, IntPtr obj)
{
	pin_ptr<cfgopt_t*> optsPtr = &opts[0];
	return read_config2((const char*)(input.ToPointer()), is_file, (const cfgopt_t*)(optsPtr), nopts, (const char* (*)(::lexer_t*, const ::token_t&, const ::token_t&))(defhdlr.ToPointer()), (const char* const*)(defines.ToPointer()), ndefines, (void*)(obj.ToPointer()));
}

static bool ida_read_config_file2(IntPtr filename, cli::array<cfgopt_t*>^ opts, size_t nopts, IntPtr defhdlr, IntPtr defines, size_t ndefines, IntPtr obj)
{
	return ida_read_config2(filename, cfg_input_kind_t::cik_path, opts, nopts, defhdlr, defines, ndefines, obj);
}

static bool ida_read_config_file(IntPtr filename, cli::array<cfgopt_t*>^ opts, size_t nopts, IntPtr defhdlr, IntPtr defines, size_t ndefines)
{
	return ida_read_config(filename, cfg_input_kind_t::cik_filename, opts, nopts, defhdlr, defines, ndefines);
}

static bool ida_read_config_string(IntPtr string, cli::array<cfgopt_t*>^ opts, size_t nopts, IntPtr defhdlr, IntPtr defines, size_t ndefines) 
{
	return ida_read_config(string, cfg_input_kind_t::cik_string, opts, nopts, defhdlr, defines, ndefines);
}

static bool ida_register_cfgopts(cli::array<cfgopt_t*>^ opts, size_t nopts, config_changed_cb_t cb, IntPtr obj)
{
	pin_ptr<cfgopt_t*> optsPtr = &opts[0];
	return register_cfgopts((const cfgopt_t*)(optsPtr), nopts, cb, (void*)(obj.ToPointer()));
}

