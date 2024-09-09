#pragma once

// complete

static error_t ida_parse_json(IntPtr out, IntPtr lx, IntPtr ungot_tokens)
{
	return parse_json((jvalue_t*)(out.ToPointer()), (lexer_t*)(lx.ToPointer()), (tokenstack_t*)(ungot_tokens.ToPointer()));
}

static error_t ida_parse_json_string(IntPtr out, IntPtr s)
{
	return parse_json_string((jvalue_t*)(out.ToPointer()), (const char*)(s.ToPointer()));
}

static bool ida_serialize_json1(IntPtr out, IntPtr o, uint32 flags)
{
	qstring buf;
	bool rc = serialize_json(&buf, (jobj_t*)(o.ToPointer()), flags);
	::ConvertQstringToIntPtr(buf, out, buf.size());
	return rc;
}


static bool ida_serialize_json(IntPtr out, IntPtr o, uint32 flags)
{
	jvalue_t v;
	v.set_obj((jobj_t*)(o.ToPointer()));
	qstring buf;
	bool rc = serialize_json(&buf, v, flags);
	v.extract_obj();
	::ConvertQstringToIntPtr(buf, out, buf.size());
	return rc;
}

