#pragma once

// complete

static int ida_demangle(IntPtr answer, unsigned int answer_length, IntPtr str, unsigned int disable_mask)
{
	return demangle((char*)(answer.ToPointer()), answer_length, (const char*)(str.ToPointer()), disable_mask);
}

static mangled_name_type_t ida_get_mangled_name_type(IntPtr name)
{
	return get_mangled_name_type((const char*)(name.ToPointer()));
}

