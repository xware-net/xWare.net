#pragma once

// complete

static ssize_t ida_get_problem_desc(IntPtr buf, problist_id_t t, ea_t ea)
{
	qstring buffer;
	auto size = get_problem_desc(&buffer, t, ea);
	if (buf == IntPtr::Zero)
	{
		return size;
	}

	::ConvertQstringToIntPtr(buffer, buf, size);
	return size;
}

static void ida_remember_problem(problist_id_t type, ea_t ea, IntPtr msg)
{
	return remember_problem(type, ea, (const char*)(msg.ToPointer()));
}

static ea_t ida_get_problem(problist_id_t type, ea_t lowea)
{
	return get_problem(type, lowea);
}

static bool ida_forget_problem(problist_id_t type, ea_t ea)
{
	return forget_problem(type, ea);
}

static IntPtr ida_get_problem_name(problist_id_t type, bool longname)
{
	return IntPtr((void*)get_problem_name(type, longname));
}

static bool ida_is_problem_present(problist_id_t t, ea_t ea)
{
	return is_problem_present(t, ea);
}

static bool ida_was_ida_decision(unsigned long long ea)
{
	return is_problem_present(PR_FINAL, ea);
}

