#pragma once

// complete

static void ida_vqperror(IntPtr format, va_list va)
{
	vqperror((const char*)(format.ToPointer()), va);
}

static IntPtr ida_qstrerror(error_t _qerrno)
{
	return IntPtr((void*)qstrerror(_qerrno));
}

static IntPtr ida_get_errdesc(IntPtr header, error_t _qerrno)
{
	return IntPtr((void*)get_errdesc((const char*)(header.ToPointer()), _qerrno));
}

static IntPtr ida_winerr(int code)
{
	return IntPtr((void*)winerr(code));
}

static IntPtr ida_qerrstr(int errno_code)
{
	return IntPtr((void*)qerrstr(errno_code));
}

static void ida_qperror(IntPtr format)
{
	vqperror((const char*)(format.ToPointer()), nullptr);
}

static void ida_set_errno(int code)
{
	(*_errno()) = code;
	set_qerrno(eOS);
}

static void ida_set_error_data(int n, size_t data)
{
	set_error_data(n, data);
}

static void ida_set_error_string(int n, IntPtr str)
{
	set_error_string(n, (const char*)(str.ToPointer()));
}

static size_t ida_get_error_data(int n)
{
	return get_error_data(n);
}

static IntPtr ida_get_error_string(int n)
{
	return IntPtr((void*)get_error_string(n));
}

#ifdef OBSOLETE_FUNCS
static int ida_qerrcode(int new_code)
{
	return qerrcode(new_code);
}
#endif
