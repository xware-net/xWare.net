#pragma once

// complete

static IntPtr ida_itext(help_t msg_id)
{
	return IntPtr((void *)itext(msg_id));
}

static void ida_Err(help_t format)
{
	verror(itext(format), nullptr);
}

static void ida_Warn(help_t format)
{
	vwarning(itext(format), nullptr);
}

static void ida_Info(help_t format)
{
	vinfo(itext(format), nullptr);
}

static int ida_Message(help_t format)
{
	int nbytes = vmsg(itext(format), nullptr);
	return nbytes;
}

static int ida_vask_yn(int deflt, help_t format, va_list va)
{
	return vask_yn(deflt, itext(format), va);
}

static int ida_ask_yn(int deflt, help_t format)
{
	int code = vask_yn(deflt, itext(format), nullptr);
	return code;
}

