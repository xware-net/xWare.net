#pragma once

static ssize_t ida_qsendto(int socket, IntPtr buf, size_t size, int flags, IntPtr dest_addr, int addrlen)
{
	return ::sendto(socket, (const char*)(buf.ToPointer()), size, flags, (const struct sockaddr*)(dest_addr.ToPointer()), addrlen);
}

static ssize_t ida_qrecvfrom(int socket, IntPtr buf, size_t size, int flags, IntPtr src_addr, IntPtr addrlen)
{
	return ::recvfrom(socket, (char*)(buf.ToPointer()), size, flags, (struct sockaddr*)(src_addr.ToPointer()), (int*)(addrlen.ToPointer()));
}

static ssize_t ida_qsend(int socket, IntPtr buf, size_t size)
{
	return qsendto(socket, (const char*)(buf.ToPointer()), size, 0, nullptr, 0);
}

static ssize_t ida_qrecv(int socket, IntPtr buf, unsigned long long size)
{
	return qrecvfrom(socket, (char*)(buf.ToPointer()), size, 0, nullptr, nullptr);
}

static int ida_qselect(int nflds, IntPtr rds, IntPtr wds, IntPtr eds, IntPtr timeout)
{
	return ::select(nflds, (fd_set*)(rds.ToPointer()), (fd_set*)(wds.ToPointer()), (fd_set*)(eds.ToPointer()), (const timeval*)(timeout.ToPointer()));
}

static bool ida_qhost2addr_(IntPtr out, IntPtr name, unsigned short family, unsigned short port)
{
	return qhost2addr_((void*)(out.ToPointer()), (const char*)(name.ToPointer()), family, port);
}

static bool ida_qhost2addr(IntPtr out, IntPtr name, unsigned short port, bool ipv6)
{
	return qhost2addr_((void*)(out.ToPointer()), (const char*)(name.ToPointer()), ipv6 ? AF_INET6 : AF_INET, port);
}

//static qstring ida_get_mac_address(bool all) // ???
//{
//	return get_mac_address(all);
//}
//
