#include "Utils.h"

// NOTE: both encodePid and decodePid assume pid is an non-negative
//   integer with less than 16 bits
int encodePid(unsigned char *buffer, int pid)
{
	buffer[0] = pid&0xff;
	buffer[1] = (pid >> 8)&0xff;
	return _PID_BYTE_SIZE;
}

int decodePid(int &pid, unsigned char *buffer)
{
	pid = ((buffer[1]&0xff) << 8) + (buffer[0]&0xff);
	return _PID_BYTE_SIZE;
}

void ulong2uchar(unsigned char *buffer, BN_ULONG val, int n_bytes)
{
	for (BN_ULONG i = 0; i < n_bytes; ++i)
		buffer[i] = (val >> (8*i))&0xff;
}

BN_ULONG uchar2ulong(unsigned char *buffer, int n_bytes)
{
	BN_ULONG ret = 0;
	for (BN_ULONG i = 0; i < n_bytes; ++i)
		ret += ((BN_ULONG)(buffer[i]&0xff) << (8*i));
	return ret;
}