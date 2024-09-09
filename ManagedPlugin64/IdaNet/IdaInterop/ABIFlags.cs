using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum ABIFlags : uint
    {
        ABI_8ALIGN4 = 0x00000001, //< 4 byte alignment for 8byte scalars (__int64/double) inside structures?
        ABI_PACK_STKARGS = 0x00000002, //< do not align stack arguments to stack slots
        ABI_BIGARG_ALIGN = 0x00000004, //< use natural type alignment for argument if the alignment exceeds native word size
        ABI_STACK_LDBL = 0x00000008, //< long double arguments are passed on stack
        ABI_STACK_VARARGS = 0x00000010, //< varargs are always passed on stack (even when there are free registers)
        ABI_HARD_FLOAT = 0x00000020, //< use the floating-point register set
        ABI_SET_BY_USER = 0x00000040, //< compiler/abi were set by user flag and require SETCOMP_BY_USER flag to be changed
        ABI_GCC_LAYOUT = 0x00000080, //< use gcc layout for udts (used for mingw)
        ABI_MAP_STKARGS = 0x00000100, //< register arguments are mapped to stack area (and consume stack slots)
        ABI_HUGEARG_ALIGN = 0x00000200, //< use natural type alignment for an argument
    }
}
