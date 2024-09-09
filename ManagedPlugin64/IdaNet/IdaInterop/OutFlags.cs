using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum OutFlags : UInt32
    {
        OFLG_SHOW_VOID = 0x002, //< Display void marks?
        OFLG_SHOW_AUTO = 0x004, //< Display autoanalysis indicator?
        OFLG_GEN_NULL = 0x010, //< Generate empty lines?
        OFLG_SHOW_PREF = 0x020, //< Show line prefixes?
        OFLG_PREF_SEG = 0x040, //< line prefixes with segment name?
        OFLG_LZERO = 0x080, //< generate leading zeroes in numbers
        OFLG_GEN_ORG = 0x100, //< Generate 'org' directives?
        OFLG_GEN_ASSUME = 0x200, //< Generate 'assume' directives?
        OFLG_GEN_TRYBLKS = 0x400, //< Generate try/catch directives?
    }
}
