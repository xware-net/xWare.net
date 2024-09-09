using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum DelimiterFlags : byte
    {
        LMT_THIN = 0x01, //< thin borders
        LMT_THICK = 0x02, //< thick borders
        LMT_EMPTY = 0x04, //< empty lines at the end of basic blocks
    }
}
