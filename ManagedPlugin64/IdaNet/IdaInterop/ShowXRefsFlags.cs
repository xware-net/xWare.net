using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum ShowXRefsFlags : byte
    {
        SW_XRFMRK = 0x02, //< show xref type marks?
        SW_XRFFNC = 0x04, //< show function offsets?
        SW_XRFVAL = 0x08, //< show xref values? (otherwise-"...")
    }
}
