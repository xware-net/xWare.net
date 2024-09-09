using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum LinePrefixFlags : byte
    {
        PREF_SEGADR = 0x01, //< show segment addresses?
        PREF_FNCOFF = 0x02, //< show function offsets?
        PREF_STACK = 0x04, //< show stack pointer?
        PREF_PFXTRUNC = 0x08, //< truncate instruction bytes if they would need more than 1 line
    }
}
