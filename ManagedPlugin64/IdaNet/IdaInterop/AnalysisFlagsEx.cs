using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum AnalysisFlagsEx : uint
    {
        AF2_DOEH = 0x00000001,          //< Handle EH information
        AF2_DORTTI = 0x00000002,        //< Handle RTTI information
        AF2_MACRO = 0x00000004,         //< Try to combine several instructions
    }
}
