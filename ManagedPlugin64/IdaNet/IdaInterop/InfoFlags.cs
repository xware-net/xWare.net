using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum InfoFlags : UInt16
    {
        INFFL_AUTO = 0x01, //< Autoanalysis is enabled?
        INFFL_ALLASM = 0x02, //< may use constructs not supported by
        INFFL_LOADIDC = 0x04, //< loading an idc file that contains database info
        INFFL_NOUSER = 0x08, //< do not store user info in the database
        INFFL_READONLY = 0x10, //< (internal) temporary interdiction to modify the database
        INFFL_CHKOPS = 0x20, //< check manual operands? (unused)
        INFFL_NMOPS = 0x40, //< allow non-matched operands? (unused)
        INFFL_GRAPH_VIEW = 0x80, //< currently using graph options (\dto{graph})
    }
}
