using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    public enum DelItemsFlags 
    {
        DELIT_SIMPLE = 0x0000,  //< simply undefine the specified item(s)
        DELIT_EXPAND = 0x0001,  //< propagate undefined items; for example
                                //< if removing an instruction removes all
                                //< references to the next instruction, then
                                //< plan to convert to unexplored the next
                                //< instruction too.
        DELIT_DELNAMES = 0x0002,  //< delete any names at the specified
                                  //< address range (except for the starting
                                  //< address). this bit is valid if nbytes > 1
        DELIT_NOTRUNC = 0x0004,  //< don't truncate the current function
                                 //< even if #AF_TRFUNC is set
        DELIT_NOUNAME = 0x0008,  //< reject to delete if a user name is
                                 //< in address range (except for the starting
                                 //< address). this bit is valid if nbytes > 1
        DELIT_NOCMT = 0x0010,  //< reject to delete if a comment is
                               //< in address range (except for the starting
                               //< address). this bit is valid if nbytes > 1
        DELIT_KEEPFUNC = 0x0020,  //< do not undefine the function start.
                                  //< Just delete xrefs, ops e.t.c.
    }
}
