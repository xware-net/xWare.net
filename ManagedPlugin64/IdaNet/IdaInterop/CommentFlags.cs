using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum CommentFlags : byte
    {
        SCF_RPTCMT = 0x01, //< show repeatable comments?
        SCF_ALLCMT = 0x02, //< comment all lines?
        SCF_NOCMT = 0x04, //< no comments at all
        SCF_LINNUM = 0x08, //< show source line numbers
        SCF_TESTMODE = 0x10, //< testida.idc is running
        SCF_SHHID_ITEM = 0x20, //< show hidden instructions
        SCF_SHHID_FUNC = 0x40, //< show hidden functions
        SCF_SHHID_SEGM = 0x80, //< show hidden segments
    }
}
