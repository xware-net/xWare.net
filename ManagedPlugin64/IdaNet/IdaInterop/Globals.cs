using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    public static class Globals
    {
        public static void setflag(ref SegmentFlags where, SegmentFlags bit, int cnd)
        {
            if (cnd != 0)
            {
                where = where | bit;
            }
            else
            {
                where = where & ~bit;
            }
        }

        public static void setflag(ref StructureFlags where, StructureFlags bit, bool cnd)
        {
            if (cnd != true)
            {
                where = where | bit;
            }
            else
            {
                where = where & ~bit;
            }
        }
    }
}
