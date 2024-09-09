using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    internal enum AnalysisFlags : uint
    {
        AF_CODE = 0x00000001,      //< Trace execution flow
        AF_MARKCODE = 0x00000002,      //< Mark typical code sequences as code
        AF_JUMPTBL = 0x00000004,      //< Locate and create jump tables
        AF_PURDAT = 0x00000008,      //< Control flow to data segment is ignored
        AF_USED = 0x00000010,      //< Analyze and create all xrefs
        AF_UNK = 0x00000020,      //< Delete instructions with no xrefs

        AF_PROCPTR = 0x00000040,      //< Create function if data xref data->code32 exists
        AF_PROC = 0x00000080,      //< Create functions if call is present
        AF_FTAIL = 0x00000100,      //< Create function tails
        AF_LVAR = 0x00000200,      //< Create stack variables
        AF_STKARG = 0x00000400,      //< Propagate stack argument information
        AF_REGARG = 0x00000800,      //< Propagate register argument information
        AF_TRACE = 0x00001000,      //< Trace stack pointer
        AF_VERSP = 0x00002000,      //< Perform full SP-analysis. (\ph{verify_sp})
        AF_ANORET = 0x00004000,      //< Perform 'no-return' analysis
        AF_MEMFUNC = 0x00008000,      //< Try to guess member function types
        AF_TRFUNC = 0x00010000,      //< Truncate functions upon code deletion

        AF_STRLIT = 0x00020000,      //< Create string literal if data xref exists
        AF_CHKUNI = 0x00040000,      //< Check for unicode strings
        AF_FIXUP = 0x00080000,      //< Create offsets and segments using fixup info
        AF_DREFOFF = 0x00100000,      //< Create offset if data xref to seg32 exists
        AF_IMMOFF = 0x00200000,      //< Convert 32bit instruction operand to offset
        AF_DATOFF = 0x00400000,      //< Automatically convert data to offsets

        AF_FLIRT = 0x00800000,      //< Use flirt signatures
        AF_SIGCMT = 0x01000000,      //< Append a signature name comment for recognized anonymous library functions
        AF_SIGMLT = 0x02000000,      //< Allow recognition of several copies of the same function
        AF_HFLIRT = 0x04000000,      //< Automatically hide library functions

        AF_JFUNC = 0x08000000,      //< Rename jump functions as j_...
        AF_NULLSUB = 0x10000000,      //< Rename empty functions as nullsub_...

        AF_DODATA = 0x20000000,      //< Coagulate data segs at the final pass
        AF_DOCODE = 0x40000000,      //< Coagulate code segs at the final pass
        AF_FINAL = 0x80000000,      //< Final pass of analysis
    }
}
