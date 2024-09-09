using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    public enum FFFlags : uint
    {
        MS_VAL  = 0x000000FF,
        MS_CLS = 0x00000600,             ///< Mask for typing
        FF_CODE = 0x00000600,             ///< Code ?
        FF_DATA = 0x00000400,             ///< Data ?
        FF_TAIL = 0x00000200,             ///< Tail ?
        FF_UNK = 0x00000000,             ///< Unknown ?

        FF_IVL  = 0x00000100,
        FF_BYTE = 0x00000000,         ///< byte
        FF_WORD = 0x10000000,         ///< word
        FF_DWORD = 0x20000000,         ///< double word
        FF_QWORD = 0x30000000,         ///< quadro word
        FF_TBYTE = 0x40000000,         ///< tbyte
        FF_STRLIT = 0x50000000,         ///< string literal
        FF_STRUCT = 0x60000000,         ///< struct variable
        FF_OWORD = 0x70000000,         ///< octaword/xmm word (16 bytes/128 bits)
        FF_FLOAT = 0x80000000,         ///< float
        FF_DOUBLE = 0x90000000,         ///< double
        FF_PACKREAL = 0xA0000000,         ///< packed decimal real
        FF_ALIGN = 0xB0000000,         ///< alignment directive
        FF_CUSTOM = 0xD0000000,         ///< custom data type
        FF_YWORD = 0xE0000000,         ///< ymm word (32 bytes/256 bits)
        FF_ZWORD = 0xF0000000,         ///< zmm word (64 bytes/512 bits)

        DT_TYPE = 0xF0000000,             //< Mask for DATA typing
        MS_COMM = 0x000FF800,            //< Mask of common bits
        FF_COMM = 0x00000800,            //< Has comment ?
        FF_REF = 0x00001000,            //< has references
        FF_LINE = 0x00002000,            //< Has next or prev lines ?
        FF_NAME = 0x00004000,            //< Has name ?
        FF_LABL = 0x00008000,            //< Has dummy name?
        FF_FLOW = 0x00010000,            //< Exec flow from prev instruction
        FF_SIGN = 0x00020000,            //< Inverted sign of operands
        FF_BNOT = 0x00040000,            //< Bitwise negation of operands
        FF_UNUSED = 0x00080000,           //< unused bit (was used for variable bytes)

        FF_FUNC = 0x10000000,             ///< function start?
        FF_IMMD = 0x40000000,             ///< Has Immediate value ?
        FF_JUMP = 0x80000000,             ///< Has jump table or switch_info?

    }
}
