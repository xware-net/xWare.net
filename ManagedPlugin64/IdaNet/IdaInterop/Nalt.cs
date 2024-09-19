using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using EaT = System.UInt64;
using TidT = System.UInt64;
using SelT = System.UInt64;
using SizeT = System.UInt64;
using AsizeT = System.UInt64;
using AdiffT = System.Int64;
using UvalT = System.UInt64;
using BgcolorT = System.UInt32;
using FlagsT = System.UInt32;

using System.Runtime.InteropServices;

namespace IdaNet.IdaInterop
{
    public struct XrefposT
    {

    }

    public struct ArrayParametersT
    {

    }

    public struct SwitchInfoT
    {

    }

    public unsafe struct StrpathT
    {
        int len;
        fixed TidT ids[32]; // for union member ids
        AdiffT delta;
    }

    public struct EnumConstT
    {
        TidT tid;
        byte serial;
    }

    public struct RefinfoT
    {
        public EaT target;
        public EaT basr;
        public AdiffT tdelta;
        public UInt32 flags;
    }

    public struct CustomDataTypeIdsT
    {
    }

    public struct CustomRefinfoHandlerT
    {

    }

    public struct RefinfoDescT
    {
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct OpinfoT
    {
        [FieldOffset(0)]
        public RefinfoT ri;
        [FieldOffset(0)]
        public TidT tid;
        [FieldOffset(0)]
        public StrpathT path;
        [FieldOffset(0)]
        public Int32 strtype;
        [FieldOffset(0)]
        public EnumConstT ec;
        [FieldOffset(0)]
        public CustomDataTypeIdsT cd;

        [FieldOffset(0x1000)]
        public IntPtr UnmanagedPtr;

        public OpinfoT(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            ri = new RefinfoT();
            tid = new TidT();
            path = new StrpathT();
            strtype = new Int32();
            ec = new EnumConstT();
            cd = new CustomDataTypeIdsT();
        }
    }

    public struct PrintopT
    {

    }

    public class Nalt
    {
    }
}
