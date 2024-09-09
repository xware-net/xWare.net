using System;

namespace IdaNet.IdaInterop
{
    public enum RefType : byte
    {
        V695_REF_OFF8 = 0,
        REF_OFF16 = 1,
        REF_OFF32 = 2,
        REF_LOW8 = 3,
        REF_LOW16 = 4,
        REF_HIGH8 = 5,
        REF_HIGH16 = 6,
        V695_REF_VHIGH = 7,
        V695_REF_VLOW = 8,
        REF_OFF64 = 9,
        REF_OFF8 = 10,
        REF_LAST = REF_OFF8,
    }
}
