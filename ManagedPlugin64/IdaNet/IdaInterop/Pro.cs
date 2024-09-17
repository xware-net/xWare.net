using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    public class BytevecT : QVector<byte>
    {
        public BytevecT(byte[] value)
        {
            Append(value);
        }

        public BytevecT Append(byte[] value)
        {
            base.AddRange(value);
            return this;
        }

        public bool AllZeros()
        {
            for (int i = 0; i < base.Size(); ++i)
            {
                if (this[i] != 0)
                    return false;
            }
            return true;
        }

    }
}
