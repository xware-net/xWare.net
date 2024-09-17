using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    public class BytevecT : QVector<byte>
    {
        public bool Empty()
        {
            return base.Count == 0;
        }

        public void Qclear()
        {
            base.Clear();
        }

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
            for (int i = 0; i < base.Count; ++i)
            {
                if (this[i] != 0)
                    return false;
            }
            return true;
        }

    }
}
