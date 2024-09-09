using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Threading;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public class OggPlay
    {
        public static void EndPlay()
        {
            OggPlayer_EndPlay();
        }

        public static void Play()
        {
            OggPlayer_Play();
        }
    }
}
