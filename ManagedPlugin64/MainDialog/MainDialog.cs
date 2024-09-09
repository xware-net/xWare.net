using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using static IdaPlusPlus.IdaInterop;

namespace IdaNet.IdaInterop
{
    public class MainDialog
    {
        public unsafe static bool ExecuteMainDialog(ref bool optionPlaceStructs, ref bool optionProcessStatic, ref bool optionAudioOnDone)
        {
            bool ret;
            fixed (bool* x = &optionPlaceStructs, y = &optionProcessStatic, z = &optionAudioOnDone)
            {
                ret = DoMainDialog(x, y, z);
            };

            return ret;
        }

        public static List<SegmentT> GetSelectedSegments()
        {
            var segments = new List<SegmentT>();
            var selectedSegments = MainDialog_getSelectedSegments();
            foreach (var selectedSegment in selectedSegments)
            {
                segments.Add(new SegmentT(selectedSegment));
            }

            return segments;
        }
    }
}
