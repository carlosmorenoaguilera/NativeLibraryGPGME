using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NativeLibraryGPGME.GPGME
{

    public class GpgmeData
    {
        public IntPtr Data { get; set; }
        public int DataLength { get; set; }
        public int Flags { get; set; }

        public GpgmeData(IntPtr data, int dataLength, int flags)
        {
            Data = data;
            DataLength = dataLength;
            Flags = flags;
        }
    }


}
