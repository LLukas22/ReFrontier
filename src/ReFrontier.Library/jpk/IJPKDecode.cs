using System.IO;

namespace ReFrontier.Library.jpk
{
    interface IJPKDecode
    {
        byte ReadByte(Stream s);
        void ProcessOnDecode(Stream inStream, byte[] outBuffer);
    }
}
