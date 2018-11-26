﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ReFrontier
{
    class Helpers
    {
        public static string ReadNullterminatedString(BinaryReader brInput)
        {
            var charByteList = new List<byte>();
            string str = "";
            if (brInput.BaseStream.Position == brInput.BaseStream.Length)
            {
                byte[] charByteArray = charByteList.ToArray();
                str = Encoding.UTF8.GetString(charByteArray);
                return str;
            }
            byte b = brInput.ReadByte();
            while ((b != 0x00) && (brInput.BaseStream.Position != brInput.BaseStream.Length))
            {
                charByteList.Add(b);
                b = brInput.ReadByte();
            }
            byte[] char_bytes = charByteList.ToArray();
            str = Encoding.UTF8.GetString(char_bytes);
            return str;
        }
    }
}