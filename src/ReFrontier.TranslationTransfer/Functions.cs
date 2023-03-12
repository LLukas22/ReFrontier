using CsvHelper;
using Konsole;
using Microsoft.VisualBasic;
using ReFrontier.Library;
using System;
using System.Collections.Generic;
using System.IO.Enumeration;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace ReFrontier.TranslationTransfer
{
    static class Functions
    {

        public static string EncryptJPK(string decryptedFile, string metaFile=null,int level = 100,ushort type=4)
        {
            if (metaFile==null)
                metaFile = $"{decryptedFile}.meta";

            if (!File.Exists(metaFile))
                throw new Exception($"Meta-File '{metaFile}' must exist!");

            var filename = Path.GetFileNameWithoutExtension(decryptedFile);
            var dir = Path.GetDirectoryName(decryptedFile);
            var extension = Path.GetExtension(decryptedFile);

            var compressed_file = Path.Combine(dir, $"{filename}_compressed{extension}");
            var encrypted_file = Path.Combine(dir, $"{filename}_encrypted{extension}");

            Console.WriteLine($"Compressing '{decryptedFile}' into '{compressed_file}' with level {level}");
            Pack.JPKEncode(type, decryptedFile, compressed_file, level);
            Console.WriteLine($"Encrypting '{compressed_file}' into '{encrypted_file}'");
            byte[] buffer = File.ReadAllBytes(compressed_file);
            byte[] bufferMeta = File.ReadAllBytes(metaFile);
            buffer = Crypto.encEcd(buffer, bufferMeta);
            File.WriteAllBytes(encrypted_file, buffer);
            return encrypted_file;
        }

        public static string DecryptJPK(string input,out string metaFile)
        {
            var filename = Path.GetFileNameWithoutExtension(input);
            var dir = Path.GetDirectoryName(input);
            var extension = Path.GetExtension(input);
            metaFile=string.Empty;

            MemoryStream msInput = new MemoryStream(File.ReadAllBytes(input));
            BinaryReader brInput = new BinaryReader(msInput);
            if (msInput.Length == 0)
            { 
                Console.WriteLine("File is empty. Skipping.");
                
                return string.Empty; 
            }
            int fileMagic = brInput.ReadInt32();

            if (fileMagic != 0x1A646365)
            {
                throw new Exception("No ECD Header detected!");
            }

            var decrypted_name = Path.Combine(dir, $"{filename}_decrypted{extension}");
            //Decrypt File
            Console.WriteLine("ECD Header detected! Trying to decrypt file ...");
            byte[] buffer = File.ReadAllBytes(input);
            Crypto.decEcd(buffer);

            byte[] ecdHeader = new byte[0x10];
            Array.Copy(buffer, 0, ecdHeader, 0, 0x10);
            byte[] bufferStripped = new byte[buffer.Length - 0x10];
            Array.Copy(buffer, 0x10, bufferStripped, 0, buffer.Length - 0x10);

            metaFile=$"{decrypted_name}.meta";
            File.WriteAllBytes(decrypted_name, bufferStripped);
            File.WriteAllBytes(metaFile, ecdHeader);
            Console.WriteLine($"File '{input}' decrypted to '{decrypted_name}'.");

            brInput.Dispose();
            msInput.Dispose();

            //Open decrpyted File

            msInput = new MemoryStream(File.ReadAllBytes(decrypted_name));
            brInput = new BinaryReader(msInput);

            fileMagic = brInput.ReadInt32();
            if (fileMagic != 0x1A524B4A)
            {
                throw new Exception("No JKR Header detected!");
            }
            //Uncompress File

            var uncompressedFile = Unpack.UnpackJPK(decrypted_name,$"{filename}_uncompressed");
            Console.WriteLine($"File '{decrypted_name}' uncompressed to '{uncompressedFile}'.");

            brInput.Dispose();
            msInput.Dispose();

            return uncompressedFile;
        }

        public class TranslationEntry
        {
            public UInt32 Offset { get; set; }
            public UInt32 Hash { get; set; }
            public string Japanese { get; set; }
            public string Translation { get; set; }
        }


        public static byte[] CopyTranslationBlob(byte[] translated, byte[] toPatch)
        {
            var jap_length = toPatch.Length; //26454976
            var translated_length = translated.Length; //28717781

            var tranlated_blob = translated[jap_length..].ToList();

            var japanese_list = toPatch.ToList();

            var combined = japanese_list.Concat(tranlated_blob).ToArray();
            return combined;
        }
        public static string ExtractTranslations(string translatedFile,string japaneseFile, int startOffset = 3072, int endOffset = 3328538)
        {
            var dir = Path.GetDirectoryName(translatedFile);
            //Extract the texts from the JP File
            var texts = ExtractTexts(japaneseFile, startOffset, endOffset);

            //Build a dictionary 
            var offset_original_lookup = texts.ToDictionary(x => x.Offset, y => y);

            //Get the differenze in sizes of the files => The english translations are appended at the end
            var japanese_length = File.ReadAllBytes(japaneseFile).Length;
            var translated_length = File.ReadAllBytes(translatedFile).Length;
            var diff = translated_length-japanese_length;

            if (diff < 0)
                throw new Exception("The translation file contains no Translations!");

            var translated_texts = ExtractTexts(translatedFile, startOffset,-1);
            var offset_translation_lookup = translated_texts.ToDictionary(x => x.Offset, y => y);

            Console.WriteLine($"Trying to find english translations!");
            //Iterate pver the translation array and extract the pointers
            byte[] translatedArray = File.ReadAllBytes(translatedFile);
            byte[] japaneseArray = File.ReadAllBytes(japaneseFile);
            byte[] japaneseArray_toPatch = File.ReadAllBytes(japaneseFile);
            var handledPointers = new HashSet<uint>();
            var matched_translations = new List<TranslationEntry>();
            for (int p = 0; p < japaneseArray.Length; p += 4)
            {
                if (p + 4 > japaneseArray.Length) 
                    continue;
                //Get the original pointer
                uint original = (uint)BitConverter.ToInt32(japaneseArray, p);
                
                
                if (offset_original_lookup.ContainsKey((uint)original) && p > 10000)
                {
                    //Read the pointer from patched the file
                    uint patched = (uint)BitConverter.ToInt32(translatedArray, p);
                    //Compare both
                    if (original!=patched)
                    {
                        //Apply the patched pointer 
                        for(int k = 0; k<4; k++)
                        {
                            japaneseArray_toPatch[p+k]=translatedArray[p+k];
                        }
                        

                        if (offset_translation_lookup.ContainsKey(patched))
                        {
                            handledPointers.Add(original);
                            var original_entry = offset_original_lookup[original];
                            var translated_entry = offset_translation_lookup[patched];
                            matched_translations.Add(new() {
                                Offset=original_entry.Offset,
                                Hash=original_entry.Hash,
                                Japanese=original_entry.Japanese,
                                Translation=translated_entry.Japanese
                            });
                        }
                    }
                }
            }

            var patchedFileName = Path.Combine(dir, "patched.bin");
            var patchedArray = CopyTranslationBlob(translatedArray,japaneseArray_toPatch);
            File.WriteAllBytes(patchedFileName, patchedArray);
            Console.WriteLine($"Extracted {matched_translations.Count} translations!");


            return patchedFileName;
        }

        public static void WriteTranslations(List<TranslationEntry> translations,string path)
        {
            if (File.Exists(path))
                File.Delete(path);

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var encoding = Encoding.GetEncoding("shift-jis");

            StreamWriter txtOutput = new StreamWriter(path, true, encoding);
            txtOutput.WriteLine("Offset\tHash\tJapanese\tTranslation");
            foreach (var translation in translations)
            {
                txtOutput.WriteLine($"{translation.Offset}\t{translation.Hash}\t{translation.Japanese}\t{translation.Translation}");
            }
            txtOutput.Close();
        }

        // dump mhfpac.bin 4416 1278872
        // dump mhfdat.bin 3072 3328538
        public static List<TranslationEntry> ExtractTexts(string uncompressedFile,int startOffset= 3072,int endOffset= 3328538)
        {
            //var filename = Path.GetFileNameWithoutExtension(uncompressedFile);
            //var dir = Path.GetDirectoryName(uncompressedFile);

            //string output = "";
            byte[] buffer = File.ReadAllBytes(uncompressedFile);
            MemoryStream msInput = new MemoryStream(buffer);
            BinaryReader brInput = new BinaryReader(msInput);

            var end_length = endOffset > startOffset ? endOffset : brInput.BaseStream.Length;

            Console.WriteLine($"Extracting Translations at: 0x{startOffset.ToString("X8")} - 0x{end_length.ToString("X8")}. Size 0x{(end_length - startOffset).ToString("X8")}");

            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var encoding = Encoding.GetEncoding("shift-jis");

            brInput.BaseStream.Seek(startOffset, SeekOrigin.Begin);

            var entries = new List<TranslationEntry>();
            while (brInput.BaseStream.Position < end_length)
            {
                long off = brInput.BaseStream.Position;
                string str = Helpers.ReadNullterminatedString(brInput, encoding).
                    Replace("\t", "<TAB>"). // Replace tab
                    Replace("\r\n", "<CLINE>"). // Replace carriage return
                    Replace("\n", "<NLINE>"); // Replace new line
                entries.Add(new() { Offset=(uint)off,Hash=Helpers.GetCrc32(encoding.GetBytes(str)),Japanese=str });
                
            }
            Console.WriteLine($"Sucessfully dumped translations!");
            return entries;
        }


     

        public static string ApplyTranslations(string translationFile,string fileToPatch)
        {
            var filename = Path.GetFileNameWithoutExtension(fileToPatch);
            var dir = Path.GetDirectoryName(fileToPatch);
            var extension = Path.GetExtension(fileToPatch);


            byte[] inputArray = File.ReadAllBytes(fileToPatch);

            // Read csv
            var encoding = Encoding.GetEncoding("shift-jis");

            int GetNullterminatedStringLength(string input)
            {
                return encoding.GetBytes(input).Length + 1;
            }

            var stringDatabase = new List<TranslationEntry>();
            using (var reader = new StreamReader(translationFile, encoding))
            {
                using (var csv = new CsvReader(reader))
                {
                    csv.Configuration.Delimiter = "\t";
                    csv.Configuration.IgnoreQuotes = true;
                    csv.Configuration.MissingFieldFound = null;
                    csv.Read();
                    csv.ReadHeader();
                    while (csv.Read())
                    {
                        var record = new TranslationEntry
                        {
                            Offset = csv.GetField<UInt32>("Offset"),
                            Hash = csv.GetField<UInt32>("Hash"),
                            Translation = csv.GetField("Translation").
                            Replace("<TAB>", "\t"). // Replace tab
                            Replace("<CLINE>", "\r\n"). // Replace carriage return
                            Replace("<NLINE>", "\n") // Replace new line
                        };
                        stringDatabase.Add(record);
                    }
                }
            }

            // Get info for translation array and get all offsets that need to be remapped
            List<UInt32> eStringsOffsets = new List<uint>();
            List<Int32> eStringLengths = new List<int>();

            var pb_offsets = new ProgressBar(stringDatabase.Count);
            foreach (var obj in stringDatabase)
            {
                if (obj.Translation != "")
                {
                    eStringsOffsets.Add(obj.Offset);
                    eStringLengths.Add(GetNullterminatedStringLength(obj.Translation));
                }
                pb_offsets.Next("Getting Offsets");
            }
            int eStringsLength = eStringLengths.Sum();
            int eStringsCount = eStringLengths.Count;

            // Create dictionary with offset replacements
            var pb_offset_dict = new ProgressBar(eStringsCount);
            Dictionary<int, int> offsetDict = new Dictionary<int, int>();

            for (int i = 0; i < eStringsCount; i++)
            {
                offsetDict.Add((int)eStringsOffsets[i], inputArray.Length + eStringLengths.Take(i).Sum());
                pb_offset_dict.Next("Calculationg Offsets");
            }

            var pb_stringArray = new ProgressBar(stringDatabase.Count);
            byte[] eStringsArray = new byte[eStringsLength];
            for (int i = 0, j = 0; i < stringDatabase.Count; i++)
            {
                if (stringDatabase[i].Translation != "")
                {
                    // Write string to string array
                    byte[] eStringArray = encoding.GetBytes(stringDatabase[i].Translation);
                    Array.Copy(eStringArray, 0, eStringsArray, eStringLengths.Take(j).Sum(), eStringLengths[j] - 1);
                    j++;
                }
                pb_stringArray.Next("Building Encoded String Arrays");
            }

            // Replace offsets in binary file
            var pb_replace = new ProgressBar(inputArray.Length);
            for (int p = 0; p < inputArray.Length; p += 4)
            {
                if (p + 4 > inputArray.Length) continue;
                int cur = BitConverter.ToInt32(inputArray, p);
                if (offsetDict.ContainsKey(cur) && p > 10000)
                {
                    int replacement = 0;
                    offsetDict.TryGetValue(cur, out replacement);
                    byte[] newPointer = BitConverter.GetBytes(replacement);
                    for (int w = 0; w < 4; w++) inputArray[p + w] = newPointer[w];
                }
                pb_replace.Refresh(p, "Replacing Strings in Original File");
            }

            // Combine arrays
            byte[] outputArray = new byte[inputArray.Length + eStringsLength];
            Array.Copy(inputArray, outputArray, inputArray.Length);
            Array.Copy(eStringsArray, 0, outputArray, inputArray.Length, eStringsArray.Length);



            // Output file
            string outputFile = Path.Combine(dir, $"{filename}_patched{extension}");
            File.WriteAllBytes(outputFile, outputArray);
            Console.WriteLine($"Saved patched file as '{outputFile}'");
            return outputFile;

        }
    }
}
