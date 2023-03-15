using CsvHelper;
using Konsole;
using Microsoft.VisualBasic;
using ReFrontier.Library;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.IO.Enumeration;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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

        public class QuestEntry
        {
            public int ID { get; set; }
            public int Flag { get; set; }
            public int Info { get; set; }
        }
        public static void ExtractQuestInfo(string decryptedFile)
        {
            var dir = Path.GetDirectoryName(decryptedFile);
            byte[] data = File.ReadAllBytes(decryptedFile);
            var flagset = new HashSet<int>();
            var infoset = new HashSet<int>();

            Dictionary<Ranks, List<QuestEntry>> questData = new();
            foreach(var rank in Enum.GetValues<Ranks>())
            {
                var rankData = new List<QuestEntry>();

                var rank_start_address = MHFDat.GetRankAddress(rank, data);

                for(var i=0; true; i++)
                {
                    var quest_address = rank_start_address + (i * 8);

                    if (quest_address>=MHFDat.OriginalLength)
                        break;

                    int quest_id = BitConverter.ToInt16(data, quest_address);
                    if (quest_id==0)
                        break;

                    int flag = BitConverter.ToInt16(data, quest_address + 2);
                    int info = BitConverter.ToInt16(data, quest_address + 4);
                    int unknown = BitConverter.ToInt16(data, quest_address + 6);

                    flagset.Add(flag);
                    infoset.Add(info);
                    rankData.Add(new() { ID = quest_id, Info=info, Flag=flag });

                }

                questData.Add(rank, rankData);
            }
            
            string fileName = Path.Combine(dir, "keyquestinfo.json");
            var options = new JsonSerializerOptions { WriteIndented = true };
            string jsonString = JsonSerializer.Serialize<Dictionary<Ranks, List<QuestEntry>>>(questData, options);
            File.WriteAllText(fileName, jsonString);

        }

        public class TranslationEntry
        {
            public UInt32 Offset { get; set; }
            public UInt32 Hash { get; set; }
            public string Japanese { get; set; }
            public string Translation { get; set; }
        }



        public static T[] ConcatArrays<T>(T[] first, T[] second)
        {
            var result = new T[first.Length + second.Length];
            first.CopyTo(result, 0);
            second.CopyTo(result, first.Length);
            return result;
        }
        /// <summary>
        /// Can be used to add the padded translations from a translated file to an original japanese file
        /// </summary>
        public static byte[] CopyTranslationBlob(byte[] translated, byte[] toPatch)
        {
            var jap_length = toPatch.Length; //26454976 for original mhfdat.bin
            var translated_length = translated.Length; //28717781 for mhfdat.bin of community edition 4.1

            if(jap_length <= translated_length)
            {
                throw new Exception();
            }
            var tranlated_blob = translated[jap_length..];

            return ConcatArrays(toPatch, tranlated_blob);
        }
        public static List<TranslationEntry> ExtractTranslations(string translatedFile,string japaneseFile, int startOffset = 3072, int endOffset = 3328538)
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

            //Extract the english translations from the end of the file
            var translated_texts = ExtractTexts(translatedFile, japanese_length, -1);
            var offset_translation_lookup = translated_texts.ToDictionary(x => x.Offset, y => y);

            Console.WriteLine($"Trying to find english translations!");

            byte[] translatedArray = File.ReadAllBytes(translatedFile);
            byte[] japaneseArray = File.ReadAllBytes(japaneseFile);
            //byte[] japaneseArray_toPatch = File.ReadAllBytes(japaneseFile);
            var matched_translations = new Dictionary<uint,TranslationEntry>();
            //Iterate over the original file 
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
                        //for(int k = 0; k<4; k++)
                        //{
                        //    japaneseArray_toPatch[p+k]=translatedArray[p+k];
                        //}
                        
                        //Check if the entry is translated
                        if (offset_translation_lookup.ContainsKey(patched))
                        {
                            var original_entry = offset_original_lookup[original];
                            var translated_entry = offset_translation_lookup[patched];

                            if (!matched_translations.ContainsKey(original_entry.Offset))
                            {
                                matched_translations.Add(original_entry.Offset, new()
                                {
                                    Offset=original_entry.Offset,
                                    Hash=original_entry.Hash,
                                    Japanese=original_entry.Japanese,
                                    Translation=translated_entry.Japanese
                                });
                            }
                        }
                    }
                }
            }

            //var patchedFileName = Path.Combine(dir, "patched.bin");
            //var patchedArray = CopyTranslationBlob(translatedArray,japaneseArray_toPatch);
            // File.WriteAllBytes(patchedFileName, patchedArray);
            Console.WriteLine($"Extracted {matched_translations.Count} translations!");

            var sorted_translations = matched_translations.Select(kvp => kvp.Value).OrderBy(o => o.Offset).ToList();
            return sorted_translations;
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
        public static List<TranslationEntry> ExtractTexts(string uncompressedFile,int startOffset= MHFDat.JapaneseTextStart, int endOffset= MHFDat.JapaneseTextEnd)
        {
            byte[] buffer = File.ReadAllBytes(uncompressedFile);
            using MemoryStream msInput = new MemoryStream(buffer);
            using BinaryReader brInput = new BinaryReader(msInput);

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


        
        static byte[] paddingbyte = new byte[1];
        class PatchEntry
        {
            public PatchEntry(int offset, string text,Encoding encoding)
            {
                this.Offset = offset;
                this.Text = text;
                this.Encoded = ConcatArrays(encoding.GetBytes(text), paddingbyte) ; //The encoding must be 00 terminated => add a 0 to the end of the array
                this.Length = Encoded.Length;
            }

            public readonly int Offset;
            public readonly int Length;
            public readonly byte[] Encoded;
            public readonly string Text;
        }

        public static T[] ConcatArrays<T>(params T[][] p)
        {
            var position = 0;
            var outputArray = new T[p.Sum(a => a.Length)];
            foreach (var curr in p)
            {
                Array.Copy(curr, 0, outputArray, position, curr.Length);
                position += curr.Length;
            }
            return outputArray;
        }


        public static string ApplyTranslations(string translationFile,string fileToPatch,string translatedFile)
        {
            var filename = Path.GetFileNameWithoutExtension(fileToPatch);
            var dir = Path.GetDirectoryName(fileToPatch);
            var extension = Path.GetExtension(fileToPatch);

            byte[] inputArray = File.ReadAllBytes(fileToPatch);
            byte[] translatedArray = File.ReadAllBytes(translatedFile);

            var encoding = Encoding.GetEncoding("shift-jis");

            // Read csv
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
            Dictionary<int,PatchEntry> patchEntriesLookup = new ();
            List<PatchEntry> patchEntries = new();
            //Create the patch entries, these will calculate the encoding,offset and length of each english entry
            foreach (var entry in stringDatabase)
            {
                if (string.IsNullOrEmpty(entry.Translation))
                    continue;

                PatchEntry patch_entry = new((int)entry.Offset, entry.Translation, encoding);
                patchEntriesLookup.Add((int)entry.Offset, patch_entry);
                patchEntries.Add(patch_entry);
            }


            // create a dictionary for each offset. We later need to search all original japanese pointers and swap them with the english ones
            Dictionary<int, int> offsetLookup = new Dictionary<int, int>();
            int startAddress = inputArray.Length; //We will append the translations to the file => Start at the end of the original file
            foreach(var patch in patchEntries)
            {
                offsetLookup.Add(patch.Offset, startAddress);
                startAddress += patch.Length; //advance the pointer to the next padded 00
            }

            //Create the English Translation Array by combining all encodings
            var encoded_translations = patchEntries.Select(x => x.Encoded).ToArray();
            var englishBlob = ConcatArrays(encoded_translations);


            //Open a second copy of the original file that actually will be modified
            var patched_array = File.ReadAllBytes(fileToPatch);
            patched_array = ConcatArrays(patched_array, englishBlob);

            var successfull_patches = 0;

            //Iterate over the original file and search all pointers that need to be remapped
            for (int p = 0; p < inputArray.Length; p += 4)
            {
                if (p + 4 > inputArray.Length)
                    continue;

                int currentPointer = BitConverter.ToInt32(inputArray, p);
                //If we found a new pointer we exchange them
                if (p > MHFDat.TranslationPointersStart && offsetLookup.ContainsKey(currentPointer))
                {
                    //check if we are in a region we dont want to patch
                    bool skip = false;
                    foreach(var (start,end) in MHFDat.TranslationInvalidRegions)
                    {
                        if (p>=start && p<=end)
                            skip=true;
                    }

                    if (skip)
                        continue;

                    int replacement = offsetLookup[currentPointer];
                    //Get binary Representation
                    byte[] newPointer = BitConverter.GetBytes(replacement);
                    //Apply it to the patched array
                    for (int w = 0; w < 4; w++)
                        patched_array[p + w] = newPointer[w];

                    successfull_patches++;
                }
            }

            Console.WriteLine($"Applied {successfull_patches} patches!");

            // Output file
            string outputFile = Path.Combine(dir, $"{filename}_patched{extension}");
            File.WriteAllBytes(outputFile, patched_array);
            Console.WriteLine($"Saved patched file as '{outputFile}'");
            return outputFile;

        }
    }
}
