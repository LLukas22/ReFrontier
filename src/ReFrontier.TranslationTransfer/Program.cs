


using ReFrontier.TranslationTransfer;
using System.Runtime.ExceptionServices;

var source_file = args[0];
var target_file = args[1];
//var target_file = args[1];

var decompressedFile=Functions.DecryptJPK(source_file, out _);
var translations = Functions.ExtractTranslations(decompressedFile);



var decompressedTargetFile = Functions.DecryptJPK(target_file, out var targetMetaFile);
var patched_file = Functions.ApplyTranslations(translations, decompressedTargetFile);

var encrypted_patched_file = Functions.EncryptJPK(patched_file, targetMetaFile);
var dir = Path.GetDirectoryName(encrypted_patched_file);
var output = Path.Combine(dir, "mhfdat.bin");
File.Copy(encrypted_patched_file, output);
Console.WriteLine($"Sucessfully transfered translations into '{output}'!");
Console.ReadLine();