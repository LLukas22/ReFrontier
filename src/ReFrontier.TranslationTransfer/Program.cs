


using ReFrontier.TranslationTransfer;
using System.Runtime.ExceptionServices;

var source_file = args[0];
var japanese_file = args[1];

var decompressedFile = Functions.DecryptJPK(source_file, out var translated_metadata);
var Japanese_decompressedFile = Functions.DecryptJPK(japanese_file, out var japanese_meta_data);

Functions.ExtractQuestInfo(decompressedFile);
// TODO apply quest patches


// Transfer Translations
var translations = Functions.ExtractTranslations(decompressedFile, Japanese_decompressedFile);

var dir = Path.GetDirectoryName(source_file);
var translation_file = Path.Combine(dir, "translations.csv");

Functions.WriteTranslations(translations, translation_file);

var patched_file = Functions.ApplyTranslations(translation_file, Japanese_decompressedFile, decompressedFile);

var encrypted_patched_file = Functions.EncryptJPK(patched_file, translated_metadata);
var output = Path.Combine(dir, "mhfdat.bin");

if (File.Exists(output))
    File.Delete(output);
File.Copy(encrypted_patched_file, output);
Console.WriteLine($"Sucessfully transfered translations into '{output}'!");
Console.ReadLine();