using NativeLibraryGPGME.GPGME;
using System.Runtime.InteropServices;
using static NativeLibraryGPGME.GPGME.GPGMEService;

namespace NativeLibraryGPGME
{
    public class Program
    {
        static void Main(string[] args)
        {
            // Ruta del archivo .gpg a desencriptar
            string filePath = $@"C:\Users\Carlos Moreno\Documents\TextWithData.txt.gpg";

            // Frase secreta para la clave privada
            string passphrase = "la kisawa";

            string  decryptedText =  string.Empty;

            // Crear una instancia del desencriptador
            //var decryptor = new GpgDecryptor();

            //// Desencriptar el archivo
            //string decryptedText;
            //if (decryptor.DecryptFile(filePath, passphrase, out decryptedText))
            //{
            //    Console.WriteLine("Archivo desencriptado correctamente:");
            //    Console.WriteLine(decryptedText);
            //}
            //else
            //{
            //    Console.WriteLine("No se pudo desencriptar el archivo.");
            //}



            var result = gpgdecrypt.DecryptFile(filePath, passphrase, out decryptedText);

            Console.WriteLine(result);  

        }
    }
}
