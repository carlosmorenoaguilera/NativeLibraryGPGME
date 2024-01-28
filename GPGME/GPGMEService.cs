using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NativeLibraryGPGME.GPGME
{


    public class GPGMEService
    {
        // Definición del delegado para la función gpgme_new
        public delegate IntPtr GpgmeNewDelegate(int flags);

        // Importación de la función gpgme_new desde la dll libgpgme-11.dll
        [DllImport($@"C:\Program Files (x86)\Gpg4win\bin\libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr gpgme_new(int flags);



        public delegate int GpgmePassphraseCbDelegate(IntPtr context, int uid, int flags, out IntPtr passphrase, out int passphrase_size);

        // Importación de la función gpgme_set_passphrase_cb desde la dll libgpgme-11.dll
        [DllImport($@"C:\Program Files (x86)\Gpg4win\bin\libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int gpgme_set_passphrase_cb(IntPtr context, GpgmePassphraseCbDelegate callback);



        // Methdos

        //public void DecryptFile(string encryptedFilePath, string outputFilePath, string passphrase)
        //{
        //    // Obtención del contexto GPGME
        //    IntPtr gpgmeContext = gpgme_new(0);

        //    int passphrase_size;
        //    IntPtr passphrase;


        //    // Definición de la función de devolución de llamada para la contraseña
        //    GpgmePassphraseCbDelegate passphraseCallback = (context, uid, flags, out  passphrase, out  passphrase_size) =>
        //    {
        //        // Obtención de la contraseña del usuario
        //        string password = "La kisawa";

        //        // Conversión de la contraseña a una cadena de bytes
        //        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        //        // Asignación de la memoria para la contraseña
        //        passphrase = Marshal.AllocHGlobal(passwordBytes.Length);

        //        // Copia de la contraseña en la memoria asignada
        //        Marshal.Copy(passwordBytes, 0, passphrase, passwordBytes.Length);

        //        // Asignación del tamaño de la contraseña
        //        passphrase_size = passwordBytes.Length;

        //        // Retorno de éxito
        //        return 0;
        //    };

        //    // Configuración de la función de devolución de llamada para la contraseña
        //    int result = gpgme_set_passphrase_cb(gpgmeContext, passphraseCallback);

        //    if (result != 0)
        //    {
        //        Console.WriteLine("Error al configurar la función de devolución de llamada para la contraseña");
        //        return;
        //    }

        //    // ... (código para importar la clave GPG y desencriptar el archivo) ...

        //    // Liberación del contexto GPGME
        //    gpgme_release(gpgmeContext);
        //}

        // Función de devolución de llamada para la contraseña
        //public static int PassphraseCallback(IntPtr context, int uid, int flags, out IntPtr passphrase, out int passphrase_size)
        //{
        //    // Obtención de la contraseña del usuario
        //    string password = "La kisawea";

        //    // Conversión de la contraseña a una cadena de bytes
        //    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        //    // Asignación de la memoria para la contraseña
        //    passphrase = Marshal.AllocHGlobal(passwordBytes.Length);

        //    // Copia de la contraseña en la memoria asignada
        //    Marshal.Copy(passwordBytes, 0, passphrase, passwordBytes.Length);

        //    // Asignación del tamaño de la contraseña
        //    passphrase_size = passwordBytes.Length;

        //    // Retorno de éxito
        //    return 0;
        //}


    }



}
