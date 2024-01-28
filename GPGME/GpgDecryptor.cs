using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System;

namespace NativeLibraryGPGME.GPGME
{

    using System;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Runtime.Loader;

    public class GpgDecryptor
    {
        private IntPtr _libHandle;

        public GpgDecryptor()
        {
            // Cargar la biblioteca dinámica
            _libHandle = NativeLibrary.Load($@"C:\Program Files (x86)\Gpg4win\bin\libgpgme-11.dll");
        }

        ~GpgDecryptor()
        {
            // Liberar la biblioteca dinámica
            if (_libHandle != IntPtr.Zero)
            {
                NativeLibrary.Free(_libHandle);
            }
        }

        // Delegados necesarios

        private delegate int gpgme_new_delegate(out IntPtr ctx);
        private delegate int gpgme_data_new_delegate(out IntPtr data);
        private delegate int gpgme_set_passphrase_cb_delegate(IntPtr ctx, string passphrase);
        private delegate int gpgme_data_new_from_file_delegate(out IntPtr data, string filename, int binary);
        private delegate int gpgme_op_decrypt_delegate(IntPtr ctx, IntPtr cipher, IntPtr plain);
        private delegate int gpgme_data_read_delegate(IntPtr data, byte[] buffer, int count);

        // Funciones de la biblioteca dinámica
        public int gpgme_new(out IntPtr ctx) => GetFunction<gpgme_new_delegate>("gpgme_new")(out ctx);
        public int gpgme_data_new(out IntPtr data) => GetFunction<gpgme_data_new_delegate>("gpgme_data_new")(out data);
        public int gpgme_set_passphrase_cb(IntPtr ctx, string passphrase) => GetFunction<gpgme_set_passphrase_cb_delegate>("gpgme_set_passphrase_cb")(ctx, passphrase);
        public int gpgme_data_new_from_file(out IntPtr data, string filename, int binary) => GetFunction<gpgme_data_new_from_file_delegate>("gpgme_data_new_from_file")(out data, filename, binary);
        public int gpgme_op_decrypt(IntPtr ctx, IntPtr cipher, IntPtr plain) => GetFunction<gpgme_op_decrypt_delegate>("gpgme_op_decrypt")(ctx, cipher, plain);
        public int gpgme_data_read(IntPtr data, byte[] buffer, int count) => GetFunction<gpgme_data_read_delegate>("gpgme_data_read")(data, buffer, count);

        private T GetFunction<T>(string functionName) where T : Delegate
        {
            IntPtr funcPtr = NativeLibrary.GetExport(_libHandle, functionName);
            return funcPtr == IntPtr.Zero ? null : Marshal.GetDelegateForFunctionPointer<T>(funcPtr);
        }

        public bool DecryptFile(string filePath, string passphrase, out string decryptedText)
        {
            decryptedText = null;

            IntPtr ctx = IntPtr.Zero;
            IntPtr plain = IntPtr.Zero;
            IntPtr cipher = IntPtr.Zero;

            try
            {

                // Crear el contexto

                gpgme_new_delegate new_Delegate = gpgme_new;
                if (new_Delegate(out ctx) != 0)
                    return false;

                gpgme_data_new_delegate dataNewDelegate = gpgme_data_new;
                if (dataNewDelegate(out cipher) != 0)
                    return false;

                if (dataNewDelegate(out plain) == IntPtr.Zero)
                    return false;

                // Cargar el archivo cifrado
                gpgme_data_new_from_file_delegate dataNewFromFileDelegate = gpgme_data_new_from_file;
                if (dataNewFromFileDelegate(out cipher, filePath, 0) == IntPtr.Zero)
                    return false;

                // Configurar la frase secreta
                if (gpgme_set_passphrase_cb(ctx, passphrase) != 0)
                    return false;

                // Desencriptar
                gpgme_op_decrypt_delegate decryptDelegate = gpgme_op_decrypt;
                if (decryptDelegate(ctx, cipher, plain) == IntPtr.Zero)
                    return false;

                // Leer el texto desencriptado
                decryptedText = ReadDecryptedData(plain);

                return true;
            }
            finally
            {
                // Liberar recursos
                if (ctx != IntPtr.Zero)
                    gpgme_data_release(ctx);

                if (plain != IntPtr.Zero)
                    gpgme_data_release(plain);

                if (cipher != IntPtr.Zero)
                    gpgme_data_release(cipher);
            }
        }

        private string ReadDecryptedData(IntPtr data)
        {
            const int bufferSize = 1024;
            byte[] buffer = new byte[bufferSize];
            StringBuilder decryptedBuilder = new StringBuilder();

            gpgme_data_read_delegate dataReadDelegate = gpgme_data_read;
            int bytesRead;
            while ((bytesRead = dataReadDelegate(data, buffer, bufferSize)) > 0)
            {
                decryptedBuilder.Append(Encoding.UTF8.GetString(buffer, 0, bytesRead));
            }

            return decryptedBuilder.ToString();
        }

        // Liberar recursos para evitar pérdida de memoria
        private void gpgme_data_release(IntPtr data)
        {
            // No hay función gpgme_data_release en la biblioteca, podría ser necesario agregar una función de liberación personalizada si es necesaria.
        }
    }
}
