using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static NativeLibraryGPGME.GPGME.GPGMEService;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace NativeLibraryGPGME.GPGME
{
    public class gpgdecrypt
    {

        //[DllImport("libgpgme-11.dll", CharSet = CharSet.Ansi,  CallingConvention = CallingConvention.Cdecl)]
        //private static extern IntPtr gpgme_new(int flags);


        //prueba con unmanaged type
        [DllImport("libgpgme-11.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr gpgme_new([MarshalAs(UnmanagedType.SysInt)] out IntPtr ctx);



        [DllImport("libgpgme-11.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        private static extern int  gpgme_set_passphrase_cb(IntPtr ctx, GpgmePassphraseCbDelegate callback);



        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "gpgme_op_import_keys")]
        public static extern int gpgme_import_keys(IntPtr ctx, gpgme_keylist_t keylist);


        // Importar la biblioteca libgpgme-11.dll
        [DllImport("libgpgme-11.dll", EntryPoint = "gpgme_keylist_new",  CallingConvention = CallingConvention.Cdecl)]
        public static extern gpgme_keylist_t gpgme_keylist_new();

        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void gpgme_keylist_free(gpgme_keylist_t keylist);

        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int gpgme_keylist_add(gpgme_keylist_t keylist, gpgme_key_t key);

        [DllImport("libgpgme-11.dll", EntryPoint = "gpgme_key_read", CallingConvention = CallingConvention.Cdecl)]
        public static extern gpgme_key_t gpgme_key_read_internal(string fname);


        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr gpgme_check_version(IntPtr version);



        // importacion con 3 parametros
        //[DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        //public static extern int gpgme_op_import(IntPtr ctx, string keydata, int flags);


        //importacion solo con 2 parametros
        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int gpgme_op_import(IntPtr ctx, IntPtr keydata);

        [DllImport("libgpgme-11.dll")]
        public static extern int gpgme_data_new_from_mem(out IntPtr dh, string buffer, int size, int copy);


        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int gpgme_data_new_from_mem(IntPtr data, int dataLen);

        
        [DllImport("libgpgme-11.dll", EntryPoint = "gpgme_data_new_from_mem", CallingConvention = CallingConvention.Cdecl)]
        public static extern gpgme_data gpgme_data_new_from_mem_data(IntPtr data, int dataLen);




        [DllImport("libgpgme-11.dll", EntryPoint = "gpgme_op_decrypt", CallingConvention = CallingConvention.Cdecl)]
        public static unsafe extern int gpgme_decrypt(IntPtr ctx, IntPtr data, IntPtr *plaintext);


        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static unsafe extern int gpgme_decrypt(IntPtr ctx, gpgme_data data, gpgme_data* plaintext);


        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void gpgme_data_free(IntPtr data);



        //release 

        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void gpgme_release(IntPtr ctx);


        // err

        [DllImport("libgpgme-11.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr gpgme_strerror(int errcode);





        //kernel32 para obtener la funcion no exportada

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);




        //struct 
        public struct gpgme_keylist_t
        {
            public IntPtr handle;
        };

        public struct gpgme_key_t
        {
            public IntPtr handle;
        };


        public struct gpgme_data
        {
            public IntPtr data;
            public int data_len;
            public int flags;
        }



        public static gpgme_key_t gpgme_key_read(string fname)
        {
            // Llamar a la función interna gpgme_key_read_internal
            gpgme_key_t key = gpgme_key_read_internal(fname);

            // Si la función devuelve un puntero nulo, lanzar una excepción
            if (key.handle == IntPtr.Zero)
            {
                // throw new GpgmeException("Error al leer la clave GPG");
                Console.WriteLine("error al leer clave GPG");
            }

            // Devolver la estructura gpgme_key_t
            return key;
        }


        public static string pass { get; set; }

        const int GPGME_VERSION_CHECK = 0x1100;
        const int GPGME_IMPORT_NO_SECRET = 0x0001;
        const int GPGME_IMPORT_ALL = 0x0002;
//#define GPGME_IMPORT_NO_ACTION          0x00000000
//#define GPGME_IMPORT_CHECK_TRUST        0x00000001
//#define GPGME_IMPORT_NO_CONFLICT       0x00000002
//#define GPGME_IMPORT_UPDATE_KEYSERVER   0x00000004
//#define GPGME_IMPORT_SIGN_KEY           0x00000008
//#define GPGME_IMPORT_EXPORT_KEYRING     0x00000010
//#define GPGME_IMPORT_NO_DECRYPT         0x00000020
//#define GPGME_IMPORT_ONLY_TRUSTED       0x00000040
//#define GPGME_IMPORT_NO_OWNERTRUST      0x00000080
//#define GPGME_IMPORT_ALLOW_SOCKET_OPEN  0x00000100



        //delegados
        public delegate int GpgmePassphraseCbDelegate(IntPtr ctx, int uid, int flags, out IntPtr passphrase, out int passphrase_size);

        public unsafe delegate int GpgmeDecryptCallback(IntPtr ctx, gpgme_data data, gpgme_data* plaintext);



        public static unsafe bool DecryptFile(string filePath, string passphrase, out string decryptedText)
        {
            pass = passphrase;
            decryptedText = string.Empty;


            IntPtr version = gpgme_check_version(IntPtr.Zero);

            Console.WriteLine(Marshal.PtrToStringUTF8(version));



            IntPtr ctx;

            //prueba para unmanaged type


            var err = gpgme_new(out ctx);

           // gpgme_release(ctx);



            if (err != 0)
            {
                int value = (int)err;
                IntPtr errorPtr = gpgme_strerror(value);
                string errorStr = Marshal.PtrToStringAnsi(errorPtr);

                Console.WriteLine("Error al crear el contexto: {0}", errorStr);
                return false;
            }


            GpgmePassphraseCbDelegate passphraseCallback = PassphraseCallback;

            var result = gpgme_set_passphrase_cb(ctx, passphraseCallback);

            string keyData =  string.Empty;
            byte[] buffer = new byte[4096];
            string path = @$"C:\Users\Carlos Moreno\Documents\Carlos Moreno_0x8D90B8B0_public.asc";

            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                keyData = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            }

            IntPtr keydata;
            var errorNewFormMem = gpgme_data_new_from_mem(out keydata, keyData, -1, 0);

            if (errorNewFormMem != 0)
            {
                int ErrorNewFormMem = (int)errorNewFormMem;
                IntPtr ErrorPtrFromMem = gpgme_strerror(ErrorNewFormMem);
                Console.WriteLine("Error data_from_mem: " + Marshal.PtrToStringAnsi(ErrorPtrFromMem));
                return false;

            }

            int errorImport = gpgme_op_import(ctx, keydata);

            // confirmar importacion con set gpgme_set_key

            //gpgme_error err = gpgme_set_key(ctx, "-----BEGIN PGP PRIVATE KEY----- ... -----END PGP PRIVATE KEY-----");



            if (errorImport != 0)
            {

                int Errvalue = (int)errorImport;
                IntPtr errorPtrImport = gpgme_strerror(Errvalue);
                string errorStrImport = Marshal.PtrToStringAnsi(errorPtrImport);
                throw new Exception("Error al importar la llave: " + errorStrImport);
            }
            byte[] data = File.ReadAllBytes(filePath);






            // obtener el puntero de array de bytes con Marshal para entregar en el metodo sobrecargado gpgme_data_new_from_mem que recibe un puntero de datos
            IntPtr ptrData = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, ptrData, data.Length);





            gpgme_data gpgmeDataPtr = gpgme_data_new_from_mem_data(ptrData, data.Length);


            IntPtr plaintextPtr = IntPtr.Zero;


            // requerido modificador unsafe
            // int errorDecrypt = gpgme_decrypt(ctx, gpgmeDataPtr, &plaintextPtr);

            GpgmeDecryptCallback callback = (ctx, gpgmeDataPtr, plaintext) =>
            {
                // Descifrar los datos
                int result = gpgme_decrypt(ctx, gpgmeDataPtr, plaintext);

                // Liberar la memoria
                //gpgme_data_free(gpgmeDataPtr);

                return result;
            };


            gpgme_data _plaintextPtr;

            int decrtypresult = GpgmeDecrypt(ctx, gpgmeDataPtr, &_plaintextPtr, callback);



            if (decrtypresult != 0)
            {
                Console.WriteLine("Error al descifrar los datos: {0}", result);
                return false;
            }

            string plaintext = Marshal.PtrToStringAnsi(_plaintextPtr.data);



            //if (errorDecrypt != 0)
            //{

            //    int ErrDecrypt = (int)errorDecrypt;
            //    IntPtr errorPtrDecrypt = gpgme_strerror(ErrDecrypt);
            //    string errorStrDecrypt = Marshal.PtrToStringAnsi(errorPtrDecrypt);
            //    Console.WriteLine("Error al importar la llave: " + errorStrDecrypt);
            //    return false;
            //}

            string plaintext_sec = Marshal.PtrToStringAnsi(plaintextPtr);

            Console.WriteLine(plaintext);
            decryptedText = plaintext;

            gpgme_release(ctx);

            return true;
        }


        public unsafe static int GpgmeDecrypt(IntPtr ctx, gpgme_data data, gpgme_data* plaintext, GpgmeDecryptCallback callback)
        {
            // ...

            // Llamar al delegado
            return callback(ctx, data, plaintext);
        }


        private static int PassphraseCallback(IntPtr ctx, int uid, int flags, out IntPtr passphrase, out int passphrase_size)
        {
            // Obtener la frase de contraseña del usuario
            string password = pass;

            // Convertir la frase de contraseña a una cadena de bytes
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Asignar memoria para la frase de contraseña
            passphrase = Marshal.AllocHGlobal(passwordBytes.Length);

            // Copiar la frase de contraseña en la memoria asignada
            Marshal.Copy(passwordBytes, 0, passphrase, passwordBytes.Length);

            // Asignar el tamaño de la frase de contraseña
            passphrase_size = passwordBytes.Length;

            // Retorno de éxito
            return 0;
        }


        public struct gpgme_context_t
        {
            public int version;
            public IntPtr opaque;
          //  public gpgme_error_t errcode;
            public string homedir;
            public string filename;
            public int fd;
            public int mode;
          //  public GpgmeProgressCbDelegate progress_cb;
            public IntPtr progress_cb_data;
          //  public GpgmeCancelCbDelegate cancel_cb;
            public IntPtr cancel_cb_data;
            public GpgmePassphraseCbDelegate passphrase_cb;
            public IntPtr passphrase_cb_data;
          //  public GpgmeArmorCbDelegate armor_cb;
            public IntPtr armor_cb_data;
          //  public GpgmeUnarmorCbDelegate unarmor_cb;
            public IntPtr unarmor_cb_data;
          //  public GpgmeTsigCallbackDelegate tsig_callback;
            public IntPtr tsig_callback_data;
          //  public gpgme_keylist_mode_t keylist_mode;
          //  public gpgme_protocol_t protocol;
            public int min_length;
            public int max_length;
            public int rsa_bits;
            public int dsa_bits;
            public int elgamal_bits;
            public int curve_bits;
            public int symmetric_algorithm;
            public int symmetric_key_length;
            public int compression_algorithm;
            public int compression_level;
            public int trust_model;
            public int default_key;
            public int subkey_list_mode;
            public int honor_expired;
            public int no_tty;
            public int quiet;
            public int verbose;
            public int debug;
            public int log_level;
            public string log_file;
            public string random_seed;
            public int random_bits;
            public int pinentry_mode;
            public string pinentry_program;
            public string card_model;
            public string card_id;
            public string pin;
            public int pin_tries;
            public int scdaemon_fd;
            public int scdaemon_port;
            public string scdaemon_addr;
            public int trust_signature;
            public int verify_signatures;
            public int check_sigs;
            public int no_secmem;
            public int use_agent;
            public int agent_fd;
            public string agent_env;
            public int batch;
            public int autosign;
            public int max_sigs;
            public int max_certs;
            public int max_attrs;
            public int keyserver_options;
            public string keyserver;
            public string keyserver_port;
            public string keyserver_http_proxy;
            public string keyserver_https_proxy;
            public int trust_dns;
            public int dns_servers;
            public int http_proxy;
            public int https_proxy;
            public int no_homedir;
            public int no_default_keyring;
            public int no_gpgconf;
            public int no_secring;
            public int no_trustdb;
            public int no_passwd;
            public int no_agent;
            public int no_autostart;
            public int status_fd;
            public int status_quiet;
            public int status_verbose;
            public int status_debug;
            public string status_format;
            public int status_color;
            public int status_timestamp;
            public int status_progress;
            public int status_completion;
            public int status_summary;
            public int status_keys;
            public int status_sigs;
            public int status_certs;
            public int status_attrs;
            public int status_subkeys;
            public int status_fpr;
            public int status_uid;
            public int status_email;
            public int status_filename;
            public int status_mtime;
            public int status_mode;
            public int status_owner;
            public int status_group;
            public int status_size;
            public int status_capabilities;
            public int status_fingerprint;
            public int status_hash_algorithm;
            public int status_hash_subalgorithm;
            public int status;

        }
    }
    }
