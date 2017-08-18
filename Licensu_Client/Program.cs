using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Licensu;

namespace Licensu_Client
{
    class Program
    {
        static void Main(string[] args)
        {
            string key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InBsdWdpbiI6IlhoSnRCZkpLRzEuVDFuS2djckdjUC5kdFVUUFRuQUJLLlp4UmFkTU5YbmEuTXhJVWxsUk5WUy5VQ3lMREJYb3phLkhja2dCRlZ3RVgudmRkbVhiVlN3cy5QaHptYnNBR05GIiwiZGF5c0xlZnQiOiIzMCIsImJhbm5lZCI6ImZhbHNlOmZhbHNlIiwiTUQ1Ijoia2V5Ym9hcmQgY2F0IiwiSVBCQU4iOiIzOjEiLCJJUFMiOiIiLCJIV0lEIjoiZmFsc2UifSwiaWF0IjoxNTAyNTI5OTcwLCJleHAiOjE1MDUxMjE5NzB9.9gdEDoV5eh6putzHKPe1ww8CdoOVYZGvvGt1pxKtawY";
            Core core = new Core(key, "clientcert.p12", "ca.crt", "xTurbo");
            core.remoteVariable = LoadMemory;
            iNotifAuth.StaticPropertyChanged += INotifAuth_StaticPropertyChanged;
            core.Authenticate();
            
            Console.ReadLine();
        }
        public static void LoadMemory(byte[] data)
        {
            
        }
        private static void INotifAuth_StaticPropertyChanged(object sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            Console.WriteLine(iNotifAuth.Status);
        }
    }
}
