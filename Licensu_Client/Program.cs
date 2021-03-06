﻿using System;
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

            List<Crypto.CertificateObject> certificates = new List<Crypto.CertificateObject>();
            certificates.Add(new Crypto.CertificateObject()
            {
                certificateFileExtension = ".ca",
                certificateName = "ca",
                // Cert data itself.
                data = {},
                // All caps, no space or -
                Thumbprint = "",
                isSSLAuth= false,

            });

            Core core = new Core(key, certificates, "xTurbo");
            core.remoteVariable = LoadMemory;
            iNotifAuth.StaticPropertyChanged += INotifAuth_StaticPropertyChanged;
            core.Authenticate();
            
            Console.ReadLine();
        }
        public static void LoadMemory(dynamic data)
        {
            // do stuff with the bytes
        }
        private static void INotifAuth_StaticPropertyChanged(object sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            Console.WriteLine(iNotifAuth.Status);
        }
    }
}
