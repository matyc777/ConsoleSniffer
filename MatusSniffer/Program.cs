using System;
using System.Collections.Generic;
using System.Threading;
using System.Net;

namespace MatusSniffer
{
    public enum Protocol
    {
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };

    class Program
    {
        static bool ContinueCapturing = false;
        static public string Adapter;

        static public bool GetContinueCapturing()
        {
            return ContinueCapturing;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Choose Network Adapter by input number");
            List<string> Adapters = new List<string>();
            IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));
            if (HosyEntry.AddressList.Length > 0)
            {
                int n = 0;
                foreach (IPAddress ip in HosyEntry.AddressList)
                {

                    Console.WriteLine("{0}. " + ip.ToString(), n++);
                    Adapters.Add(ip.ToString());
                }
            }
            ConsoleKeyInfo AdapterAnswer = Console.ReadKey();
            try
            {
                 Adapter = Adapters[int.Parse(AdapterAnswer.KeyChar.ToString())];
            }
            catch
            {
                Console.WriteLine("Wrong Adapter");
                Console.ReadKey();
                Environment.Exit(0);
            }
            Console.ReadKey();
            
            Console.WriteLine("Press Spacebar for start/stop sniffing");
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if(key.Key == ConsoleKey.Spacebar)
                {
                    if (!ContinueCapturing)
                    {
                        Sniffer sniffer = new Sniffer(Adapter);
                        ContinueCapturing = true;
                        Thread SniffThread = new Thread(sniffer.StartSniffing);
                        SniffThread.Start();
                        //start
                    }
                    else ContinueCapturing = false;
                }
            }
        }
    }
}
