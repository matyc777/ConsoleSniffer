using System;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace MatusSniffer
{
    class Sniffer
    {
        private string Adapter;
        private Socket SnifferSocket;
        byte[] byteData = new byte[4096];

        public Sniffer(string Adapter)
        {
            this.Adapter = Adapter;
        }

        public void StartSniffing()
        {

            try
            {
                SnifferSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                SnifferSocket.Bind(new IPEndPoint(IPAddress.Parse(Adapter), 0));
                SnifferSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                byte[] byOut = new byte[4] { 1, 0, 0, 0 };
                SnifferSocket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);
                SnifferSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
            }
            catch
            {
                Console.WriteLine("Something went wrong");
            }
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int nReceived = SnifferSocket.EndReceive(ar);

                ParseData(byteData, nReceived);

                if (Program.GetContinueCapturing())
                {
                    byteData = new byte[4096];

                    SnifferSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                        new AsyncCallback(OnReceive), null);
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                Console.WriteLine("Something went wrong");
            }
        }

        private void ParseData(byte[] byteData, int nReceived)
        {
            StringBuilder PacketInfo = new StringBuilder();
            IPHeader ipHeader = new IPHeader(byteData, nReceived);
            PacketInfo.Append("From: " + ipHeader.SourceAddress.ToString() + " to: " +
                ipHeader.DestinationAddress.ToString() + "\n");
            PacketInfo.Append("IP info:\n");
            PacketInfo.Append("Ver: " + ipHeader.Version + " Header Length: " + ipHeader.HeaderLength +
                " Differntiated Services: " + ipHeader.DifferentiatedServices + " Total Length: " + ipHeader.TotalLength +
                " Identification: " + ipHeader.Identification + " Flags: " + ipHeader.Flags + "\n");
            PacketInfo.Append("Fragmentation Offset: " + ipHeader.FragmentationOffset + " Time to live: " + ipHeader.TTL);
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    PacketInfo.Append(" Protocol: " + "TCP");
                    break;
                case Protocol.UDP:
                    PacketInfo.Append(" Protocol: " + "UDP");
                    break;
                case Protocol.Unknown:
                    PacketInfo.Append(" Protocol: " + "Unknown");
                    break;
            }
            PacketInfo.Append(" Checksum: " + ipHeader.Checksum + " Source: " + ipHeader.SourceAddress.ToString() + " Destination: " + ipHeader.DestinationAddress.ToString() + "\n");
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:

                    TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength);
                    PacketInfo.Append("Protocol(TCP) info:\n");
                    PacketInfo.Append("Source Port: " + tcpHeader.SourcePort);
                    PacketInfo.Append(" Destination Port: " + tcpHeader.DestinationPort);
                    PacketInfo.Append(" Sequence Number: " + tcpHeader.SequenceNumber);
                    if (tcpHeader.AcknowledgementNumber != "")
                        PacketInfo.Append(" Acknowledgement Number: " + tcpHeader.AcknowledgementNumber);
                    PacketInfo.Append("\nHeader Length: " + tcpHeader.HeaderLength);
                    PacketInfo.Append("Flags: " + tcpHeader.Flags);
                    PacketInfo.Append(" Window Size: " + tcpHeader.WindowSize);
                    PacketInfo.Append(" Checksum: " + tcpHeader.Checksum);
                    if (tcpHeader.UrgentPointer != "")
                        PacketInfo.Append(" Urgent Pointer: " + tcpHeader.UrgentPointer);
                    PacketInfo.Append("\n");
                    if (tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53")//Если порт равен 53, то базовым протоколом является DNS
                    {
                        DNSHeader dnsHeader = new DNSHeader(tcpHeader.Data, (int)tcpHeader.MessageLength);

                        PacketInfo.Append("Protocol(DNS) info:\n");
                        PacketInfo.Append("Identification: " + dnsHeader.Identification);
                        PacketInfo.Append(" Flags: " + dnsHeader.Flags);
                        PacketInfo.Append(" Questions: " + dnsHeader.TotalQuestions);
                        PacketInfo.Append(" Answer RRs: " + dnsHeader.TotalAnswerRRs);
                        PacketInfo.Append(" Authority RRs: " + dnsHeader.TotalAuthorityRRs);
                        PacketInfo.Append(" Additional RRs: " + dnsHeader.TotalAdditionalRRs + "\n");
                    }

                    break;

                case Protocol.UDP:

                    UDPHeader udpHeader = new UDPHeader(ipHeader.Data, (int)ipHeader.MessageLength);

                    PacketInfo.Append("Protocol(UDP) info:\n");
                    PacketInfo.Append("Source Port: " + udpHeader.SourcePort);
                    PacketInfo.Append(" Destination Port: " + udpHeader.DestinationPort);
                    PacketInfo.Append(" Length: " + udpHeader.Length);
                    PacketInfo.Append(" Checksum: " + udpHeader.Checksum + "\n");

                    if (udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53")//Если порт равен 53, то базовым протоколом является DNS
                    {
                        DNSHeader dnsHeader = new DNSHeader(udpHeader.Data, Convert.ToInt32(udpHeader.Length) - 8);

                        PacketInfo.Append("Protocol(DNS) info:\n");
                        PacketInfo.Append("Identification: " + dnsHeader.Identification);
                        PacketInfo.Append(" Flags: " + dnsHeader.Flags);
                        PacketInfo.Append(" Questions: " + dnsHeader.TotalQuestions);
                        PacketInfo.Append(" Answer RRs: " + dnsHeader.TotalAnswerRRs);
                        PacketInfo.Append(" Authority RRs: " + dnsHeader.TotalAuthorityRRs);
                        PacketInfo.Append(" Additional RRs: " + dnsHeader.TotalAdditionalRRs + "\n");
                    }

                    break;

                case Protocol.Unknown:
                    break;
            }

            Console.WriteLine(PacketInfo.ToString());
        }
    }
}
