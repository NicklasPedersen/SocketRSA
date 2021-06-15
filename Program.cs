using System;
using System.Collections;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace SocketRSA
{
    public class RSAPublicKey
    {
        public string Name { get; set; }
        public byte[] Exp { get; set; }
        public byte[] Mod { get; set; }
    }
    public class HandshakeMessage
    {
        public byte[] AesKey { get; set; }
    }
    public class ChatMessage
    {
        public string Message { get; set; }
    }
    class Program
    {
        public static byte[] EncryptMessage(byte[] broadcastBytes, RSAParameters key)
        {
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(key);

                return RSA.Encrypt(broadcastBytes, false);
            }
        }
        static void Send(TcpClient client, byte[] bytes)
        {
            NetworkStream stream = client.GetStream();
            if (!stream.CanWrite) return;
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush();
        }
        public static Hashtable clientsList = new Hashtable();
        static readonly List<(string, TcpClient, RSAParameters)> clients = new List<(string, TcpClient, RSAParameters)>();
        static readonly RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);

        static void Main()
        {

            //TcpListener serverSocket = new TcpListener(portFromAppConfig);

            TcpListener serverSocket = new TcpListener(System.Net.IPAddress.Any, 1337);
            serverSocket.Start();

            Console.WriteLine("Welcome to NYP Chat Server ");
            Console.WriteLine("Press ESC to stop");
            do
            {
                while (!Console.KeyAvailable)
                {
                    TcpClient clientSocket = serverSocket.AcceptTcpClient();
                    AesManaged aes = new AesManaged();
                    aes.GenerateKey();

                    byte[] bytesFrom = new byte[clientSocket.ReceiveBufferSize];

                    NetworkStream networkStream = clientSocket.GetStream();
                    int bytes_read = networkStream.Read(bytesFrom, 0, clientSocket.ReceiveBufferSize);
                    string dataFromClient = Encoding.UTF8.GetString(bytesFrom, 0, bytes_read);

                    var m = JsonSerializer.Deserialize<RSAPublicKey>(dataFromClient);
                    RSAParameters rps = rsa.ExportParameters(false);
                    RSAPublicKey asd = new RSAPublicKey { Exp = rps.Exponent, Mod = rps.Modulus };
                    var key = new RSAParameters { Modulus = m.Mod, Exponent = m.Exp };
                    HandshakeMessage handshake = new HandshakeMessage { AesKey = aes.Key };
                    byte[] broadcastBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(handshake));
                    SendBytesToEncrypted(clientSocket, broadcastBytes, key);

                    Console.WriteLine(m.Name + " has join the chat room ");
                    var client = (m.Name, clientSocket, key);
                    clients.Add(client);
                    Broadcast($"{m.Name} Connected ");
                    Thread ctThread = new Thread(() => DoChat(client));
                    ctThread.Start();
                }
            } while (Console.ReadKey(true).Key != ConsoleKey.Escape);

            serverSocket.Stop();
            Console.WriteLine("exit");
        }
        public static void BroadcastWithName(string msg, string uName)
        {
            Broadcast(uName + " says : " + msg);
        }
        public static void SendMessageTo(TcpClient client, byte[] broadcastBytes)
        {
            Send(client, broadcastBytes);
        }
        public static void SendMessageTo(TcpClient client, ChatMessage m)
        {
            byte[] broadcastBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(m));
            SendMessageTo(client, broadcastBytes);
        }
        public static void SendBytesToEncrypted(TcpClient client, byte[] broadcastBytes, RSAParameters key)
        {
            byte[] encryptedData = EncryptMessage(broadcastBytes, key);
            Send(client, encryptedData);
        }
        public static void SendMessageToEncrypted(TcpClient client, ChatMessage m, RSAParameters key)
        {
            byte[] broadcastBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(m));
            byte[] encryptedData = EncryptMessage(broadcastBytes, key);
            Send(client, encryptedData);
        }
        public static void Broadcast(ChatMessage broadcastMessage)
        {
            var deadConnections = new List<(string, TcpClient, RSAParameters)>();
            foreach ((string, TcpClient, RSAParameters) client in clients)
            {
                TcpClient broadcastSocket = client.Item2;
                if (broadcastSocket.Connected)
                {
                    SendMessageToEncrypted(broadcastSocket, broadcastMessage, client.Item3);
                }
                else
                {
                    deadConnections.Add(client);
                }
            }
            foreach (var deadClient in deadConnections)
            {
                clients.Remove(deadClient);
            }
        }
        public static void Broadcast(string msg = "", string name = "")
        {
            ChatMessage messageToBroadcast = new ChatMessage { Message = msg};
            Broadcast(messageToBroadcast);
        }
        public static void ReadChatters(List<(string, TcpClient, RSAParameters)> clients)
        {
            int i = 0;
            while (true)
            {
                string name = clients[i].Item1;
                var client = clients[i].Item2;
                if (client.Available > 0)
                {
                    byte[] bytesFrom = ReadFromTcp(client, 245);

                    string dataFromClient = Encoding.UTF8.GetString(rsa.Decrypt(bytesFrom, false));
                    ChatMessage m = JsonSerializer.Deserialize<ChatMessage>(dataFromClient);

                    Console.WriteLine($"From {name}: {m.Message}");

                    BroadcastWithName(m.Message, name);
                }
                else if (!client.Connected)
                {
                    clients.Remove(clients[i]);
                    BroadcastWithName($"goodbye {name}", "server");
                }

                i = (i + 1) % clients.Count;
            }
        }
        static byte[] ReadFromTcp(TcpClient client, int max_len)
        {
            byte[] bytesFrom = new byte[max_len];
            NetworkStream networkStream = client.GetStream();

            int bytes_read = networkStream.Read(bytesFrom, 0, bytesFrom.Length);
            Console.WriteLine($"client.connected: {client.Connected}, bytes_read: {bytes_read}");

            Array.Resize(ref bytesFrom, bytes_read);
            return bytesFrom;
        }
        public static void DoChat((string, TcpClient, RSAParameters) clientT)
        {
            string name = clientT.Item1;
            TcpClient client = clientT.Item2;
            int requestCount = 0;
            while (client.Connected) 
            {
                requestCount++;
                byte[] bytesFrom = ReadFromTcp(client, 245);

                string dataFromClient = Encoding.UTF8.GetString(rsa.Decrypt(bytesFrom, false));
                ChatMessage m = JsonSerializer.Deserialize<ChatMessage>(dataFromClient);

                Console.WriteLine($"From {name}: {m.Message}");

                BroadcastWithName(m.Message, name);
            }
            clients.Remove(clientT);
            Broadcast("goodbye " + name);
        }
    }
}