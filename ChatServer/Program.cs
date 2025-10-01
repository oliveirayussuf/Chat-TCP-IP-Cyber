// Program.cs (ChatServer)
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

class Program
{
    static ConcurrentDictionary<TcpClient, string> clients = new();

    static void Main()
    {
        TcpListener server = new(IPAddress.Any, 9000);
        server.Start();
        Console.WriteLine("Servidor iniciado na porta 9000.");

        Task.Run(async () =>
        {
            while (true)
            {
                TcpClient client = await server.AcceptTcpClientAsync();
                Console.WriteLine("Novo cliente conectado.");
                clients.TryAdd(client, "");

                Task.Run(() => HandleClient(client));
            }
        });

        Console.ReadLine();
    }

    static void HandleClient(TcpClient client)
    {
        var stream = client.GetStream();
        byte[] buffer = new byte[1024];

        try
        {
            while (true)
            {
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0) break;

                byte[] received = new byte[bytesRead];
                Array.Copy(buffer, received, bytesRead);

                // Mostra a mensagem criptografada em ASCII/hex
                string hex = BitConverter.ToString(received).Replace("-", " ");
                Console.WriteLine($"Mensagem criptografada recebida (hex): {hex}");

                // Retransmite para outros clients
                foreach (var c in clients.Keys)
                {
                    if (c != client)
                    {
                        c.GetStream().Write(received, 0, received.Length);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erro no client: " + ex.Message);
        }
        finally
        {
            clients.TryRemove(client, out _);
            client.Close();
            Console.WriteLine("Cliente desconectado.");
        }
    }
}
