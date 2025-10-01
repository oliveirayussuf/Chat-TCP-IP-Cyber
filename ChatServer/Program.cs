using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class Program
{
    static ConcurrentDictionary<TcpClient, string> clients = new();

    static async Task Main()
    {
        int port = 9000;
        var listener = new TcpListener(IPAddress.Any, port);
        listener.Start();
        Console.WriteLine($"Servidor rodando na porta {port}...");

        while (true)
        {
            var client = await listener.AcceptTcpClientAsync();
            _ = HandleClient(client);
        }
    }

    static async Task HandleClient(TcpClient client)
    {
        clients[client] = "";

        using var stream = client.GetStream();
        using var reader = new StreamReader(stream, new UTF8Encoding(false));
        // Não precisa criar writer aqui para o cliente atual (broadcast faz isso)
        try
        {
            while (true)
            {
                string line = await reader.ReadLineAsync();
                if (line == null) break;

                // Só encaminha a linha JSON para todos e também imprime uma linha pra debug
                // imprime baseado no conteúdo JSON
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    bool system = root.TryGetProperty("System", out var sys) && sys.GetBoolean();
                    string username = root.TryGetProperty("Username", out var u) ? u.GetString() ?? "Anon" : "Anon";
                    string cipher = root.TryGetProperty("Cipher", out var c) ? c.GetString() ?? "" : "";
                    string payload = root.TryGetProperty("Payload", out var p) ? p.GetString() ?? "" : "";

                    if (system)
                    {
                        clients[client] = username;
                        Console.WriteLine($"[SYSTEM] {payload}");
                    }
                    else
                    {
                        if (cipher.Equals("des", StringComparison.OrdinalIgnoreCase))
                            Console.WriteLine($"[{username}] (DES HEX) {payload}");
                        else
                            Console.WriteLine($"[{username}] {payload}");
                    }
                }
                catch
                {
                    Console.WriteLine("[SERVER] recebeu linha não-JSON / parse falhou:");
                    Console.WriteLine(line);
                }

                // Broadcast raw line to all other clients
                foreach (var kv in clients)
                {
                    var c = kv.Key;
                    if (c == client) continue;
                    try
                    {
                        var sw = new StreamWriter(c.GetStream(), new UTF8Encoding(false)) { AutoFlush = true };
                        await sw.WriteLineAsync(line);
                    }
                    catch { /* ignore individual client write errors */ }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[SERVER] erro: " + ex.Message);
        }
        finally
        {
            clients.TryRemove(client, out _);
            client.Close();
        }
    }
}
