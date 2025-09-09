// Program.cs (ChatServer)
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    static ConcurrentDictionary<TcpClient, ClientInfo> clients = new();

    static async Task Main(string[] args)
    {
        int port = 9000;
        var listener = new TcpListener(IPAddress.Any, port);
        listener.Start();
        Console.WriteLine($"[SERVER] Escutando na porta {port}...");

        while (true)
        {
            var tcp = await listener.AcceptTcpClientAsync();
            _ = Task.Run(() => HandleClient(tcp));
        }
    }

    static async Task HandleClient(TcpClient tcp)
    {
        var stream = tcp.GetStream();
        var reader = new StreamReader(stream, Encoding.UTF8);
        var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

        // Espera handshake inicial (JSON)
        try
        {
            string line = await reader.ReadLineAsync();
            if (line == null) { tcp.Close(); return; }

            var handshake = JsonSerializer.Deserialize<Message>(line);
            if (handshake == null || handshake.Type != "handshake")
            {
                await writer.WriteLineAsync(JsonSerializer.Serialize(new { type = "error", message = "handshake esperado" }));
                tcp.Close();
                return;
            }

            var info = new ClientInfo
            {
                Tcp = tcp,
                Username = handshake.Username ?? "Anon",
                Cipher = handshake.Cipher ?? "caesar",
                Key = handshake.Key ?? ""
            };

            clients.TryAdd(tcp, info);
            Console.WriteLine($"[CONNECT] {info.Username} conectado. Cifra={info.Cipher} Key={info.Key}");

            // Notifica conexão
            await BroadcastSystemMessage($"{info.Username} entrou no chat.", tcp);

            // Lê mensagens
            while (true)
            {
                string msgLine = await reader.ReadLineAsync();
                if (msgLine == null) break;

                var msg = JsonSerializer.Deserialize<Message>(msgLine);
                if (msg == null) continue;

                if (msg.Type == "message")
                {
                    // Log: descriptografa usando as configurações do remetente para depuração
                    string decryptedForLog = CipherUtil.Decrypt(msg.Payload, info.Cipher, info.Key);
                    Console.WriteLine($"[MSG] De: {info.Username} (cifra={info.Cipher}) -> Encrypted: {msg.Payload}");
                    Console.WriteLine($"      Decrypted (server-log): {decryptedForLog}");

                    // Repassa para outros clients (mantém o JSON recebido)
                    await BroadcastRaw(msgLine, except: tcp);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] {ex.Message}");
        }
        finally
        {
            if (clients.TryRemove(tcp, out var removed))
            {
                Console.WriteLine($"[DISCONNECT] {removed.Username} desconectou.");
                _ = BroadcastSystemMessage($"{removed.Username} saiu do chat.", null);
            }
            tcp.Close();
        }
    }

    static async Task BroadcastRaw(string jsonLine, TcpClient except)
    {
        foreach (var kv in clients)
        {
            var client = kv.Key;
            if (client == except) continue;
            try
            {
                var w = new StreamWriter(client.GetStream(), Encoding.UTF8) { AutoFlush = true };
                await w.WriteLineAsync(jsonLine);
            }
            catch { /* ignore */ }
        }
    }

    static async Task BroadcastSystemMessage(string text, TcpClient except)
    {
        var msg = new Message { Type = "system", Payload = text };
        string json = JsonSerializer.Serialize(msg);
        await BroadcastRaw(json, except);
    }
}

record Message
{
    public string Type { get; init; } = "message";
    public string Username { get; init; }
    public string Cipher { get; init; }
    public string Key { get; init; }
    public string Payload { get; init; }
}

class ClientInfo
{
    public TcpClient Tcp { get; set; }
    public string Username { get; set; }
    public string Cipher { get; set; }
    public string Key { get; set; }
}

/*
 * CipherUtil: contém wrappers para as cifras.
 * Copie/cole a definição abaixo em um arquivo CipherUtil.cs ou adicione aqui mesmo.
 */
static class CipherUtil
{
    public static string Encrypt(string plain, string cipher, string key)
    {
        cipher = (cipher ?? "").ToLowerInvariant();
        return cipher switch
        {
            "caesar" => Caesar.Encrypt(plain, ParseIntKey(key, 3)),
            "vigenere" => Vigenere.Encrypt(plain, key ?? ""),
            "mono" or "monoalpha" or "monoalfabetica" => Monoalphabetic.Encrypt(plain, key ?? ""),
            "playfair" => Playfair.Encrypt(plain, key ?? ""),
            _ => plain
        };
    }

    public static string Decrypt(string cipherText, string cipher, string key)
    {
        cipher = (cipher ?? "").ToLowerInvariant();
        return cipher switch
        {
            "caesar" => Caesar.Decrypt(cipherText, ParseIntKey(key, 3)),
            "vigenere" => Vigenere.Decrypt(cipherText, key ?? ""),
            "mono" or "monoalpha" or "monoalfabetica" => Monoalphabetic.Decrypt(cipherText, key ?? ""),
            "playfair" => Playfair.Decrypt(cipherText, key ?? ""),
            _ => cipherText
        };
    }

    static int ParseIntKey(string key, int @default)
    {
        if (int.TryParse(key, out int k)) return k % 26;
        return @default;
    }

    // ---------------- Caesar ----------------
    public static class Caesar
    {
        public static string Encrypt(string text, int shift)
        {
            shift = ((shift % 26) + 26) % 26;
            var sb = new System.Text.StringBuilder();
            foreach (char c in text)
            {
                if (char.IsLetter(c))
                {
                    char baseC = char.IsUpper(c) ? 'A' : 'a';
                    sb.Append((char)(baseC + (c - baseC + shift) % 26));
                }
                else sb.Append(c);
            }
            return sb.ToString();
        }
        public static string Decrypt(string text, int shift) => Encrypt(text, 26 - (shift % 26));
    }

    // ---------------- Vigenere ----------------
    public static class Vigenere
    {
        static string NormalizeKey(string key)
        {
            var s = new System.Text.StringBuilder();
            foreach (var ch in key.ToLowerInvariant())
                if (char.IsLetter(ch)) s.Append(ch);
            return s.Length == 0 ? "a" : s.ToString();
        }
        public static string Encrypt(string text, string key)
        {
            key = NormalizeKey(key);
            var sb = new System.Text.StringBuilder();
            int j = 0;
            foreach (char c in text)
            {
                if (char.IsLetter(c))
                {
                    char baseC = char.IsUpper(c) ? 'A' : 'a';
                    int shift = key[j % key.Length] - 'a';
                    sb.Append((char)(baseC + (c - baseC + shift) % 26));
                    j++;
                }
                else sb.Append(c);
            }
            return sb.ToString();
        }
        public static string Decrypt(string text, string key)
        {
            key = NormalizeKey(key);
            var sb = new System.Text.StringBuilder();
            int j = 0;
            foreach (char c in text)
            {
                if (char.IsLetter(c))
                {
                    char baseC = char.IsUpper(c) ? 'A' : 'a';
                    int shift = key[j % key.Length] - 'a';
                    sb.Append((char)(baseC + (c - baseC - shift + 26) % 26));
                    j++;
                }
                else sb.Append(c);
            }
            return sb.ToString();
        }
    }

    // ---------------- Monoalphabetic ----------------
    public static class Monoalphabetic
    {
        public static string Encrypt(string text, string key)
        {
            key = key?.ToUpperInvariant() ?? "";
            if (key.Length != 26) return text;
            var map = new char[26];
            for (int i = 0; i < 26; i++) map[i] = key[i];
            var sb = new System.Text.StringBuilder();
            foreach (char c in text)
            {
                if (char.IsUpper(c)) sb.Append(map[c - 'A']);
                else if (char.IsLower(c)) sb.Append(char.ToLower(map[c - 'a']));
                else sb.Append(c);
            }
            return sb.ToString();
        }

        public static string Decrypt(string text, string key)
        {
            key = key?.ToUpperInvariant() ?? "";
            if (key.Length != 26) return text;
            var rev = new char[26];
            for (int i = 0; i < 26; i++)
                rev[key[i] - 'A'] = (char)('A' + i);
            var sb = new System.Text.StringBuilder();
            foreach (char c in text)
            {
                if (char.IsUpper(c)) sb.Append(rev[c - 'A']);
                else if (char.IsLower(c)) sb.Append(char.ToLower(rev[c - 'a']));
                else sb.Append(c);
            }
            return sb.ToString();
        }
    }

    // ---------------- Playfair ----------------
    public static class Playfair
    {
        static char[,] BuildMatrix(string key)
        {
            key = (key ?? "").ToUpperInvariant().Replace('J', 'I');
            var used = new bool[26];
            var mat = new char[5, 5];
            int r = 0, c = 0;
            foreach (char ch in key)
            {
                if (!char.IsLetter(ch)) continue;
                int idx = ch - 'A';
                if (idx == ('J' - 'A')) idx = ('I' - 'A'); // treat J as I
                if (!used[idx])
                {
                    used[idx] = true;
                    mat[r, c] = (char)('A' + idx);
                    c++; if (c == 5) { c = 0; r++; }
                }
            }
            for (char ch = 'A'; ch <= 'Z'; ch++)
            {
                if (ch == 'J') continue;
                int idx = ch - 'A';
                if (!used[idx])
                {
                    used[idx] = true;
                    mat[r, c] = ch;
                    c++; if (c == 5) { c = 0; r++; }
                }
            }
            return mat;
        }

        static (int row, int col) Find(char[,] mat, char ch)
        {
            ch = (ch == 'J') ? 'I' : ch;
            for (int i = 0; i < 5; i++) for (int j = 0; j < 5; j++) if (mat[i, j] == ch) return (i, j);
            throw new Exception("Char not in matrix: " + ch);
        }

        static string PreparePlain(string input)
        {
            var sb = new System.Text.StringBuilder();
            foreach (char ch in input.ToUpperInvariant())
            {
                if (char.IsLetter(ch))
                    sb.Append(ch == 'J' ? 'I' : ch);
            }
            var res = new System.Text.StringBuilder();
            for (int i = 0; i < sb.Length; i++)
            {
                char a = sb[i];
                char b = (i + 1 < sb.Length) ? sb[i + 1] : '\0';
                if (b == '\0')
                {
                    res.Append(a);
                    res.Append('X');
                }
                else
                {
                    if (a == b)
                    {
                        res.Append(a);
                        res.Append('X');
                    }
                    else
                    {
                        res.Append(a);
                        res.Append(b);
                        i++;
                    }
                }
            }
            return res.ToString();
        }

        public static string Encrypt(string plain, string key)
        {
            var mat = BuildMatrix(key);
            string prepared = PreparePlain(plain);
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < prepared.Length; i += 2)
            {
                char a = prepared[i], b = prepared[i + 1];
                var pa = Find(mat, a);
                var pb = Find(mat, b);
                if (pa.row == pb.row)
                {
                    sb.Append(mat[pa.row, (pa.col + 1) % 5]);
                    sb.Append(mat[pb.row, (pb.col + 1) % 5]);
                }
                else if (pa.col == pb.col)
                {
                    sb.Append(mat[(pa.row + 1) % 5, pa.col]);
                    sb.Append(mat[(pb.row + 1) % 5, pb.col]);
                }
                else
                {
                    sb.Append(mat[pa.row, pb.col]);
                    sb.Append(mat[pb.row, pa.col]);
                }
            }
            // Preserve spacing/punctuation by returning pairs only for letters.
            // To keep it simple, we'll return uppercase cipher pairs and ignore non-letters.
            return sb.ToString();
        }

        public static string Decrypt(string cipher, string key)
        {
            var mat = BuildMatrix(key);
            cipher = new string((cipher ?? "").ToUpperInvariant().ToCharArray());
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i + 1 < cipher.Length; i += 2)
            {
                char a = cipher[i], b = cipher[i + 1];
                if (!char.IsLetter(a) || !char.IsLetter(b)) continue;
                var pa = Find(mat, a);
                var pb = Find(mat, b);
                if (pa.row == pb.row)
                {
                    sb.Append(mat[pa.row, (pa.col + 4) % 5]);
                    sb.Append(mat[pb.row, (pb.col + 4) % 5]);
                }
                else if (pa.col == pb.col)
                {
                    sb.Append(mat[(pa.row + 4) % 5, pa.col]);
                    sb.Append(mat[(pb.row + 4) % 5, pb.col]);
                }
                else
                {
                    sb.Append(mat[pa.row, pb.col]);
                    sb.Append(mat[pb.row, pa.col]);
                }
            }
            // The decrypted text may contain padding 'X' inserted; leave as-is for server log.
            return sb.ToString();
        }
    }
}
