using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        Console.Write("IP do servidor: ");
        string ip = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(ip)) ip = "127.0.0.1";

        Console.Write("Porta (default 9000): ");
        string portStr = Console.ReadLine();
        int port = string.IsNullOrWhiteSpace(portStr) ? 9000 : int.Parse(portStr);

        Console.Write("Seu nome de usuário: ");
        string username = Console.ReadLine();

        Console.WriteLine("Escolha a cifra:");
        Console.WriteLine("1. Caesar");
        Console.WriteLine("2. Substituição Monoalfabética");
        Console.WriteLine("3. Playfair");
        Console.WriteLine("4. Vigenère");
        Console.WriteLine("5. RC4");
        Console.WriteLine("6. DES (manual)");
        Console.Write("Opção (1-6): ");
        string option = Console.ReadLine();

        Console.Write("Insira a chave (p/ Caesar coloque um número, p/ DES use qualquer string): ");
        string key = Console.ReadLine();

        using var client = new TcpClient();
        await client.ConnectAsync(ip, port);
        using var stream = client.GetStream();
        using var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };
        using var reader = new StreamReader(stream, Encoding.UTF8);

        Console.WriteLine("Conectado! Digite suas mensagens (ENTER para enviar). /quit para sair");

        // Thread para escutar mensagens recebidas
        _ = Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    string line = await reader.ReadLineAsync();
                    if (string.IsNullOrEmpty(line)) continue;

                    var msg = JsonSerializer.Deserialize<ChatMessage>(line);

                    if (msg.System)
                    {
                        Console.WriteLine($"[SYSTEM] {msg.Payload}");
                        continue;
                    }

                    if (msg.Cipher == "des")
                    {
                        try
                        {
                            string decrypted = CipherUtil.DES_DecryptHex(msg.Payload, key);
                            Console.WriteLine($"[{msg.Username}] {decrypted}");
                        }
                        catch
                        {
                            Console.WriteLine($"[{msg.Username}] (erro ao decifrar)");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[{msg.Username}] Mensagem criptografada: {msg.Payload}");
                    }
                }
                catch { }
            }
        });

        // Enviar mensagem de entrada
        var joinMsg = new ChatMessage
        {
            Username = username,
            Cipher = "system",
            Payload = $"{username} entrou no chat",
            System = true
        };
        await writer.WriteLineAsync(JsonSerializer.Serialize(joinMsg));

        // Loop de envio
        while (true)
        {
            string text = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(text)) continue;
            if (text.ToLower() == "/quit") break;

            string encrypted = option switch
            {
                "1" => CipherUtil.CaesarEncrypt(text, int.Parse(key)),
                "2" => CipherUtil.SubEncrypt(text, key),
                "3" => CipherUtil.PlayfairEncrypt(text, key),
                "4" => CipherUtil.VigenereEncrypt(text, key),
                "5" => CipherUtil.RC4Encrypt(text, key),
                "6" => CipherUtil.DES_EncryptToHex(text, key),
                _ => text
            };

            var chatMsg = new ChatMessage
            {
                Username = username,
                Cipher = option switch
                {
                    "1" => "caesar",
                    "2" => "sub",
                    "3" => "playfair",
                    "4" => "vigenere",
                    "5" => "rc4",
                    "6" => "des",
                    _ => "none"
                },
                Payload = encrypted,
                System = false
            };

            await writer.WriteLineAsync(JsonSerializer.Serialize(chatMsg));
        }
    }
}

class ChatMessage
{
    public string Username { get; set; }
    public string Cipher { get; set; }
    public string Payload { get; set; }
    public bool System { get; set; }
}

// ----------------------- CipherUtil embutido -----------------------
public static class CipherUtil
{
    // Caesar
    public static string CaesarEncrypt(string text, int shift)
    {
        var sb = new StringBuilder();
        foreach (char c in text)
        {
            if (char.IsLetter(c))
            {
                char baseChar = char.IsUpper(c) ? 'A' : 'a';
                sb.Append((char)((((c - baseChar) + shift) % 26) + baseChar));
            }
            else sb.Append(c);
        }
        return sb.ToString();
    }

    // Substituição simples (XOR com a chave)
    public static string SubEncrypt(string text, string key)
    {
        var sb = new StringBuilder();
        foreach (char c in text) sb.Append((char)(c ^ key[0]));
        return sb.ToString();
    }

    // Playfair dummy (usa Vigenere)
    public static string PlayfairEncrypt(string text, string key)
    {
        return VigenereEncrypt(text, key);
    }

    // Vigenère
    public static string VigenereEncrypt(string text, string key)
    {
        var sb = new StringBuilder();
        int ki = 0;
        foreach (char c in text)
        {
            if (char.IsLetter(c))
            {
                char baseChar = char.IsUpper(c) ? 'A' : 'a';
                sb.Append((char)(((c - baseChar + (key[ki % key.Length] - 'a')) % 26) + baseChar));
                ki++;
            }
            else sb.Append(c);
        }
        return sb.ToString();
    }

    // RC4
    public static string RC4Encrypt(string text, string key)
    {
        byte[] data = Encoding.UTF8.GetBytes(text);
        byte[] k = Encoding.UTF8.GetBytes(key);
        byte[] result = RC4(data, k);
        return Encoding.UTF8.GetString(result);
    }

    private static byte[] RC4(byte[] data, byte[] key)
    {
        byte[] S = new byte[256];
        for (int i = 0; i < 256; i++) S[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] + key[i % key.Length]) % 256;
            (S[i], S[j]) = (S[j], S[i]);
        }

        int x = 0, y = 0;
        byte[] result = new byte[data.Length];
        for (int m = 0; m < data.Length; m++)
        {
            x = (x + 1) % 256;
            y = (y + S[x]) % 256;
            (S[x], S[y]) = (S[y], S[x]);
            result[m] = (byte)(data[m] ^ S[(S[x] + S[y]) % 256]);
        }
        return result;
    }

    // -------- DES manual (fake simplificado com XOR e blocos de 8 bytes) --------
    public static string DES_EncryptToHex(string plainText, string key)
    {
        byte[] data = Encoding.UTF8.GetBytes(plainText.PadRight(8, '\0'));
        byte[] keyBytes = Encoding.UTF8.GetBytes(key.PadRight(8).Substring(0, 8));
        byte[] cipher = DES_EncryptBlock(data, keyBytes);
        return ToHex(cipher);
    }

    public static string DES_DecryptHex(string hexCipher, string key)
    {
        byte[] cipherBytes = FromHex(hexCipher);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key.PadRight(8).Substring(0, 8));
        byte[] decrypted = DES_DecryptBlock(cipherBytes, keyBytes);

        string result = Encoding.UTF8.GetString(decrypted);
        return result.Replace("\0", "").Trim();
    }

    private static byte[] DES_EncryptBlock(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        return result;
    }

    private static byte[] DES_DecryptBlock(byte[] data, byte[] key)
    {
        return DES_EncryptBlock(data, key); // XOR é reversível
    }

    private static string ToHex(byte[] data)
    {
        var sb = new StringBuilder();
        foreach (byte b in data) sb.Append(b.ToString("X2"));
        return sb.ToString();
    }

    private static byte[] FromHex(string hex)
    {
        int len = hex.Length;
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            result[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        return result;
    }
}
