// Program.cs (ChatClient com DES completo manual)
using System;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

class Program
{
    static void Main()
    {
        Console.Write("IP do servidor: ");
        string ip = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(ip)) ip = "127.0.0.1";

        TcpClient client = new();
        client.Connect(ip, 9000);
        Console.WriteLine("Conectado ao servidor.");

        Console.Write("Digite a chave DES (8 caracteres): ");
        string keyText = Console.ReadLine();
        if (keyText.Length != 8) throw new Exception("Chave DES deve ter 8 caracteres.");
        byte[] key = Encoding.ASCII.GetBytes(keyText);

        Task.Run(() => ReceiveMessages(client, key));

        while (true)
        {
            string message = Console.ReadLine();
            if (string.IsNullOrEmpty(message)) continue;

            byte[] encrypted = DES.Encrypt(Encoding.ASCII.GetBytes(message), key);
            client.GetStream().Write(encrypted, 0, encrypted.Length);
        }
    }

    static void ReceiveMessages(TcpClient client, byte[] key)
    {
        var stream = client.GetStream();
        byte[] buffer = new byte[1024];

        while (true)
        {
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0) break;

            byte[] received = new byte[bytesRead];
            Array.Copy(buffer, received, bytesRead);

            string decrypted = Encoding.ASCII.GetString(DES.Decrypt(received, key));
            Console.WriteLine($"Mensagem recebida: {decrypted}");
        }
    }
}


static class DES
{
    // Tabelas DES (IP, FP, PC1, PC2, E, P, S-boxes)
    private static readonly int[] IP = {
        58,50,42,34,26,18,10,2,
        60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,
        64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,
        59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,
        63,55,47,39,31,23,15,7
    };

    private static readonly int[] FP = new int[64]
    {
        40,8,48,16,56,24,64,32,
        39,7,47,15,55,23,63,31,
        38,6,46,14,54,22,62,30,
        37,5,45,13,53,21,61,29,
        36,4,44,12,52,20,60,28,
        35,3,43,11,51,19,59,27,
        34,2,42,10,50,18,58,26,
        33,1,41,9,49,17,57,25
    };

    private static readonly int[] PC1 = {
        57,49,41,33,25,17,9,
        1,58,50,42,34,26,18,
        10,2,59,51,43,35,27,
        19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,
        7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,
        21,13,5,28,20,12,4
    };

    private static readonly int[] PC2 = {
        14,17,11,24,1,5,
        3,28,15,6,21,10,
        23,19,12,4,26,8,
        16,7,27,20,13,2,
        41,52,31,37,47,55,
        30,40,51,45,33,48,
        44,49,39,56,34,53,
        46,42,50,36,29,32
    };

    private static readonly int[] E = {
        32,1,2,3,4,5,
        4,5,6,7,8,9,
        8,9,10,11,12,13,
        12,13,14,15,16,17,
        16,17,18,19,20,21,
        20,21,22,23,24,25,
        24,25,26,27,28,29,
        28,29,30,31,32,1
    };

    private static readonly int[] P = {
        16,7,20,21,
        29,12,28,17,
        1,15,23,26,
        5,18,31,10,
        2,8,24,14,
        32,27,3,9,
        19,13,30,6,
        22,11,4,25
    };

    private static readonly int[,] SBOX = new int[8, 64] {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
         0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
         4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
         15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
         3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
         0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
         13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
         13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
         13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
         1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
         13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
         10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
         3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
         14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
         4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,
         11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
         10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
         9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
         4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
         13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
         1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
         6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
         1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
         7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
         2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    };

    private static readonly int[] Rotations = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

    // ---------------- Permutação de bits ----------------
    private static bool[] Permute(bool[] input, int[] table)
    {
        bool[] output = new bool[table.Length];
        for (int i = 0; i < table.Length; i++)
            output[i] = input[table[i] - 1];
        return output;
    }

    private static bool[] StringToBits(byte[] data)
    {
        bool[] bits = new bool[data.Length * 8];
        for (int i = 0; i < data.Length; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                bits[i * 8 + j] = (data[i] & (1 << (7 - j))) != 0;
            }
        }
        return bits;
    }

    private static byte[] BitsToBytes(bool[] bits)
    {
        byte[] data = new byte[bits.Length / 8];
        for (int i = 0; i < data.Length; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                if (bits[i * 8 + j]) data[i] |= (byte)(1 << (7 - j));
            }
        }
        return data;
    }

    // ---------------- Geração de subchaves ----------------
    private static bool[][] GenerateSubkeys(byte[] key)
    {
        bool[] keyBits = StringToBits(key);
        bool[] permuted = Permute(keyBits, PC1);
        bool[] C = new bool[28];
        bool[] D = new bool[28];
        Array.Copy(permuted, 0, C, 0, 28);
        Array.Copy(permuted, 28, D, 0, 28);

        bool[][] subkeys = new bool[16][];
        for (int i = 0; i < 16; i++)
        {
            C = RotateLeft(C, Rotations[i]);
            D = RotateLeft(D, Rotations[i]);
            bool[] CD = new bool[56];
            Array.Copy(C, 0, CD, 0, 28);
            Array.Copy(D, 0, CD, 28, 28);
            subkeys[i] = Permute(CD, PC2);
        }
        return subkeys;
    }

    private static bool[] RotateLeft(bool[] bits, int n)
    {
        bool[] res = new bool[bits.Length];
        for (int i = 0; i < bits.Length; i++)
            res[i] = bits[(i + n) % bits.Length];
        return res;
    }

    // ---------------- Função Feistel ----------------
    private static bool[] Feistel(bool[] R, bool[] K)
    {
        bool[] ER = Permute(R, E);
        for (int i = 0; i < 48; i++) ER[i] ^= K[i];

        bool[] output = new bool[32];
        for (int i = 0; i < 8; i++)
        {
            int row = (ER[i * 6] ? 2 : 0) + (ER[i * 6 + 5] ? 1 : 0);
            int col = 0;
            for (int j = 1; j <= 4; j++)
                if (ER[i * 6 + j]) col += 1 << (4 - j);
            int val = SBOX[i, row * 16 + col];
            for (int j = 0; j < 4; j++)
                output[i * 4 + j] = (val & (1 << (3 - j))) != 0;
        }

        return Permute(output, P);
    }

    // ---------------- Processamento de blocos ----------------
    private static byte[] ProcessBlock(byte[] block, bool[][] subkeys, bool encrypt)
    {
        bool[] bits = StringToBits(block);
        bits = Permute(bits, IP);
        bool[] L = new bool[32];
        bool[] R = new bool[32];
        Array.Copy(bits, 0, L, 0, 32);
        Array.Copy(bits, 32, R, 0, 32);

        for (int i = 0; i < 16; i++)
        {
            bool[] temp = R;
            bool[] f = Feistel(R, encrypt ? subkeys[i] : subkeys[15 - i]);
            R = new bool[32];
            for (int j = 0; j < 32; j++)
                R[j] = L[j] ^ f[j];
            L = temp;
        }

        bool[] combined = new bool[64];
        Array.Copy(R, 0, combined, 0, 32);
        Array.Copy(L, 0, combined, 32, 32);
        combined = Permute(combined, FP);

        return BitsToBytes(combined);
    }

    // ---------------- Criptografar/Descriptografar ----------------
    public static byte[] Encrypt(byte[] data, byte[] key)
    {
        bool[][] subkeys = GenerateSubkeys(key);
        byte[] padded = Pad(data);
        byte[] result = new byte[padded.Length];

        for (int i = 0; i < padded.Length; i += 8)
        {
            byte[] block = new byte[8];
            Array.Copy(padded, i, block, 0, 8);
            byte[] encrypted = ProcessBlock(block, subkeys, true);
            Array.Copy(encrypted, 0, result, i, 8);
        }
        return result;
    }

    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        bool[][] subkeys = GenerateSubkeys(key);
        byte[] result = new byte[data.Length];

        for (int i = 0; i < data.Length; i += 8)
        {
            byte[] block = new byte[8];
            Array.Copy(data, i, block, 0, 8);
            byte[] decrypted = ProcessBlock(block, subkeys, false);
            Array.Copy(decrypted, 0, result, i, 8);
        }
        return result;
    }

    private static byte[] Pad(byte[] data)
    {
        int length = ((data.Length + 7) / 8) * 8;
        byte[] padded = new byte[length];
        Array.Copy(data, padded, data.Length);
        return padded;
    }
}
