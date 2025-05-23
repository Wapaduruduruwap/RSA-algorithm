using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;

// Статический класс верхнего уровня для методов расширения
public static class BigIntExtensions
{
    public static int BitLength(this BigInt value)
    {
        if (value.IsZero())
            return 1;

        int bitLength = 0;
        BigInt temp = value.Abs();
        while (temp > BigInt.Zero)
        {
            bitLength++;
            temp = temp / BigInt.Two;
        }
        return bitLength;
    }

    public static int ByteLength(this BigInt value)
    {
        return (BitLength(value) + 7) / 8;
    }

    public static BigInt Abs(this BigInt value)
    {
        return value < BigInt.Zero ? -value : value;
    }

    public static bool IsEven(this BigInt value)
    {
        return value % BigInt.Two == BigInt.Zero;
    }

    public static BigInt Gcd(this BigInt a, BigInt b)
    {
        while (b != BigInt.Zero)
        {
            BigInt temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }
}

public class RSA
{
    private readonly BigInt p;
    private readonly BigInt q;
    private readonly BigInt n;
    private readonly BigInt phi;
    private readonly BigInt e;
    private readonly BigInt d;

    private const int PKCS1_PADDING_SIZE = 11; // Minimum padding size for PKCS#1 v1.5

    // Добавляем статические поля для часто используемых констант
    private static readonly BigInt Four = new BigInt(4);

    public RSA(int bits = 2048)
    {
        if (bits < 1024)
            throw new ArgumentException("Key size must be at least 1024 bits for security");

        Console.WriteLine($"Generating RSA keys with {bits}-bit modulus...");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        
        // Генерируем p и q разного размера для дополнительной безопасности
        int pBits = bits / 2;
        int qBits = bits / 2;
        
        p = GenerateProbablePrime(pBits);
        Console.WriteLine($"Generated p ({pBits} bits) in {sw.ElapsedMilliseconds}ms");
        
        do {
            q = GenerateProbablePrime(qBits);
        } while ((p - q).Abs().BitLength() < bits / 3); // Убеждаемся, что p и q достаточно различны
        
        Console.WriteLine($"Generated q ({qBits} bits) in {sw.ElapsedMilliseconds}ms");
        
        n = p * q;
        phi = (p - BigInt.One) * (q - BigInt.One);
        
        // Используем стандартное значение открытого экспонента
        e = new BigInt(65537);
        
        // Проверяем, что e и phi взаимно просты
        if (phi.Gcd(e) != BigInt.One)
        {
            throw new CryptographicException("Failed to generate valid RSA parameters: e and phi are not coprime");
        }
        
        d = e.ModInverse(phi);
        
        // Проверяем корректность сгенерированных ключей
        ValidateKeyPair();
        
        Console.WriteLine($"Key generation completed in {sw.ElapsedMilliseconds}ms");
    }

    public BigInt Encrypt(BigInt message)
    {
        if (message.CompareTo(n) >= 0)
            throw new ArgumentException("Message must be less than modulus");
        return message.ModPow(e, n);
    }

    public BigInt Decrypt(BigInt ciphertext)
    {
        if (ciphertext.CompareTo(n) >= 0)
            throw new ArgumentException("Ciphertext must be less than modulus");
        return ciphertext.ModPow(d, n);
    }

    private byte[] AddPKCS1Padding(byte[] data, int blockSize)
    {
        // PKCS#1 v1.5 padding format: 0x00 || 0x02 || PS || 0x00 || D
        // where PS is random non-zero bytes
        int paddingLength = blockSize - data.Length - 3; // 3 = 0x00 + 0x02 + ending 0x00
        if (paddingLength < 8)
            throw new ArgumentException("Data too long for RSA block size");

        byte[] padded = new byte[blockSize];
        padded[0] = 0x00;
        padded[1] = 0x02;

        // Generate random non-zero padding bytes
        using (var rng = RandomNumberGenerator.Create())
        {
            byte[] padding = new byte[paddingLength];
            int index = 2;
            while (index < paddingLength + 2)
            {
                rng.GetBytes(padding, 0, 1);
                if (padding[0] != 0)
                {
                    padded[index] = padding[0];
                    index++;
                }
            }
        }

        padded[paddingLength + 2] = 0x00;
        Array.Copy(data, 0, padded, paddingLength + 3, data.Length);

        return padded;
    }

    private byte[] RemovePKCS1Padding(byte[] padded)
    {
        if (padded[0] != 0x00 || padded[1] != 0x02)
            throw new CryptographicException("Invalid PKCS#1 v1.5 padding");

        int dataStart = 2;
        while (dataStart < padded.Length && padded[dataStart] != 0x00)
            dataStart++;

        if (dataStart < 10 || dataStart == padded.Length)
            throw new CryptographicException("Invalid PKCS#1 v1.5 padding");

        dataStart++; // Skip the 0x00 byte
        int dataLength = padded.Length - dataStart;
        byte[] data = new byte[dataLength];
        Array.Copy(padded, dataStart, data, 0, dataLength);
        return data;
    }

    public string EncryptString(string message)
    {
        if (string.IsNullOrEmpty(message))
            return string.Empty;

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        int blockSize = (n.BitLength() - 1) / 8; // Maximum size of data that can be encrypted
        int maxDataSize = blockSize - PKCS1_PADDING_SIZE;

        List<byte> encryptedBlocks = new List<byte>();
        for (int i = 0; i < messageBytes.Length; i += maxDataSize)
        {
            int currentBlockSize = Math.Min(maxDataSize, messageBytes.Length - i);
            byte[] block = new byte[currentBlockSize];
            Array.Copy(messageBytes, i, block, 0, currentBlockSize);

            // Add PKCS#1 v1.5 padding
            byte[] paddedBlock = AddPKCS1Padding(block, blockSize);
            BigInt messageInt = BytesToBigInt(paddedBlock);
            BigInt encrypted = Encrypt(messageInt);
            byte[] encryptedBytes = BigIntToBytes(encrypted);

            // Ensure the encrypted block is exactly blockSize bytes
            if (encryptedBytes.Length < blockSize)
            {
                byte[] paddedEncrypted = new byte[blockSize];
                Array.Copy(encryptedBytes, 0, paddedEncrypted, blockSize - encryptedBytes.Length, encryptedBytes.Length);
                encryptedBytes = paddedEncrypted;
            }

            encryptedBlocks.AddRange(encryptedBytes);
        }

        return Convert.ToBase64String(encryptedBlocks.ToArray());
    }

    public string DecryptString(string ciphertext)
    {
        if (string.IsNullOrEmpty(ciphertext))
            return string.Empty;

        byte[] encryptedBytes = Convert.FromBase64String(ciphertext);
        int blockSize = (n.BitLength() - 1) / 8;

        if (encryptedBytes.Length % blockSize != 0)
            throw new CryptographicException("Invalid ciphertext length");

        List<byte> decryptedData = new List<byte>();
        for (int i = 0; i < encryptedBytes.Length; i += blockSize)
        {
            byte[] block = new byte[blockSize];
            Array.Copy(encryptedBytes, i, block, 0, blockSize);

            BigInt encrypted = BytesToBigInt(block);
            BigInt decrypted = Decrypt(encrypted);
            byte[] decryptedBlock = BigIntToBytes(decrypted);

            // Ensure the decrypted block is properly padded
            if (decryptedBlock.Length < blockSize)
            {
                byte[] paddedDecrypted = new byte[blockSize];
                Array.Copy(decryptedBlock, 0, paddedDecrypted, blockSize - decryptedBlock.Length, decryptedBlock.Length);
                decryptedBlock = paddedDecrypted;
            }

            // Remove PKCS#1 v1.5 padding
            byte[] unpaddedBlock = RemovePKCS1Padding(decryptedBlock);
            decryptedData.AddRange(unpaddedBlock);
        }

        return Encoding.UTF8.GetString(decryptedData.ToArray());
    }

    // Convert byte array to BigInt, handling multi-byte UTF-8 characters
    private BigInt BytesToBigInt(byte[] bytes)
    {
        BigInt result = BigInt.Zero;
        BigInt twoFiveSix = new BigInt(256);
        // Process bytes in big-endian order
        for (int i = 0; i < bytes.Length; i++)
        {
            result = result * twoFiveSix + new BigInt(bytes[i]);
        }
        return result;
    }

    // Convert BigInt to byte array
    private byte[] BigIntToBytes(BigInt num)
    {
        if (num.IsZero())
            return new byte[] { 0 };

        List<byte> bytes = new List<byte>();
        BigInt n = num.Abs(); // Work with absolute value
        BigInt twoFiveSix = new BigInt(256);

        while (n > BigInt.Zero)
        {
            BigInt remainder = n % twoFiveSix;
            byte byteValue = remainder.ToByte();
            bytes.Add(byteValue);
            n = n / twoFiveSix;
        }

        bytes.Reverse();
        return bytes.ToArray();
    }

    public void EncryptFile(string inputFile, string outputFile)
    {
        try
        {
            string content = File.ReadAllText(inputFile, Encoding.UTF8);
            string encrypted = EncryptString(content);
            File.WriteAllText(outputFile, encrypted, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            throw new Exception($"File encryption failed: {ex.Message}");
        }
    }

    public void DecryptFile(string inputFile, string outputFile)
    {
        try
        {
            string encrypted = File.ReadAllText(inputFile, Encoding.UTF8);
            string decrypted = DecryptString(encrypted);
            File.WriteAllText(outputFile, decrypted, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            throw new Exception($"File decryption failed: {ex.Message}");
        }
    }

    public (BigInt e, BigInt n) GetPublicKey() => (e, n);

    public void SavePublicKey(string filename)
    {
        File.WriteAllText(filename, $"{e}\n{n}");
    }

    public static (BigInt e, BigInt n) LoadPublicKey(string filename)
    {
        string[] lines = File.ReadAllLines(filename);
        return (new BigInt(lines[0]), new BigInt(lines[1]));
    }

    private BigInt GenerateProbablePrime(int bits)
    {
        if (bits < 512)
            throw new ArgumentException("Prime size must be at least 512 bits for security");

        using var rng = RandomNumberGenerator.Create();
        int byteLength = bits / 8 + (bits % 8 > 0 ? 1 : 0);
        byte[] bytes = new byte[byteLength];
        BigInt candidate;
        var sw = System.Diagnostics.Stopwatch.StartNew();

        int attempt = 0;
        const int MAX_ATTEMPTS = 10000;
        
        // Предварительно вычисляем маленькие простые числа для решета
        var smallPrimes = new List<int> { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97 };
        BigInt product = BigInt.One;
        foreach (var prime in smallPrimes)
        {
            product = product * new BigInt(prime);
        }
        
        while (attempt < MAX_ATTEMPTS)
        {
            attempt++;
            rng.GetBytes(bytes);
            
            // Устанавливаем старший бит для обеспечения нужной длины
            bytes[0] |= 0x80;
            // Устанавливаем младший бит для обеспечения нечетности
            bytes[byteLength - 1] |= 1;

            candidate = BytesToBigInt(bytes);
            
            // Быстрая проверка делимости на все маленькие простые числа сразу
            if (candidate.Gcd(product) != BigInt.One)
                continue;

            var primeCheckSw = System.Diagnostics.Stopwatch.StartNew();
            
            // Сначала делаем быструю проверку с меньшим количеством раундов
            if (IsProbablePrime(candidate, 3))
            {
                // Если прошла быстрая проверка, делаем полную проверку
                if (IsProbablePrime(candidate, 7))
                {
                    primeCheckSw.Stop();
                    sw.Stop();
                    Console.WriteLine($"Generated prime ({bits} bits) in {sw.ElapsedMilliseconds}ms after {attempt} attempts. Prime check took {primeCheckSw.ElapsedMilliseconds}ms");
                    return candidate;
                }
            }
            
            if (attempt % 1000 == 0)
                Console.WriteLine($"Attempt {attempt}: Checking candidates...");
        }
        
        throw new CryptographicException("Failed to generate prime number after maximum attempts");
    }

    private bool IsProbablePrime(BigInt n, int certainty)
    {
        if (n <= BigInt.One) return false;
        if (n <= BigInt.Three) return true;
        if (n.IsEven()) return false;

        BigInt d = n - BigInt.One;
        BigInt s = BigInt.Zero;
        
        // Находим d и s: n-1 = d * 2^s
        while (d.IsEven())
        {
            d = d / BigInt.Two;
            s = s + BigInt.One;
        }

        // Используем фиксированный набор свидетелей
        BigInt[] witnesses = new[] { 
            new BigInt(2), new BigInt(3), new BigInt(5), 
            new BigInt(7), new BigInt(11), new BigInt(13), 
            new BigInt(17)
        };
        
        certainty = Math.Min(certainty, witnesses.Length);

        // Проверяем всех свидетелей
        for (int i = 0; i < certainty; i++)
        {
            BigInt a = witnesses[i];
            if (a >= n) continue;
            
            BigInt x = a.ModPow(d, n);
            if (x == BigInt.One || x == n - BigInt.One)
                continue;

            bool isProbablyPrime = false;
            for (BigInt r = BigInt.Zero; r < s - BigInt.One; r = r + BigInt.One)
            {
                x = x.ModPow(BigInt.Two, n);
                if (x == n - BigInt.One)
                {
                    isProbablyPrime = true;
                    break;
                }
                if (x == BigInt.One)
                    return false;
            }

            if (!isProbablyPrime)
                return false;
        }
        
        return true;
    }

    // Добавляем метод для проверки качества ключей
    private void ValidateKeyPair()
    {
        // Проверка размера модуля
        if (n.BitLength() < 1024)
            throw new CryptographicException("RSA modulus is too small. Minimum recommended size is 1024 bits.");

        // Проверка, что p и q достаточно различны
        BigInt diff = p > q ? p - q : q - p;
        if (diff.BitLength() < n.BitLength() / 3)
            throw new CryptographicException("Prime factors p and q are too close together.");

        // Проверка, что n = p * q
        if (p * q != n)
            throw new CryptographicException("Invalid key pair: n != p * q");

        // Проверка, что (e * d) mod phi = 1
        if ((e * d) % phi != BigInt.One)
            throw new CryptographicException("Invalid key pair: (e * d) mod phi != 1");
    }

    public void EncryptFileWithPublicKey(string inputFile, string outputFile, BigInt e, BigInt n)
    {
        string text = File.ReadAllText(inputFile, Encoding.UTF8);
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        BigInt message = BytesToBigInt(bytes);
        BigInt encrypted = message.ModPow(e, n);
        byte[] encryptedBytes = BigIntToBytes(encrypted);
        string base64Encrypted = Convert.ToBase64String(encryptedBytes);
        File.WriteAllText(outputFile, base64Encrypted, Encoding.UTF8);
    }

    public void DecryptFileWithPrivateKey(string inputFile, string outputFile)
    {
        string base64Encrypted = File.ReadAllText(inputFile, Encoding.UTF8);
        byte[] encryptedBytes = Convert.FromBase64String(base64Encrypted);
        BigInt encrypted = BytesToBigInt(encryptedBytes);
        BigInt decrypted = encrypted.ModPow(d, n);
        byte[] bytes = BigIntToBytes(decrypted);
        string originalText = Encoding.UTF8.GetString(bytes);
        File.WriteAllText(outputFile, originalText, Encoding.UTF8);
    }

    // Вспомогательные методы для операций с BigInt
    private static BigInt Add(BigInt a, BigInt b) => a + b;
    private static BigInt Subtract(BigInt a, BigInt b) => a - b;
    private static BigInt Multiply(BigInt a, BigInt b) => a * b;
    private static BigInt Divide(BigInt a, BigInt b) => a / b;
    private static BigInt Mod(BigInt a, BigInt b) => a % b;
}