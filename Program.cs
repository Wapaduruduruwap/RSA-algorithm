using System;
using System.Text;
using System.IO;

class Program
{
    // Метод кодирования сообщения
    static string EncodeMessage(string message)
    {
        StringBuilder encoded = new StringBuilder();
        foreach (char c in message)
        {
            // Преобразуем каждый символ в 4-значный код
            encoded.Append(((int)c).ToString("D4"));
        }
        return encoded.ToString();
    }

    // Метод декодирования сообщения
    static string DecodeMessage(string encoded)
    {
        if (encoded.Length % 4 != 0)
        {
            // Добавляем ведущие нули, если их не хватает
            encoded = new string('0', 4 - (encoded.Length % 4)) + encoded;
        }

        StringBuilder decoded = new StringBuilder();
        for (int i = 0; i < encoded.Length; i += 4)
        {
            string code = encoded.Substring(i, 4);
            if (int.TryParse(code, out int asciiCode))
            {
                decoded.Append((char)asciiCode);
            }
            else
            {
                throw new ArgumentException($"Invalid ASCII code at position {i}: {code}");
            }
        }
        return decoded.ToString();
    }

    static void Main()
    {
        try
        {
            Console.WriteLine("Тестирование RSA шифрования с русским текстом");
            Console.WriteLine("-------------------------------------------");

            // Создаем экземпляр RSA
            RSA rsa = new RSA();

            // Создаем текст для шифрования
            string text = "Маша купила 5 яблок";
            Console.WriteLine($"Исходный текст: {text}");

            // Преобразуем текст в число через ASCII коды
            string encodedText = EncodeMessage(text);
            BigInt textNumber = new BigInt(encodedText);
            Console.WriteLine($"Текст в виде ASCII кодов: {encodedText}");
            Console.WriteLine($"Текст в виде числа: {textNumber}");

            // Шифруем число
            Console.WriteLine("\nШифрование...");
            BigInt encrypted = rsa.Encrypt(textNumber);
            Console.WriteLine($"Зашифрованное значение E: {encrypted}");

            // Расшифровываем
            Console.WriteLine("\nРасшифрование...");
            BigInt decrypted = rsa.Decrypt(encrypted);
            Console.WriteLine($"Расшифрованное число: {decrypted}");

            // Преобразуем число обратно в текст
            string decryptedText = DecodeMessage(decrypted.ToString());
            Console.WriteLine($"Расшифрованный текст: {decryptedText}");

            // Проверяем корректность
            Console.WriteLine("\nПроверка результата:");
            Console.WriteLine($"Исходный текст равен расшифрованному: {text == decryptedText}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nОшибка: {ex.Message}");
            Console.WriteLine($"StackTrace: {ex.StackTrace}");
        }
    }
}