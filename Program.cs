using System.Text;

class Program
{
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

    // 1. Тесты сравнения чисел
    static void TestComparisons()
    {
        BigInt a = new BigInt("123456");
        BigInt b = new BigInt("123457");
        if (!(a < b)) throw new Exception("Ошибка в тесте 1.1");
        if (!(b > a)) throw new Exception("Ошибка в тесте 1.2");
        if (a == b) throw new Exception("Ошибка в тесте 1.3");
        if (!(a != b)) throw new Exception("Ошибка в тесте 1.4");
        if (!(a <= b)) throw new Exception("Ошибка в тесте 1.5");
        if (!(b >= a)) throw new Exception("Ошибка в тесте 1.6");

        BigInt c = new BigInt("-987654");
        BigInt d = new BigInt("-987653");
        if (!(c < d)) throw new Exception("Ошибка в тесте 1.7");
        if (!(d > c)) throw new Exception("Ошибка в тесте 1.8");
        if (c == d) throw new Exception("Ошибка в тесте 1.9");
        if (!(c != d)) throw new Exception("Ошибка в тесте 1.10");

        BigInt e = new BigInt("12345");
        BigInt f = new BigInt("-12345");
        if (!(f < e)) throw new Exception("Ошибка в тесте 1.11");
        if (!(e > f)) throw new Exception("Ошибка в тесте 1.12");
    }

    // 2. Тесты арифметических операций
    static void TestArithmetic()
    {
        BigInt a = new BigInt("12345");
        BigInt b = new BigInt("54321");
        if ((a + b).ToString() != "66666") throw new Exception("Ошибка в тесте 2.1");

        if ((b - a).ToString() != "41976") throw new Exception("Ошибка в тесте 2.2");

        if ((-a).ToString() != "-12345") throw new Exception("Ошибка в тесте 2.3");

        BigInt c = new BigInt("1234");
        BigInt d = new BigInt("5678");
        if ((c * d).ToString() != "7006652") throw new Exception("Ошибка в тесте 2.4");

        BigInt e = new BigInt("100000");
        BigInt f = new BigInt("3");
        if ((e / f).ToString() != "33333") throw new Exception("Ошибка в тесте 2.5");
        if ((e % f).ToString() != "1") throw new Exception("Ошибка в тесте 2.6");
    }

    // 3. Тесты специальных операций
    static void TestSpecialOperations()
    {
        try
        {
            BigInt prime = new BigInt("17");
            BigInt notPrime = new BigInt("15");
            RSA rsa = new RSA();
            if (!rsa.IsPrime(prime)) throw new Exception("Ошибка в тесте 3.1");
            if (rsa.IsPrime(notPrime)) throw new Exception("Ошибка в тесте 3.2");

            BigInt a = new BigInt("5");
            BigInt m = new BigInt("11");
            
            BigInt inverse = rsa.FindModularInverse(a, m);
            
            BigInt product = a * inverse;
            
            BigInt result = product % m;
            
            if (result < BigInt.Zero)
            {
                result = result + m;
            }
            
            if (result != BigInt.One)
                throw new Exception($"Ошибка в тесте 3.3: {a} * {inverse} mod {m} = {result} (ожидается 1)");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Исключение в TestSpecialOperations: {ex.Message}");
            throw;
        }
    }

    static void TestRSA()
    {
        RSA rsa = new RSA();
        string originalText = "Test123";
        string encodedText = EncodeMessage(originalText);
        BigInt textNumber = new BigInt(encodedText);
        
        BigInt encrypted = rsa.Encrypt(textNumber);
        
        BigInt decrypted = rsa.Decrypt(encrypted);
        string decryptedText = DecodeMessage(decrypted.ToString());
        
        if (originalText != decryptedText)
            throw new Exception("Ошибка в тесте 4.1");
    }

    static void RunAllTests()
    {
        try
        {
            TestComparisons();
            TestArithmetic();
            TestSpecialOperations();
            TestRSA();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            Environment.Exit(1);
        }
    }

    static void Main()
    {
        try
        {
            Console.InputEncoding = Encoding.Unicode;
            Console.OutputEncoding = Encoding.Unicode;

            Console.Clear(); 
            Console.WriteLine("Хотите запустить тестирование? (y/n):");
            string? response = Console.ReadLine()?.ToLower();
            
            if (response == "y")
            {
                RunAllTests();
            }

            Console.Clear(); 

            RSA rsa = new RSA();

            Console.WriteLine("Введите текст, который хотите зашифровать:");
            string? text = Console.ReadLine();

            if (string.IsNullOrEmpty(text))
            {
                Console.WriteLine("Ошибка: текст не может быть пустым");
                return;
            }

            Console.WriteLine($"\nИсходный текст: {text}");

            string encodedText = EncodeMessage(text);
            BigInt textNumber = new BigInt(encodedText);
            Console.WriteLine($"Текст в виде ASCII кодов: {encodedText}");

            Console.WriteLine("\nШифрование...");
            BigInt encrypted = rsa.Encrypt(textNumber);
            Console.WriteLine($"Зашифрованное значение: {encrypted}");

            Console.WriteLine("\nРасшифрование...");
            BigInt decrypted = rsa.Decrypt(encrypted);

            string decryptedText = DecodeMessage(decrypted.ToString());
            Console.WriteLine($"Расшифрованный текст: {decryptedText}");

            Console.WriteLine("\nПроверка результата:");
            Console.WriteLine($"Исходный текст равен расшифрованному: {text == decryptedText}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nОшибка: {ex.Message}");
            if (ex.StackTrace != null)
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
        }
    }
}