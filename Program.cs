class Program
{
    static void Main()
    {
        try
        {
            // 1. Инициализация RSA
            RSA rsa = new RSA(1024);
            
            // 2. Получение открытого ключа
            var (e, n) = rsa.GetPublicKey();
            Console.WriteLine($"Public key:\nE: {e}\nN: {n}");
            
            // 3. Сохраняем открытый ключ в файл
            rsa.SavePublicKey("public_key.txt");
            
            // 4. Загружаем открытый ключ из файла
            var (loadedE, loadedN) = RSA.LoadPublicKey("public_key.txt");
            
            // 5. Шифруем файл с помощью открытого ключа
            rsa.EncryptFileWithPublicKey("secret.txt", "encrypted_secret.txt", loadedE, loadedN);
            Console.WriteLine("File encrypted successfully");
            
            // 6. Дешифруем файл с помощью закрытого ключа
            rsa.DecryptFileWithPrivateKey("encrypted_secret.txt", "decrypted_secret.txt");
            Console.WriteLine("File decrypted successfully");
            
            // 7. Проверяем результат
            Console.WriteLine("\nOriginal:");
            Console.WriteLine(File.ReadAllText("secret.txt"));
            
            Console.WriteLine("\nDecrypted:");
            Console.WriteLine(File.ReadAllText("decrypted_secret.txt"));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}