using System;
using System.Text;

public class RSA
{
    private BigInt p = BigInt.Zero;
    private BigInt q = BigInt.Zero;
    private BigInt n = BigInt.Zero;
    private BigInt e = BigInt.Zero;
    private BigInt d = BigInt.Zero;
    private Random random;

    public RSA()
    {
        random = new Random();
    }

    // 1. Генерация открытого ключа на основе секретного числа P
    public (BigInt e, BigInt n) GeneratePublicKey(BigInt P)
    {
        Console.WriteLine($"Начинаем генерацию ключей для P = {P}");
        
        // Разбиваем P на две части примерно равной длины
        int length = P.ToString().Length;
        int halfLength = length / 2;
        
        // Получаем p и q как простые числа, близкие к половинам P
        BigInt halfP = P / BigInt.Two;
        Console.WriteLine($"Ищем простое число p <= {halfP}");
        p = GeneratePrimeNumber(halfP);
        Console.WriteLine($"Найдено p = {p}");
        
        // Для q берем число, меньшее p
        Console.WriteLine($"Ищем простое число q < {p}");
        q = GeneratePrimeNumber(p - BigInt.One);
        
        // Если получили то же самое число, ищем следующее меньшее простое
        while (q == p)
        {
            Console.WriteLine($"q равно p, ищем меньшее простое число");
            q = GeneratePrimeNumber(q - BigInt.One);
        }
        Console.WriteLine($"Найдено q = {q}");

        // Вычисляем модуль n
        n = p * q;
        Console.WriteLine($"Вычислен модуль n = p * q = {n}");

        // Вычисляем функцию Эйлера
        BigInt phi = CalculateEulerFunction();
        Console.WriteLine($"Функция Эйлера phi = {phi}");

        // Выбираем открытую экспоненту
        e = new BigInt(65537); // Стандартное значение
        Console.WriteLine($"Пробуем открытую экспоненту e = {e}");
        
        while (BigInt.Gcd(phi, e) != BigInt.One)
        {
            e = e + BigInt.Two;
            Console.WriteLine($"GCD не равен 1, пробуем следующее e = {e}");
        }
        Console.WriteLine($"Найдена подходящая открытая экспонента e = {e}");

        return (e, n);
    }

    // 2. Вычисление функции Эйлера
    public BigInt CalculateEulerFunction()
    {
        return (p - BigInt.One) * (q - BigInt.One);
    }

    // 3. Генерация простого числа, меньшего или равного x
    public BigInt GeneratePrimeNumber(BigInt x)
    {
        if ((x % BigInt.Two) == BigInt.Zero)
            x = x - BigInt.One;

        BigInt current = x;
        while (current > BigInt.Two)
        {
            if (IsPrime(current))
            {
                Console.WriteLine($"Найдено простое число: {current}");
                return current;
            }
            current = current - BigInt.Two;
        }

        return BigInt.Two;
    }

    // 4. Проверка числа на простоту
    public bool IsPrime(BigInt number)
    {
        if (number <= BigInt.One)
            return false;
        if (number <= BigInt.Three)
            return true;
        if ((number % BigInt.Two) == BigInt.Zero)
            return false;

        BigInt d = number - BigInt.One;
        int s = 0;

        while ((d % BigInt.Two) == BigInt.Zero)
        {
            d = d / BigInt.Two;
            s++;
        }

        // Тест Миллера-Рабина
        int k = 10; // Количество проверок
        for (int i = 0; i < k; i++)
        {
            BigInt a = GenerateRandomNumber(BigInt.Two, number - BigInt.Two);
            BigInt x = a.ModPow(d, number);

            if (x == BigInt.One || x == number - BigInt.One)
                continue;

            bool isProbablyPrime = false;
            for (int r = 1; r < s; r++)
            {
                x = x.ModPow(BigInt.Two, number);
                if (x == number - BigInt.One)
                {
                    isProbablyPrime = true;
                    break;
                }
            }

            if (!isProbablyPrime)
                return false;
        }
        
        return true;
    }

    // 5. Генерация случайного числа в заданном диапазоне
    public BigInt GenerateRandomNumber(BigInt min, BigInt max)
    {
        int length = max.ToString().Length;
        StringBuilder sb = new StringBuilder();
        
        // Генерируем случайное число нужной длины
        for (int i = 0; i < length; i++)
        {
            sb.Append(random.Next(10));
        }
        
        BigInt result = new BigInt(sb.ToString());
        
        // Приводим число к нужному диапазону
        result = min + (result % (max - min));
        return result;
    }

    // 7. Расшифровка сообщения
    public BigInt Decrypt(BigInt E)
    {
        // Вычисляем закрытую экспоненту
        d = CalculatePrivateExponent();
        Console.WriteLine($"Вычислена закрытая экспонента d = {d}");
        
        // Расшифровываем сообщение
        Console.WriteLine($"Расшифровываем E = {E} с помощью d = {d} и n = {n}");
        BigInt result = E.ModPow(d, n);
        Console.WriteLine($"Результат расшифрования: {result}");
        return result;
    }

    // 8. Шифрование секретного ключа
    public BigInt Encrypt(BigInt P)
    {
        // Генерируем открытый ключ
        Console.WriteLine("Генерация открытого ключа...");
        var (publicE, publicN) = GeneratePublicKey(P);
        Console.WriteLine($"Сгенерирован открытый ключ: (e={publicE}, n={publicN})");
        
        // Шифруем сообщение
        Console.WriteLine($"Шифруем P = {P} с помощью e = {publicE} и n = {publicN}");
        BigInt result = P.ModPow(publicE, publicN);
        Console.WriteLine($"Результат шифрования: {result}");
        return result;
    }

    // 9. Вычисление закрытой экспоненты
    public BigInt CalculatePrivateExponent()
    {
        BigInt phi = CalculateEulerFunction();
        Console.WriteLine($"Вычисляем закрытую экспоненту для e = {e} и phi = {phi}");
        
        var (d, _, gcd) = BigInt.ExtendedGcd(e, phi);
        Console.WriteLine($"Результат ExtendedGcd: d = {d}, gcd = {gcd}");
        
        if (gcd != BigInt.One)
            throw new ArgumentException("Невозможно вычислить закрытую экспоненту");

        // Если d отрицательное, добавляем значение функции Эйлера
        if (d < BigInt.Zero)
        {
            Console.WriteLine($"d отрицательное ({d}), добавляем phi");
            d = d + phi;
            Console.WriteLine($"Новое значение d = {d}");
        }

        return d;
    }
}