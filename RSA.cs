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
        // Разбиваем P на две части примерно равной длины
        int length = P.ToString().Length;
        int halfLength = length / 2;
        
        // Получаем p и q как простые числа, близкие к половинам P
        BigInt halfP = P / BigInt.Two;
        p = GeneratePrimeNumber(halfP);
        
        // Для q берем число, меньшее p
        q = GeneratePrimeNumber(p - BigInt.One);
        
        // Если получили то же самое число, ищем следующее меньшее простое
        while (q == p)
        {
            q = GeneratePrimeNumber(q - BigInt.One);
        }

        // Вычисляем модуль n
        n = p * q;

        // Вычисляем функцию Эйлера
        BigInt phi = CalculateEulerFunction();

        // Выбираем открытую экспоненту
        e = new BigInt(65537); // Стандартное значение
        
        while (BigInt.Gcd(phi, e) != BigInt.One)
        {
            e = e + BigInt.Two;
        }

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

    // 6. Вычисление основного значения по модулю
    public BigInt CalculateModValue(BigInt value, BigInt modulus)
    {
        if (modulus.IsZero())
            throw new ArgumentException("Модуль не может быть равен нулю");

        BigInt result = value % modulus;
        if (result < BigInt.Zero)
            result = result + modulus;

        return result;
    }

    // 7. Нахождение обратного элемента по модулю (расширенный алгоритм Евклида)
    public BigInt FindModularInverse(BigInt a, BigInt m)
    {
        if (m.IsZero())
            throw new ArgumentException("Модуль не может быть равен нулю");

        if (m.IsOne())
            return BigInt.Zero;

        var (x, y, d) = BigInt.ExtendedGcd(a, m);

        if (d != BigInt.One)
            throw new ArgumentException("Обратный элемент не существует");

        // Нормализуем результат в диапазоне [1, m-1]
        while (x <= BigInt.Zero)
            x = x + m;
        while (x >= m)
            x = x - m;

        // Проверяем корректность результата
        BigInt check = (a * x) % m;
        
        if (check != BigInt.One)
            throw new ArgumentException("Ошибка вычисления обратного элемента");

        return x;
    }

    // 8. Расшифровка сообщения
    public BigInt Decrypt(BigInt E)
    {
        // Вычисляем закрытую экспоненту
        d = CalculatePrivateExponent();
        
        // Расшифровываем сообщение
        return E.ModPow(d, n);
    }

    // 9. Шифрование секретного ключа
    public BigInt Encrypt(BigInt P)
    {
        // Генерируем открытый ключ
        var (publicE, publicN) = GeneratePublicKey(P);
        
        // Шифруем сообщение
        return P.ModPow(publicE, publicN);
    }

    // 10. Вычисление закрытой экспоненты
    public BigInt CalculatePrivateExponent()
    {
        BigInt phi = CalculateEulerFunction();
        return FindModularInverse(e, phi);
    }
}