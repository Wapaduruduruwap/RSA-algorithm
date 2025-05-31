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

    public (BigInt e, BigInt n) GeneratePublicKey(BigInt P)
    {
        int length = P.ToString().Length;
        int halfLength = length / 2;
        
        BigInt halfP = P / BigInt.Two;
        p = GeneratePrimeNumber(halfP);
        
        q = GeneratePrimeNumber(p - BigInt.One);
        
        while (q == p)
        {
            q = GeneratePrimeNumber(q - BigInt.One);
        }

        n = p * q;

        BigInt phi = CalculateEulerFunction();

        e = new BigInt(65537); 
        
        while (BigInt.Gcd(phi, e) != BigInt.One)
        {
            e = e + BigInt.Two;
        }

        return (e, n);
    }

    public BigInt CalculateEulerFunction()
    {
        return (p - BigInt.One) * (q - BigInt.One);
    }

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

        int k = 10; 
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

    public BigInt CalculateModValue(BigInt value, BigInt modulus)
    {
        if (modulus.IsZero())
            throw new ArgumentException("Модуль не может быть равен нулю");

        BigInt result = value % modulus;
        if (result < BigInt.Zero)
            result = result + modulus;

        return result;
    }
    
    public BigInt FindModularInverse(BigInt a, BigInt m)
    {
        if (m.IsZero())
            throw new ArgumentException("Модуль не может быть равен нулю");

        if (m.IsOne())
            return BigInt.Zero;

        var (x, y, d) = BigInt.ExtendedGcd(a, m);

        if (d != BigInt.One)
            throw new ArgumentException("Обратный элемент не существует");

        while (x <= BigInt.Zero)
            x = x + m;
        while (x >= m)
            x = x - m;

        BigInt check = (a * x) % m;

        if (check != BigInt.One)
            throw new ArgumentException("Ошибка вычисления обратного элемента");

        return x;
    }

    public BigInt Decrypt(BigInt E)
    {
        d = CalculatePrivateExponent();
        return E.ModPow(d, n);
    }

    public BigInt Encrypt(BigInt P)
    {
        var (publicE, publicN) = GeneratePublicKey(P);
        return P.ModPow(publicE, publicN);
    }

    public BigInt CalculatePrivateExponent()
    {
        BigInt phi = CalculateEulerFunction();
        return FindModularInverse(e, phi);
    }
}