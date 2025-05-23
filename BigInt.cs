using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

public class BigInt : IComparable<BigInt>, IEquatable<BigInt>
{
    private List<byte> digits;
    private bool isNegative;

    public static readonly BigInt Zero = new BigInt(0);
    public static readonly BigInt One = new BigInt(1);
    public static readonly BigInt Two = new BigInt(2);
    public static readonly BigInt Three = new BigInt(3);

    public BigInt() : this(0) { }

    public BigInt(long num)
    {
        digits = new List<byte>();
        if (num < 0)
        {
            isNegative = true;
            num = -num;
        }

        if (num == 0)
        {
            digits.Add(0);
        }
        else
        {
            while (num > 0)
            {
                digits.Add((byte)(num % 10));
                num /= 10;
            }
        }
    }

    public BigInt(string str)
    {
        if (string.IsNullOrEmpty(str))
            throw new ArgumentException("Empty string cannot be converted to BigInt");

        int start = 0;
        if (str[0] == '-')
        {
            isNegative = true;
            start = 1;
        }

        while (start < str.Length && str[start] == '0')
            start++;

        if (start == str.Length)
        {
            digits = new List<byte> { 0 };
            isNegative = false;
            return;
        }

        digits = new List<byte>();
        for (int i = str.Length - 1; i >= start; i--)
        {
            if (!char.IsDigit(str[i]))
                throw new ArgumentException("Invalid character in number");

            digits.Add((byte)(str[i] - '0'));
        }
    }

    private BigInt(List<byte> digits, bool isNegative)
    {
        this.digits = digits;
        this.isNegative = isNegative;
        RemoveLeadingZeros();
    }

    ~BigInt() { }

    private void RemoveLeadingZeros()
    {
        while (digits.Count > 1 && digits.Last() == 0)
            digits.RemoveAt(digits.Count - 1);

        if (IsZero())
            isNegative = false;
    }

    public bool IsZero() => digits.Count == 1 && digits[0] == 0;

    public BigInt Abs() => new BigInt(new List<byte>(digits), false);

    public BigInt Negate() => IsZero() ? this : new BigInt(new List<byte>(digits), !isNegative);

    private int CompareAbs(BigInt other)
    {
        if (digits.Count != other.digits.Count)
            return digits.Count < other.digits.Count ? -1 : 1;

        for (int i = digits.Count - 1; i >= 0; i--)
        {
            if (digits[i] != other.digits[i])
                return digits[i] < other.digits[i] ? -1 : 1;
        }

        return 0;
    }

    public int CompareTo(BigInt? other)
    {
        if (other is null) return 1;
        if (isNegative != other.isNegative)
            return isNegative ? -1 : 1;
        return isNegative ? -CompareAbs(other) : CompareAbs(other);
    }

    public bool Equals(BigInt? other)
    {
        if (other is null) return false;
        return isNegative == other.isNegative && digits.SequenceEqual(other.digits);
    }

    public override bool Equals(object? obj) => obj is BigInt other && Equals(other);

    public override int GetHashCode() => digits.Aggregate(isNegative ? 1 : 0, (hash, digit) => hash * 31 + digit);

    public static bool operator ==(BigInt? left, BigInt? right)
    {
        if (left is null) return right is null;
        return left.Equals(right);
    }

    public static bool operator !=(BigInt? left, BigInt? right) => !(left == right);
    public static bool operator <(BigInt left, BigInt right) => left.CompareTo(right) < 0;
    public static bool operator >(BigInt left, BigInt right) => left.CompareTo(right) > 0;
    public static bool operator <=(BigInt left, BigInt right) => left.CompareTo(right) <= 0;
    public static bool operator >=(BigInt left, BigInt right) => left.CompareTo(right) >= 0;

    public static BigInt operator +(BigInt a, BigInt b) => Add(a, b);
    public static BigInt operator -(BigInt a) => a.Negate();
    public static BigInt operator -(BigInt a, BigInt b) => Subtract(a, b);
    public static BigInt operator *(BigInt a, BigInt b) => Multiply(a, b);
    public static BigInt operator /(BigInt a, BigInt b) => Divide(a, b);
    public static BigInt operator %(BigInt a, BigInt b) => Mod(a, b);

    private static BigInt Add(BigInt a, BigInt b)
    {
        if (a.isNegative && !b.isNegative) return b - (-a);
        if (!a.isNegative && b.isNegative) return a - (-b);
        
        var result = new List<byte>();
        int carry = 0;
        int maxLen = Math.Max(a.digits.Count, b.digits.Count);

        for (int i = 0; i < maxLen || carry > 0; i++)
        {
            int sum = carry;
            if (i < a.digits.Count) sum += a.digits[i];
            if (i < b.digits.Count) sum += b.digits[i];
            
            result.Add((byte)(sum % 10));
            carry = sum / 10;
        }

        return new BigInt(result, a.isNegative);
    }

    private static BigInt Subtract(BigInt a, BigInt b)
    {
        if (a.isNegative != b.isNegative) return a + (-b);
        if (a.CompareAbs(b) < 0) return -(b - a);
        
        var result = new List<byte>();
        int borrow = 0;

        for (int i = 0; i < a.digits.Count; i++)
        {
            int diff = a.digits[i] - borrow;
            if (i < b.digits.Count) diff -= b.digits[i];
            
            if (diff < 0)
            {
                diff += 10;
                borrow = 1;
            }
            else
            {
                borrow = 0;
            }
            
            result.Add((byte)diff);
        }

        return new BigInt(result, a.isNegative);
    }

    private static BigInt Multiply(BigInt a, BigInt b)
    {
        if (a.IsZero() || b.IsZero()) return Zero;
        
        var result = Zero;
        for (int i = 0; i < b.digits.Count; i++)
        {
            var temp = MultiplyByDigit(a, b.digits[i]);
            temp = ShiftLeft(temp, i);
            result = Add(result, temp);
        }
        
        result.isNegative = a.isNegative != b.isNegative;
        return result;
    }

    private static BigInt MultiplyByDigit(BigInt a, byte digit)
    {
        if (digit == 0) return Zero;
        
        var result = new List<byte>();
        int carry = 0;

        foreach (var d in a.digits)
        {
            int product = d * digit + carry;
            result.Add((byte)(product % 10));
            carry = product / 10;
        }

        if (carry > 0)
            result.Add((byte)carry);

        return new BigInt(result, a.isNegative);
    }

    private static BigInt ShiftLeft(BigInt num, int positions)
    {
        if (num.IsZero()) return num;
        
        var result = new List<byte>(new byte[positions]);
        result.AddRange(num.digits);
        return new BigInt(result, num.isNegative);
    }

    private static (BigInt quotient, BigInt remainder) DivMod(BigInt dividend, BigInt divisor)
    {
        if (divisor.IsZero()) throw new DivideByZeroException();
        
        BigInt remainder = Zero;
        var quotientDigits = new List<byte>();

        for (int i = dividend.digits.Count - 1; i >= 0; i--)
        {
            remainder = Add(Multiply(remainder, Ten), new BigInt(dividend.digits[i].ToString()));
            byte digit = 0;
            
            while (remainder.CompareAbs(divisor) >= 0)
            {
                remainder = Subtract(remainder, divisor);
                digit++;
            }
            
            quotientDigits.Add(digit);
        }

        quotientDigits.Reverse();
        var quotient = new BigInt(quotientDigits, dividend.isNegative != divisor.isNegative);
        quotient.RemoveLeadingZeros();
        
        return (quotient, remainder);
    }

    private static BigInt Divide(BigInt a, BigInt b) => DivMod(a, b).quotient;
    private static BigInt Mod(BigInt a, BigInt b) => DivMod(a, b).remainder;

    public BigInt ModPow(BigInt exponent, BigInt modulus)
    {
        if (modulus.IsZero())
            throw new ArgumentException("Modulus cannot be zero");

        BigInt result = One;
        BigInt baseVal = Mod(this, modulus);
        BigInt exp = new BigInt(exponent.ToString());

        while (!exp.IsZero())
        {
            if ((exp.digits[0] & 1) == 1)
                result = Mod(Multiply(result, baseVal), modulus);
            
            baseVal = Mod(Multiply(baseVal, baseVal), modulus);
            exp = Divide(exp, Two);
        }

        return result;
    }

    public BigInt ModInverse(BigInt modulus)
    {
        if (modulus <= Zero)
            throw new ArgumentException("Modulus must be positive");

        BigInt a = Mod(this, modulus);
        if (a < Zero) a = Add(a, modulus);

        BigInt m = new BigInt(modulus.ToString());
        BigInt x = Zero, y = One;
        BigInt lastX = One, lastY = Zero;

        while (!m.IsZero())
        {
            BigInt q = Divide(a, m);
            BigInt temp = m;
            m = Mod(a, m);
            a = temp;

            temp = x;
            x = Subtract(lastX, Multiply(q, x));
            lastX = temp;

            temp = y;
            y = Subtract(lastY, Multiply(q, y));
            lastY = temp;
        }

        if (a != One)
            throw new ArithmeticException("Numbers are not coprime");

        return Mod(Add(Mod(lastX, modulus), modulus), modulus);
    }

    public override string ToString()
    {
        if (IsZero()) return "0";
        
        var sb = new StringBuilder();
        if (isNegative) sb.Append('-');
        
        for (int i = digits.Count - 1; i >= 0; i--)
            sb.Append(digits[i]);
        
        return sb.ToString();
    }

    public byte ToByte()
    {
        if (this < Zero || this > new BigInt(255))
            throw new InvalidOperationException("BigInt value must be between 0 and 255 to convert to byte");

        int value = 0;
        for (int i = 0; i < digits.Count; i++)
        {
            value += digits[i] * (int)Math.Pow(10, i);
        }
        return (byte)value;
    }

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
    public static BigInt Ten => new BigInt(10);
    public static BigInt Gcd(BigInt a, BigInt b) => b.IsZero() ? a : Gcd(b, Mod(a, b));
}