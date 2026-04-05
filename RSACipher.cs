using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace _7._2_Aleksyuk_Khachatryan
{
    public class RSACipher
    {

        private static readonly Random _random = new Random();
        public class RSAKeys
        {
            public BigInteger P { get; set; }
            public BigInteger Q { get; set; }
            public BigInteger N { get; set; }
            public BigInteger PublicKey { get; set; }
            public BigInteger PrivateKey { get; set; } 
        }

        /// <summary>
        /// Генерирует пару случайных ключей.
        /// </summary>
        /// <returns>Объект с открытым и закрытым ключами.</returns>
        public static RSAKeys GenerateKeys()
        {
            BigInteger p = GenerateRandomPrime(300, 2000);
            BigInteger q;
            do
            {
                q = GenerateRandomPrime(300, 2000);
            } while (p == q); 

            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);

            BigInteger e;
            do
            {
                e = _random.Next(2, (int)BigInteger.Min(phi - 1, 100000));
            } while (GCD(e, phi) != 1); 

            BigInteger d = ModInverse(e, phi);

            return new RSAKeys { P = p, Q = q, N = n, PublicKey = e, PrivateKey = d };
        }

        /// <summary>
        /// Шифрует строку текста. Каждый символ шифруется отдельно.
        /// </summary>
        /// <param name="text">Исходный текст.</param>
        /// <param name="e">Открытый ключ.</param>
        /// <param name="n">Модуль.</param>
        /// <returns>Строка с числами, разделенными пробелом.</returns>
        public static string Encrypt(string text, BigInteger e, BigInteger n)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            if (string.IsNullOrEmpty(text)) return string.Empty;

            var result = new List<string>();
            foreach (char c in text)
            {
                BigInteger m = (int)c;
                BigInteger crypto = BigInteger.ModPow(m, e, n);
                result.Add(crypto.ToString());
            }

            return string.Join(" ", result);
        }

        /// <summary>
        /// Расшифровывает строку чисел обратно в текст.
        /// </summary>
        /// <param name="cipherText">Зашифрованный текст (числа через пробел).</param>
        /// <param name="d">Закрытый ключ.</param>
        /// <param name="n">Модуль.</param>
        /// <returns>Исходная строка текста.</returns>
        public static string Decrypt(string cipherText, BigInteger d, BigInteger n)
        {
            if (string.IsNullOrWhiteSpace(cipherText)) return string.Empty;

            try
            {
                var sb = new StringBuilder();
                string[] numbers = cipherText.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (string numStr in numbers)
                {
                    BigInteger c = BigInteger.Parse(numStr);
                    BigInteger m = BigInteger.ModPow(c, d, n);
                    sb.Append((char)(int)m);
                }
                return sb.ToString();
            }
            catch (Exception ex)
            {
                throw new FormatException("Неверный формат зашифрованных данных.", ex);
            }
        }

        /// <summary>
        /// Генерирует случайное простое число в заданном диапазоне.
        /// </summary>
        private static BigInteger GenerateRandomPrime(int min, int max)
        {
            while (true)
            {
                int num = _random.Next(min, max);
                if (IsPrime(num)) return num;
            }
        }

        /// <summary>
        /// Проверяет, является ли число простым.
        /// </summary>
        /// <param name="n">Число типа BigInteger для проверки на простоту.</param>
        /// <returns>Возвращает true, если число является простым; иначе — false.</returns>
        public static bool IsPrime(BigInteger n)
        {
            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0) return false;
            for (BigInteger i = 3; i * i <= n; i += 2)
                if (n % i == 0) return false;
            return true;
        }

        /// <summary>
        /// Вычисляет наибольший общий делитель (НОД) двух чисел по классическому алгоритму Евклида.
        /// </summary>
        /// <param name="a">Первое целое число (обычно экспонента e).</param>
        /// <param name="b">Второе целое число (обычно значение функции Эйлера phi).</param>
        /// <returns>Наибольший общий делитель переданных чисел. Если результат равен 1, числа взаимно просты.</returns>
        private static BigInteger GCD(BigInteger a, BigInteger b)
        {
            while (b != 0)
            {
                BigInteger temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }

        /// <summary>
        /// Вычисляет модульное обратное число для 'a' по модулю 'n' с использованием расширенного алгоритма Евклида.
        /// </summary>
        /// <param name="a">Число, для которого ищется обратное (обычно открытая экспонента e).</param>
        /// <param name="n">Модуль, по которому производится вычисление (обычно функция Эйлера phi).</param>
        /// <returns>
        /// Возвращает значение d, такое что (a * d) % n == 1. 
        /// Если обратного числа не существует (НОД != 1), возвращает -1.
        /// </returns>
        private static BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            BigInteger t = 0, nt = 1, r = n, nr = a;
            while (nr != 0)
            {
                BigInteger q = r / nr;
                (t, nt) = (nt, t - q * nt);
                (r, nr) = (nr, r - q * nr);
            }
            if (r > 1) return -1;
            if (t < 0) t += n;
            return t;
        }
    }
}
