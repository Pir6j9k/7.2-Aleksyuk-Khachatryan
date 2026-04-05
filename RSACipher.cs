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

        public class RSAKeys
        {
            public BigInteger P { get; set; }
            public BigInteger Q { get; set; }
            public BigInteger N { get; set; }
            public BigInteger PublicKey { get; set; }
            public BigInteger PrivateKey { get; set; } 
        }

        /// <summary>
        /// Генерирует пару ключей на основе простых чисел.
        /// </summary>
        /// <returns>Объект с открытым и закрытым ключами.</returns>
        public static RSAKeys GenerateKeys()
        {
            BigInteger p = 101;
            BigInteger q = 103;
            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);
            BigInteger e = 7; 

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
