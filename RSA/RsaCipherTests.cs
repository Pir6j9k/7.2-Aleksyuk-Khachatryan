using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Numerics;
using _7._2_Aleksyuk_Khachatryan;

namespace RSA
{
    [TestClass]
    public class RSACipherTests
    {
        [TestMethod]
        public void TestRSA_EncryptDecrypt_EnglishChar()
        {
            var keys = RSACipher.GenerateKeys();
            string original = "Abcd";

            string encrypted = RSACipher.Encrypt(original, keys.PublicKey, keys.N);
            string decrypted = RSACipher.Decrypt(encrypted, keys.PrivateKey, keys.N);

            Assert.AreEqual(original, decrypted, "Ошибка дешифрования английского символа.");
            Assert.AreNotEqual(original, encrypted, "Зашифрованный текст совпадает с оригиналом.");
        }

        [TestMethod]
        public void TestRSA_EncryptDecrypt_RussianText()
        {
            var keys = RSACipher.GenerateKeys();
            string original = "Привет";

            string encrypted = RSACipher.Encrypt(original, keys.PublicKey, keys.N);
            string decrypted = RSACipher.Decrypt(encrypted, keys.PrivateKey, keys.N);

            Assert.AreEqual(original, decrypted, "Ошибка дешифрования русского текста.");
            Assert.AreNotEqual(original, encrypted, "Зашифрованный текст совпадает с оригиналом.");
        }

        [TestMethod]
        public void TestRSA_EncryptDecrypt_SpecialCharacters()
        {
            var keys = RSACipher.GenerateKeys();
            string original = "P@ssw0rd_123!";

            string encrypted = RSACipher.Encrypt(original, keys.PublicKey, keys.N);
            string decrypted = RSACipher.Decrypt(encrypted, keys.PrivateKey, keys.N);

            Assert.AreEqual(original, decrypted, "Ошибка дешифрования строки со спецсимволами.");
            Assert.AreNotEqual(original, encrypted, "Зашифрованный текст совпадает с оригиналом.");
        }

        [TestMethod]
        public void TestRSA_EncryptDecrypt_WhitespaceAndNewlines()
        {
            var keys = RSACipher.GenerateKeys();
            string original = "Текст с пробелами\nи переносом строки";

            string encrypted = RSACipher.Encrypt(original, keys.PublicKey, keys.N);
            string decrypted = RSACipher.Decrypt(encrypted, keys.PrivateKey, keys.N);

            Assert.AreEqual(original, decrypted, "Ошибка дешифрования текста с пробелами и переносами.");
            Assert.AreNotEqual(original, encrypted, "Зашифрованный текст совпадает с оригиналом.");
        }

        [TestMethod]
        public void TestRSA_KeyGeneration_ShouldBeMathematicallyCorrect()
        {
            var keys = RSACipher.GenerateKeys();

            BigInteger phi = (keys.P - 1) * (keys.Q - 1);
            BigInteger check = (keys.PublicKey * keys.PrivateKey) % phi;

            Assert.AreEqual(BigInteger.One, check, "Математическая связь ключей e и d нарушена.");
            Assert.IsTrue(IsPrime(keys.P), "Число P не является простым.");
            Assert.IsTrue(IsPrime(keys.Q), "Число Q не является простым.");
        }
    }
}
