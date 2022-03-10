using DES_Implementation;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Security.Cryptography;

namespace Tests
{
    [TestClass]
    public class DESCbcTest
    {
        [TestMethod]
        public void TestDESCbc()
        {
            // Arrange
            var des = new DESCbc();
            var rand = RandomNumberGenerator.Create();
            var plainText = new byte[18];
            rand.GetBytes(plainText);
            var key = new byte[8];
            rand.GetBytes(key);
            var iv = new byte[8];
            rand.GetBytes(plainText);

            // Act
            var cipher = DESCbcEncrypt(plainText, key, iv);
            var decrypted = DESCbcDecrypt(cipher, key, iv);
            des.Clear();

            // Assert
            for (int i = 0; i < plainText.Length; i++)
                Assert.AreEqual(plainText[i], decrypted[i]);
        }

        [TestMethod]
        public void TestEqualsToDES()
        {
            // Arrange
            var desRef = new DESCryptoServiceProvider
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.Zeros,
            };
            var rand = RandomNumberGenerator.Create();
            var plainText = new byte[18];
            rand.GetBytes(plainText);
            var key = new byte[8];
            rand.GetBytes(key);
            var iv = new byte[8];
            rand.GetBytes(plainText);

            // Act
            var cipher = DESCbcEncrypt(plainText, key, iv);

            var transform = desRef.CreateEncryptor(key, iv);
            var cipherRef = new byte[24];
            using (var ms = new MemoryStream(plainText, false))
            using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Read))
            {
                cs.Read(cipherRef, 0, cipherRef.Length);
            }
            desRef.Clear();

            // Assert
            for (int i = 0; i < 24; i++)
                Assert.AreEqual(cipherRef[i], cipher[i]);
        }

        private byte[] DESCbcEncrypt(byte[] plainText, byte[] key, byte[] iv)
        {
            using (var des = new DESCbc())
            {
                var transform = des.CreateEncryptor(key, iv);
                var encrypted = new byte[24];
                using (var outMs = new MemoryStream(encrypted, true))
                using (var ms = new MemoryStream(plainText, false))
                using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Read))
                {
                    cs.Read(encrypted, 0, encrypted.Length);
                    return encrypted;
                }
            }
        }

        private byte[] DESCbcDecrypt(byte[] plainText, byte[] key, byte[] iv)
        {
            using (var des = new DESCbc())
            {
                var transform = des.CreateDecryptor(key, iv);
                var decrypted = new byte[24];
                using (var ms = new MemoryStream(plainText, false))
                using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Read))
                {
                    cs.Read(decrypted, 0, decrypted.Length);
                    return decrypted;
                }
            }
        }
    }
}
