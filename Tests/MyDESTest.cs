using DES_Implementation;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.IO;

namespace Tests
{
    [TestClass]
    public class MyDESTest
    {
        [TestMethod]
        public void TestOneBlock()
        {
            // Arrange
            var des = new MyDES();
            var rand = RandomNumberGenerator.Create();
            var key = new byte[8];
            rand.GetBytes(key);
            var plainText = new byte[8];
            rand.GetBytes(plainText);

            // Act
            var cipher = des.TransformBlock(plainText, MyDES.Mode.Encrypt, key);
            var decrypted = des.TransformBlock(cipher, MyDES.Mode.Decrypt, key);

            // Assert
            for (int i = 0; i < 8; i++)
                Assert.AreEqual(plainText[i], decrypted[i]);
        }

        [TestMethod]
        public void TestEqualsToDES()
        {
            // Arrange
            var des = new MyDES();
            var desRef = new DESCryptoServiceProvider { Mode = CipherMode.ECB };
            var rand = RandomNumberGenerator.Create();
            var key = new byte[8];
            rand.GetBytes(key);
            var plainText = new byte[8];
            rand.GetBytes(plainText);

            // Act
            var cipher = des.TransformBlock(plainText, MyDES.Mode.Encrypt, key);

            var transform = desRef.CreateEncryptor(key, null);
            var cipherRef = new byte[8];
            using (var ms = new MemoryStream(plainText, false))
            using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Read))
            {
                cs.Read(cipherRef, 0, 8);
            }
            desRef.Clear();

            // Assert
            for (int i = 0; i < 8; i++)
                Assert.AreEqual(cipherRef[i], cipher[i]);
        }
    }
}
