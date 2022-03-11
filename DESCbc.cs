using System.Security.Cryptography;

namespace DES_Implementation
{
    public class DESCbc : SymmetricAlgorithm
    {
        public DESCbc()
        {
            PaddingValue = PaddingMode.Zeros;
            ModeValue = CipherMode.CBC;
        }

        public override int BlockSize => 64; 
        public override int KeySize => 64; 
        public override byte[] Key
        {
            get
            {
                if (KeyValue is null)
                    GenerateKey();
                return KeyValue;
            }
            set
            {
                if (DES.IsWeakKey(value))
                    throw new CryptographicException("Weak key");
                if (DES.IsSemiWeakKey(value))
                    throw new CryptographicException("Semi weak key");
                KeyValue = value;
            }
        }
        public override byte[] IV
        {
            get
            {
                if (IVValue is null)
                    GenerateIV();
                return IVValue;
            }
            set
            {
                if(!IsLegalIVSize(value))
                    throw new CryptographicException("Invalid IV size");
                IVValue = value;
            }
        }
        public override PaddingMode Padding
        {
            get => PaddingValue;
            set
            {
                if (value != PaddingMode.Zeros)
                    throw new CryptographicException("Supports only zeros padding mode");
                PaddingValue = value;
            }
        }
        public override CipherMode Mode
        {
            get => ModeValue;
            set
            {
                if (value != CipherMode.CBC)
                    throw new CryptographicException("Supports only CBC cipher mode");
                ModeValue = value;
            }
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return NewEncrypter(DESCbcEncryptor.Mode.Decrypt);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return NewEncrypter(rgbKey, rgbIV, DESCbcEncryptor.Mode.Decrypt);
        }

        public override ICryptoTransform CreateEncryptor()
        {
            return NewEncrypter(DESCbcEncryptor.Mode.Encrypt);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {           
            return NewEncrypter(rgbKey, rgbIV, DESCbcEncryptor.Mode.Encrypt);
        }

        public override void GenerateIV()
        {
            IVValue = new byte[8];
            using (var rand = RandomNumberGenerator.Create())
                rand.GetBytes(IVValue);
        }

        public override void GenerateKey()
        {
            KeyValue = new byte[8];
            using (var rand = RandomNumberGenerator.Create())
            {
                rand.GetBytes(KeyValue);
                while (IsWeakKey(KeyValue) || IsSemiWeakKey(KeyValue))
                    rand.GetBytes(KeyValue);
            }
        }

        public static bool IsWeakKey(byte[] rgbKey)
        {
            if (!IsLegalKeySize(rgbKey))
                throw new CryptographicException("Invalid key size");
            switch (Utils.Join8bitsTo64bist(rgbKey))
            {
                case 72340172838076673:
                case 2242545357694045710:
                case 16204198716015505905:
                case 18374403900871474942:
                    return true;
                default:
                    return false;
            }
        }

        public static bool IsSemiWeakKey(byte[] rgbKey)
        {
            if (!IsLegalKeySize(rgbKey))
                throw new CryptographicException("Invalid key size");
            switch (Utils.Join8bitsTo64bist(rgbKey))
            {
                case 80784550989267214:
                case 135110050437988849:
                case 143554428589179390:
                case 2234100979542855169:
                case 2296870857142767345:
                case 2305315235293957886:
                case 16141428838415593729:
                case 16149873216566784270:
                case 16212643094166696446:
                case 18303189645120372225:
                case 18311634023271562766:
                case 18365959522720284401:
                    return true;
                default:
                    return false;
            }
        }

        private ICryptoTransform NewEncrypter(DESCbcEncryptor.Mode mode)
        {
            return new DESCbcEncryptor(KeyValue, IVValue, mode);
        }

        private ICryptoTransform NewEncrypter(byte[] rgbKey, byte[] rgbIV, DESCbcEncryptor.Mode mode)
        {
            if (DES.IsWeakKey(rgbKey))
                throw new CryptographicException("Weak key");
            if (DES.IsSemiWeakKey(rgbKey))
                throw new CryptographicException("Semi weak key");

            return new DESCbcEncryptor(rgbKey, rgbIV, mode);
        }

        private static bool IsLegalKeySize(byte[] rgbKey)
        {
            return !(rgbKey is null) && (rgbKey.Length == 8);
        }

        private static bool IsLegalIVSize(byte[] rgbIV)
        {
            return !(rgbIV is null) && (rgbIV.Length == 8);
        }
    }
}
