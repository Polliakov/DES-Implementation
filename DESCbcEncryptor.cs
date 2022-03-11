using System;
using System.Security.Cryptography;

namespace DES_Implementation
{
    internal class DESCbcEncryptor : ICryptoTransform
    {
        public DESCbcEncryptor(byte[] rgbKey, byte[] rgbIV, Mode mode)
        {
            this.mode = mode;
            keys48b = KeyExpansion(rgbKey);
            cbcBuffer = Utils.Join8bitsTo64bist(rgbIV);
        }

        public int InputBlockSize => 8;
        public int OutputBlockSize => 8;
        public bool CanTransformMultipleBlocks => false;
        public bool CanReuseTransform => false;
        public enum Mode { Encrypt, Decrypt }

        private readonly Mode mode;
        private readonly ulong[] keys48b;
        private ulong cbcBuffer;

        public void Dispose()
        {
            Array.Clear(keys48b, 0, keys48b.Length);
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            #region Validation
            if (inputBuffer == null)
                throw new ArgumentNullException(nameof(inputBuffer));
            if (outputBuffer == null)
                throw new ArgumentNullException(nameof(outputBuffer));
            if (inputOffset != 0)
                throw new ArgumentOutOfRangeException("Argument invalid offset length");
            if (inputCount != InputBlockSize)
                throw new ArgumentException("Argument invalid value");
            #endregion

            if (inputCount == 0)
                return 0;

            var block = new byte[InputBlockSize];
            Buffer.BlockCopy(inputBuffer, inputOffset, block, 0, inputCount);

            var resultBlock = TransformCBC(block);
            Buffer.BlockCopy(resultBlock, 0, outputBuffer, outputOffset, inputCount);

            return OutputBlockSize;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            #region Validation
            if (inputBuffer == null)
                throw new ArgumentNullException(nameof(inputBuffer));
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException(nameof(inputOffset), "Need non negative num");
            if (inputCount < 0 || inputCount > inputBuffer.Length)
                throw new ArgumentException("Argument invalid value");
            if (inputBuffer.Length - inputCount < inputOffset)
                throw new ArgumentException("Argument invalid offset length");
            if (mode == Mode.Decrypt && inputCount != InputBlockSize && inputCount != 0)
                throw new CryptographicException("Not full final block");
            #endregion

            if (inputCount == 0)
                return new byte[0];

            var block = new byte[InputBlockSize];
            Buffer.BlockCopy(inputBuffer, inputOffset, block, 0, inputCount);

            var resultBlock = TransformCBC(block);
            var outputBuffer = new byte[OutputBlockSize];
            Buffer.BlockCopy(resultBlock, 0, outputBuffer, 0, OutputBlockSize);

            return outputBuffer;
        }

        private byte[] TransformCBC(byte[] inputBlock)
        {
            ulong block = Utils.Join8bitsTo64bist(inputBlock);
            if (mode == Mode.Encrypt)
                block ^= cbcBuffer;

            ulong resultBlock = DESAlgorithm(block);

            if (mode == Mode.Encrypt)
            {
                cbcBuffer = resultBlock;
            }
            if (mode == Mode.Decrypt)
            {
                resultBlock ^= cbcBuffer;
                cbcBuffer = block;
            }
            return Utils.Split64bitsTo8bits(resultBlock);
        }

        private ulong DESAlgorithm(ulong block)
        {
            Utils.Split64bitsTo32Bits(
                InitialPermutation(block),
                out uint left, out uint right
            );
            FeisteCipher(ref left, ref right);
            return FinalPermutation(
                Utils.Join32bitsTo64bits(left, right)
            );
        }

        private void FeisteCipher(ref uint left, ref uint right)
        {
            switch (mode)
            {
                case Mode.Encrypt:
                    for (int round = 0; round < 16; ++round)
                        FeistelCipherRound(ref left, ref right, keys48b[round]);
                    Utils.Swap(ref left, ref right);
                    break;
                case Mode.Decrypt:
                    for (int round = 15; round >= 0; --round)
                        FeistelCipherRound(ref left, ref right, keys48b[round]);
                    Utils.Swap(ref left, ref right);
                    break;
            }
        }

        private void FeistelCipherRound(ref uint left, ref uint right, ulong key48b)
        {
            uint tmp = right;
            right = left ^ FeistelFunction(right, key48b);
            left = tmp;
        }

        private uint FeistelFunction(uint block32b, ulong key48b)
        {
            ulong block48b = ExpansionPermutation(block32b);
            block48b ^= key48b;
            block32b = Substitution(block48b);
            return Permutation(block32b);
        }

        private ulong ExpansionPermutation(uint block32b)
        {
            ulong block48b = 0;
            for (int i = 0; i < 48; i++)
                block48b |= (ulong)((block32b >> (32 - TB.EP[i])) & 0x01) << (63 - i);
            return block48b;
        }

        private uint Substitution(ulong block48b)
        {
            var blocks6b = Utils.Split48bitsTo6Bits(block48b);
            var blocks4b = new byte[4];
            byte eb;
            byte mb;
            for (int i = 0, j = 0; i < 8; i += 2, j++)
            {
                eb = Utils.ExternalBits(blocks6b[i]);
                mb = Utils.MiddleBits(blocks6b[i]);
                blocks4b[j] = TB.S[i, eb, mb];

                eb = Utils.ExternalBits(blocks6b[i + 1]);
                mb = Utils.MiddleBits(blocks6b[i + 1]);
                blocks4b[j] = (byte)(blocks4b[j] << 4 | TB.S[i + 1, eb, mb]);
            }
            return Utils.Join4bitsTo32bits(blocks4b);
        }

        private uint Permutation(uint block32b)
        {
            uint result = 0;
            for (int i = 0; i < 32; i++)
                result |= ((block32b >> (32 - TB.P[i])) & 0x01) << (31 - i);
            return result;
        }

        private ulong InitialPermutation(ulong block64b)
        {
            ulong result = 0;
            for (int i = 0; i < 64; i++)
                result |= ((block64b >> (64 - TB.IP[i])) & 0x01) << (63 - i);
            return result;
        }

        private ulong FinalPermutation(ulong block64b)
        {
            ulong result = 0;
            for (int i = 0; i < 64; i++)
                result |= ((block64b >> (64 - TB.FP[i])) & 0x01) << (63 - i);
            return result;
        }

        private ulong[] KeyExpansion(byte[] key)
        {
            ulong key64b = Utils.Join8bitsTo64bist(key);
            KeyPermutation(key64b, out uint c, out uint d);
            return GenerateSubKeys(c, d);
        }

        private void KeyPermutation(ulong key64b, out uint keyC28b, out uint keyD28b)
        {
            keyC28b = 0;
            keyD28b = 0;
            for (int i = 0; i < 28; i++)
            {
                keyC28b |= (uint)(key64b >> (64 - TB.KCP[i]) & 0x01) << (31 - i);
                keyD28b |= (uint)(key64b >> (64 - TB.KDP[i]) & 0x01) << (31 - i);
            }
        }

        private ulong[] GenerateSubKeys(uint keyC28b, uint keyD28b)
        {
            ulong[] keys48b = new ulong[16];
            for (int i = 0; i < 16; i++)
            {
                keyC28b = Utils.LShift28bitCyclic(keyC28b, TB.KS[i]);
                keyD28b = Utils.LShift28bitCyclic(keyD28b, TB.KS[i]);
                ulong block56b = Utils.Join28bitsTo64bits(keyC28b, keyD28b);
                keys48b[i] = KeyContractionPermutation(block56b);
            }
            return keys48b;
        }

        private ulong KeyContractionPermutation(ulong block56b)
        {
            ulong block48b = 0;
            for (int i = 0; i < 48; i++)
                block48b |= ((block56b >> (64 - TB.CP[i])) & 0x01) << (63 - i);
            return block48b;
        }
    }
}
