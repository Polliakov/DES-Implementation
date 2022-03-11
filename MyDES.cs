using System;

namespace DES_Implementation
{
    public class MyDES
    {
        public enum Mode
        {
            Encrypt,
            Decrypt,
        }

        public byte[] TransformBlock(byte[] from, Mode mode, byte[] key)
        {
            if (from is null || key is null)
                throw new ArgumentNullException("Null arguments");
            if (from.Length != 8 || key.Length != 8)
                throw new ArgumentException("Invalid arguments");

            ulong[] keys48b = KeyExpansion(key);

            Utils.Split64bitsTo32Bits(
                InitialPermutation(Utils.Join8bitsTo64bist(from)),
                out uint left, out uint right
            );

            FeisteCipher(mode, ref left, ref right, keys48b);

            return Utils.Split64bitsTo8bits(
                FinalPermutation(Utils.Join32bitsTo64bits(left, right))
            );
        }

        private void FeisteCipher(Mode mode, ref uint left, ref uint right, ulong[] keys48b)
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
