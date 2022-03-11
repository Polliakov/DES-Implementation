using System.Security.Cryptography;

namespace DESImplementation
{
    internal static class Utils
    {
        public static byte ExternalBits(byte block6b)
        {
            return (byte)(block6b >> 6 & 0x02 | block6b >> 2 & 0x01);
        }

        public static byte MiddleBits(byte block6b)
        {
            return (byte)(block6b >> 3 & 0x0F);
        }

        public static void Split64bitsTo32Bits(ulong block64b, out uint blockL, out uint blockR)
        {
            blockL = (uint)(block64b >> 32);
            blockR = (uint)block64b;
        }

        public static byte[] Split64bitsTo8bits(ulong block64b)
        {
            var blocks8b = new byte[8];
            for (int i = 0; i < 8; i++)
                blocks8b[i] = (byte)(block64b >> ((7 - i) * 8));
            return blocks8b;
        }

        public static byte[] Split48bitsTo6Bits(ulong block48b)
        {
            var blocks6b = new byte[8];
            for (byte i = 0; i < 8; i++)
                blocks6b[i] = (byte)((block48b >> (58 - (i * 6))) << 2);
            return blocks6b;
        }

        public static ulong Join32bitsTo64bits(uint blockL, uint blockR)
        {
            return (ulong)blockL << 32 | blockR;
        }

        public static ulong Join28bitsTo64bits(uint blockL, uint blockR)
        {
            uint mask28b = 0xFFFFFFF0;
            return ((ulong)(blockL >> 4) << 32 | blockR & mask28b) << 4;
        }

        public static ulong Join8bitsTo64bist(byte[] blocks8b)
        {
            ulong block64b = 0;
            for (int i = 0; i < 8; i++)
                block64b = block64b << 8 | blocks8b[i];
            return block64b;
        }

        public static uint Join4bitsTo32bits(byte[] blocks4b)
        {
            uint block32b = 0;
            for (int i = 0; i < 4; i++)
                block32b = block32b << 8 | blocks4b[i];
            return block32b;
        }

        public static uint LShift28bitCyclic(uint x, int shift)
        {
            uint mask28b = 0xFFFFFFF0;
            return ((x & mask28b) << shift | x >> (28 - shift)) & mask28b;
        }

        public static void Swap(ref uint first, ref uint second)
        {
            first ^= second;
            second ^= first;
            first ^= second;
        }
    }
}
