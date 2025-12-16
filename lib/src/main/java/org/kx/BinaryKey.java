package org.kx;

// Fixed

import java.math.BigInteger;
import java.util.Arrays;

public class BinaryKey {

   private static boolean is8thBitSet(byte in) {
      return (in & 128) > 0;
   }

   public static KxKeyData parseDER(byte[] in) {
      int offset = 0;
      if (in[offset] != 48) {
         return null;
      } else {
         int var12 = 4;
         if (in[var12] == 2 && in[var12 + 1] == 1 && in[var12 + 2] == 0) {
            var12 = (byte)7;
            BigInteger n = getBigInteger(in, var12);
            var12 = getNextOffset(in, var12);
            BigInteger e = getBigInteger(in, var12);
            var12 = getNextOffset(in, var12);
            BigInteger d = getBigInteger(in, var12);
            var12 = getNextOffset(in, var12);
            BigInteger p = getBigInteger(in, var12);
            var12 = getNextOffset(in, var12);
            BigInteger q = getBigInteger(in, var12);
            var12 = getNextOffset(in, var12);
            BigInteger dp = getBigInteger(in, var12);
            var12 = getNextOffset(in, var12);
            BigInteger dq = getBigInteger(in, var12);
            var12 = getNextOffset(in, var12);
            BigInteger qInv = getBigInteger(in, var12);
            return new KxKeyData(2048, n, e, d, p, q, dp, dq, qInv);
         } else {
            return null;
         }
      }
   }

   private static BigInteger getBigInteger(byte[] in, int offset) {
      int length = 0;
      byte lengthLength = 0;
      if (in[offset] != 2) {
         return null;
      } else {
         lengthLength = getLengthLength(in, offset);
         length = getLength(in, offset, lengthLength);
         BigInteger p;
         if ((byte)(in[offset + 1] & 128) != 0) {
            p = new BigInteger(1, Arrays.copyOfRange(in, offset + lengthLength + 2, offset + lengthLength + 2 + length));
         } else {
            p = new BigInteger(1, Arrays.copyOfRange(in, offset + lengthLength + 1, offset + lengthLength + 1 + length));
         }

         return p;
      }
   }

   private static int getNextOffset(byte[] in, int currentOffset) {
      byte llen = getLengthLength(in, currentOffset);
      int length = getLength(in, currentOffset, llen);
      int offset;
      if (is8thBitSet(in[currentOffset + 1])) {
         offset = currentOffset + 2 + llen + length;
      } else {
         offset = currentOffset + 1 + llen + length;
      }

      return offset;
   }

   private static byte getLengthLength(byte[] in, int offset) {
      byte lengthLength;
      if (is8thBitSet(in[offset + 1])) {
         lengthLength = (byte)(in[offset + 1] ^ 128);
      } else {
         lengthLength = 1;
      }

      return lengthLength;
   }

   private static int getLength(byte[] in, int offset, byte lengthLength) {
      int length = 0;
      if (is8thBitSet(in[offset + 1])) {
         if (lengthLength < 1 || lengthLength > 3) {
            return -1;
         }

         int shift = 0;

         for (int i = 0; i < lengthLength; i++) {
            shift = (in[offset + 1 + lengthLength - i] & 255) << 8 * i;
            length |= shift;
         }
      } else {
         length = in[offset + 1];
      }

      return length;
   }

}
