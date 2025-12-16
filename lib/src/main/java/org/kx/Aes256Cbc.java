package org.kx;

// Fixed

import java.util.Arrays;

public class Aes256Cbc extends Aes {
   private static final int BLOCKSIZE = 16;
   private static final double BLOCKSIZE_D = 16.0;

   public Aes256Cbc() {
   }

   public static byte[] xorData(byte[] pad, byte[] msg) {
      if (msg != null && pad != null && msg.length == BLOCKSIZE && pad.length == BLOCKSIZE) {
         byte[] ret = new byte[BLOCKSIZE];

         for (int i = 0; i < BLOCKSIZE; i++) {
            ret[i] = (byte)(msg[i] ^ pad[i]);
         }

         return ret;
      } else {
         return null;
      }
   }

   public static byte[] padBlock(byte[] in) {
      if (in.length == BLOCKSIZE) {
         return in;
      } else if (in.length > BLOCKSIZE) {
         return null;
      } else {
         byte[] ret = new byte[BLOCKSIZE];
         byte padValue = (byte)(BLOCKSIZE - in.length);
         System.arraycopy(in, 0, ret, 0, in.length);

         for (int i = in.length; i < BLOCKSIZE; i++) {
            ret[i] = padValue;
         }

         return ret;
      }
   }

   public byte[] unPad(byte[] in) {
      if (in != null && in.length == BLOCKSIZE) {
         int len = in.length;
         int padValue = in[len - 1];
         if (padValue >= 1 && padValue <= BLOCKSIZE) {
            for (int i = len - padValue; i < len; i++) {
               if (in[i] != padValue) {
                  return in;
               }
            }

            byte[] ret = new byte[len - padValue];
            System.arraycopy(in, 0, ret, 0, len - padValue);
            return ret;
         } else {
            return in;
         }
      } else {
         return null;
      }
   }


   public byte[] decrypt(byte[] enc, byte[] key, byte[] iv) {
      if (key != null && iv != null && enc != null && key.length == 32 && iv.length == BLOCKSIZE && enc.length % BLOCKSIZE == 0) {
         int iteration = enc.length / BLOCKSIZE;
         byte[] msg = new byte[BLOCKSIZE * iteration];
         byte[] buf = new byte[BLOCKSIZE];
         byte[] xorPad = new byte[BLOCKSIZE];
         int lastBlockMsgLen = 0;

         for (int i = 0; i < iteration; i++) {
            System.arraycopy(enc, BLOCKSIZE * i, buf, 0, BLOCKSIZE);
            buf = super.decBlock(key, buf);
            if (i == 0) {
               System.arraycopy(iv, 0, xorPad, 0, BLOCKSIZE);
            } else {
               System.arraycopy(enc, (i - 1) * BLOCKSIZE, xorPad, 0, BLOCKSIZE);
            }

            buf = xorData(xorPad, buf);
            System.arraycopy(buf, 0, msg, BLOCKSIZE * i, BLOCKSIZE);
         }

         System.arraycopy(msg, BLOCKSIZE * (iteration - 1), buf, 0, BLOCKSIZE);
         lastBlockMsgLen = BLOCKSIZE - getLengthOfPadding(buf);
         return lastBlockMsgLen == 0 ? Arrays.copyOfRange(msg, 0, BLOCKSIZE * (iteration - 1)) : Arrays.copyOfRange(msg, 0, BLOCKSIZE * (iteration - 1) + lastBlockMsgLen);
      } else {
         return null;
      }
   }

   public static int getLengthOfPadding(byte[] in) {
      if (in != null && in.length == BLOCKSIZE) {
         int len = in.length;
         int padValue = in[len - 1];
         if (padValue >= 1 && padValue <= BLOCKSIZE) {
            for (int i = len - padValue; i < len; i++) {
               if (in[i] != padValue) {
                  return -1;
               }
            }

            return padValue;
         } else {
            return -1;
         }
      } else {
         return -1;
      }
   }

   public byte[] encrypt(byte[] data, byte[] key, byte[] iv) {
      if (key != null && iv != null && data != null && key.length == 32 && iv.length == BLOCKSIZE && data.length >= 1) {
         int iteration = (int)Math.floor(1.0 * data.length / BLOCKSIZE_D) + 1;
         byte[] msgbuf = new byte[BLOCKSIZE];
         byte[] xorPad = new byte[BLOCKSIZE];
         byte[] enc = new byte[BLOCKSIZE * iteration];

         for (int i = 0; i < iteration; i++) {
            if (i == iteration - 1) {
               if (data.length % BLOCKSIZE != 0) {
                  int tl = data.length % BLOCKSIZE;
                  byte[] tmp = new byte[tl];
                  System.arraycopy(data, i * BLOCKSIZE, tmp, 0, tl);
                  msgbuf = padBlock(tmp);
               } else {
                  Arrays.fill(msgbuf, (byte)BLOCKSIZE);
               }
            } else {
               System.arraycopy(data, i * BLOCKSIZE, msgbuf, 0, BLOCKSIZE);
            }

            if (i == 0) {
               System.arraycopy(iv, 0, xorPad, 0, BLOCKSIZE);
            } else {
               System.arraycopy(enc, (i - 1) * BLOCKSIZE, xorPad, 0, BLOCKSIZE);
            }

            msgbuf = xorData(xorPad, msgbuf);
            System.arraycopy(super.encBlock(key, msgbuf), 0, enc, BLOCKSIZE * i, BLOCKSIZE);
         }

         return enc;
      } else {
         return null;
      }
   }

}
