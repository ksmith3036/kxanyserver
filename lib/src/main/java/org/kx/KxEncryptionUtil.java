package org.kx;

// Fixed

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KxEncryptionUtil {
   private static final Logger LOGGER = LoggerFactory.getLogger(KxEncryptionUtil.class.getName());
   private volatile SecretKeySpec skeySpec;
   // TODO Remove
   //@Value("#{restProperties['klm.secret.key']}")
   // oCOsq2djfaKzrCkirP0tiQ==

   private SecretKeySpec getSkeySpec() {
      if (this.skeySpec == null) {
         synchronized (this) {
            if (this.skeySpec == null) {
               this.skeySpec = new SecretKeySpec(Configuration.getKlmKey(), "AES");
               //this.skeySpec = new SecretKeySpec(this.secretKey, "AES");
            }
         }
      }

      return this.skeySpec;
   }

   private byte[] ivBytes = new byte[]{0, 18, 0, 0, 16, 1, 48, 96, 0, 0, 48, 0, 0, 32, 0, 0};

   public String encryptMessage(String message) throws KxDataEncryptException {
      long start = System.currentTimeMillis();
      SecretKeySpec keySpec = this.getSkeySpec();

      Cipher cipher;
      try {
         cipher = Cipher.getInstance("AES/CFB8/NoPadding");
         cipher.init(1, keySpec, new IvParameterSpec(this.ivBytes));
      } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException var10) {
         throw new KxDataEncryptException(var10.getMessage());
      }

      String result;
      try {
         result = Base64.encodeBase64String(cipher.doFinal(message.getBytes()));
      } catch (BadPaddingException | IllegalBlockSizeException var9) {
         throw new KxDataEncryptException(var9.getMessage());
      }

      long duration = System.currentTimeMillis() - start;
      LOGGER.info("Time took to encrypt message is {} ms", duration);
      return result;
   }

   public String decryptMessage(String messge) throws KxDataEncryptException {
      long start = System.currentTimeMillis();
      String result = "";
      SecretKeySpec keySpec = this.getSkeySpec();

      Cipher cipher;
      try {
         cipher = Cipher.getInstance("AES/CFB8/NoPadding");
         cipher.init(2, keySpec, new IvParameterSpec(this.ivBytes));
      } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException var9) {
         throw new KxDataEncryptException(var9.getMessage());
      }

      try {
         byte[] bytes = Base64.decodeBase64(messge);
         if (bytes != null) {
            result = new String(cipher.doFinal(bytes));
         }
      } catch (BadPaddingException | IllegalBlockSizeException var10) {
         throw new KxDataEncryptException(var10.getMessage());
      }

      long duration = System.currentTimeMillis() - start;
      LOGGER.info("Time took to decrypt message is {} ms", duration);
      return result;
   }


}
