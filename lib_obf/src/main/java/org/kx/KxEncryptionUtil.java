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
               this.skeySpec = new SecretKeySpec(Configuration.getKlmKey(), zqw.puS(new byte[] {(byte)2,(byte)-23,(byte)-88,(byte)-102,(byte)-122}));
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
         cipher = Cipher.getInstance(zqw.pQH(new byte[] {(byte)96,(byte)-11,(byte)-76,(byte)29,(byte)-24,(byte)49,(byte)-62,(byte)-94,(byte)5,(byte)-110,(byte)34,(byte)62,(byte)-68,(byte)102,(byte)-8,(byte)-104,(byte)59,(byte)-85,(byte)75,(byte)-17}));
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
      LOGGER.info(zqw.ph(new byte[] {(byte)-61,(byte)-8,(byte)-84,(byte)124,(byte)95,(byte)42,(byte)76,(byte)-3,(byte)-55,(byte)-84,(byte)-117,(byte)-35,(byte)110,(byte)88,(byte)116,(byte)20,(byte)-32,(byte)-56,(byte)-70,(byte)-100,(byte)114,(byte)107,(byte)28,(byte)52,(byte)19,(byte)-32,(byte)-61,(byte)-84,(byte)-115,(byte)98,(byte)4,(byte)40,(byte)45,(byte)91,(byte)-29,(byte)-56,(byte)-14,(byte)-126,(byte)127}), duration);
      return result;
   }

   public String decryptMessage(String messge) throws KxDataEncryptException {
      long start = System.currentTimeMillis();
      String result = zqw.pQg(new byte[] {(byte)118,(byte)-37});
      SecretKeySpec keySpec = this.getSkeySpec();

      Cipher cipher;
      try {
         cipher = Cipher.getInstance(zqw.pRY(new byte[] {(byte)-77,(byte)93,(byte)28,(byte)-94,(byte)34,(byte)-44,(byte)-58,(byte)73,(byte)-37,(byte)27,(byte)-126,(byte)121,(byte)-82,(byte)27,(byte)-76,(byte)59,(byte)-115,(byte)26,(byte)-109,(byte)-32}));
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
      LOGGER.info(zqw.pK(new byte[] {(byte)26,(byte)-60,(byte)-112,(byte)-101,(byte)77,(byte)43,(byte)92,(byte)-34,(byte)-73,(byte)105,(byte)95,(byte)66,(byte)-28,(byte)-47,(byte)-52,(byte)126,(byte)45,(byte)21,(byte)-42,(byte)-85,(byte)112,(byte)90,(byte)124,(byte)-25,(byte)-35,(byte)-107,(byte)103,(byte)35,(byte)23,(byte)-5,(byte)-20,(byte)-109,(byte)91,(byte)118,(byte)-1,(byte)-49,(byte)-64,(byte)99,(byte)79}), duration);
      return result;
   }


}
