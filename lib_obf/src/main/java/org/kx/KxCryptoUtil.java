package org.kx;

// Fixed

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

public class KxCryptoUtil {
   private static final Logger _logger = LoggerFactory.getLogger(KxCryptoUtil.class);
   private static HashMap<String, KxKeyData> keystore;
   private static final KxCryptoUtil myself = new KxCryptoUtil();
   PKIXParameters pkixParams = null;


   private KxCryptoUtil() {
      keystore = new HashMap<>();
   }

   public static KxCryptoUtil getInstance() {
      return myself;
   }

   public static void convertAndSaveEncryptionKey(String encKey, String xsn, String encDER) {
      byte[] aesKey = DatatypeConverter.parseHexBinary(encKey);
      byte[] aesIV = Arrays.copyOfRange(aesKey, 0, 16);
      Aes256Cbc aes = new Aes256Cbc();
      byte[] encArr = DatatypeConverter.parseBase64Binary(encDER);
      byte[] derKey = aes.decrypt(encArr, aesKey, aesIV);
      KxKeyData kd = BinaryKey.parseDER(derKey);
      keystore.put(xsn, kd);
   }

   public static void convertAndSaveEncryptionKey(String xsn, String encDER) {
      convertAndSaveEncryptionKey(zqw.pRr(new byte[] {(byte)115,(byte)-25,(byte)-45,(byte)-89,(byte)116,(byte)-58,(byte)-62,(byte)102,(byte)57,(byte)-128,(byte)102,(byte)61,(byte)-34,(byte)8,(byte)122,(byte)-81,(byte)77,(byte)26,(byte)-75,(byte)-73,(byte)3,(byte)-43,(byte)-94,(byte)119,(byte)-57,(byte)-106,(byte)127,(byte)-53,(byte)-99,(byte)107,(byte)51,(byte)-115,(byte)13,(byte)126,(byte)-90,(byte)68,(byte)18,(byte)-19,(byte)-27,(byte)80,(byte)-39,(byte)-13,(byte)91,(byte)-37,(byte)-81,(byte)40,(byte)-102,(byte)-56,(byte)108,(byte)108,(byte)-45,(byte)94,(byte)38,(byte)-95,(byte)75,(byte)21,(byte)-75,(byte)-74,(byte)28,(byte)-25,(byte)-75,(byte)94,(byte)-118,(byte)-93,(byte)123,(byte)-56}), xsn, encDER);
   }

   public static void convertAndSaveELMEncryptionKey(String xsn, String encDER) {
      convertAndSaveEncryptionKey(zqw.pQR(new byte[] {(byte)-10,(byte)74,(byte)44,(byte)-30,(byte)-96,(byte)101,(byte)91,(byte)31,(byte)-120,(byte)-60,(byte)84,(byte)14,(byte)-104,(byte)-113,(byte)71,(byte)7,(byte)-63,(byte)-22,(byte)123,(byte)99,(byte)-96,(byte)-24,(byte)58,(byte)124,(byte)-69,(byte)-16,(byte)52,(byte)91,(byte)30,(byte)-120,(byte)-57,(byte)82,(byte)17,(byte)-107,(byte)-113,(byte)67,(byte)86,(byte)-112,(byte)-23,(byte)126,(byte)105,(byte)-89,(byte)-29,(byte)108,(byte)47,(byte)-65,(byte)-94,(byte)97,(byte)115,(byte)74,(byte)-115,(byte)-57,(byte)87,(byte)67,(byte)-56,(byte)-120,(byte)30,(byte)87,(byte)-106,(byte)-70,(byte)126,(byte)109,(byte)-12,(byte)-26,(byte)35,(byte)41}), xsn, encDER);
   }

   public byte[] getSessionKey(HttpServletRequest hreq) {
      _logger.info(zqw.pRS(new byte[] {(byte)20,(byte)44,(byte)111,(byte)-34,(byte)73,(byte)-51,(byte)88,(byte)-59,(byte)66,(byte)-53,(byte)12,(byte)-33,(byte)73,(byte)-33,(byte)95,(byte)-59,(byte)67,(byte)-62,(byte)12,(byte)-57,(byte)73,(byte)-43,(byte)12,(byte)-54,(byte)94,(byte)-61,(byte)65,(byte)-116,(byte)68,(byte)-55,(byte)77,(byte)-56,(byte)73,(byte)-34,(byte)95}));
      String rnaVersion = hreq.getHeader(RnaHeader.XSS.getValue());
      String serialKey = hreq.getHeader(RnaHeader.XSN.getValue());
      String encSessionData = hreq.getHeader(RnaHeader.XED.getValue());
      String encSessionKey = hreq.getHeader(RnaHeader.XSK.getValue());
      byte[] sk = null;
      if (!RnaVersion.V4A.getValue().equalsIgnoreCase(rnaVersion) && !RnaVersion.V4B.getValue().equalsIgnoreCase(rnaVersion)) {
         sk = this.getSessionKey(serialKey, encSessionKey);
      } else {
         sk = this.getOAEPSessionKey(serialKey, encSessionData);
      }

      return sk;
   }

   private String printArr(byte[] arr) {
      String ret = zqw.pQm(new byte[] {(byte)-127,(byte)37});
      if (arr != null && arr.length >= 1) {
         int printLen = 0;
         if (arr.length > 500) {
            printLen = 500;
         } else {
            printLen = arr.length;
         }

         for (int i = 0; i < printLen; i++) {
            ret = ret + String.format(zqw.pv(new byte[] {(byte)81,(byte)-87,(byte)-116,(byte)-98,(byte)-127,(byte)-32}), arr[i]);
         }

         return ret;
      } else {
         return zqw.ptA(new byte[] {(byte)126,(byte)72});
      }
   }

   public String getEncryptedResponse(byte[] resBytes, String rnaVersion, byte[] sessionKey, String serialNo, HttpServletResponse hres) {
      String encRetMsg = null;
      if (resBytes != null && resBytes.length > 0) {
         _logger.info(zqw.pQJ(new byte[] {(byte)-74,(byte)-6,(byte)-88,(byte)7,(byte)-71,(byte)66,(byte)-11,(byte)108,(byte)25,(byte)-73,(byte)26,(byte)-16,(byte)68,(byte)51,(byte)-6,(byte)52,(byte)-49,(byte)96,(byte)9,(byte)-117,(byte)37,(byte)-36,(byte)32,(byte)-94,(byte)-111,(byte)47}), rnaVersion);
         if (rnaVersion.equalsIgnoreCase(RnaVersion.V1.getValue())) {
            encRetMsg = this.getEncryptedData(Arrays.copyOfRange(sessionKey, 0, 32), Arrays.copyOfRange(sessionKey, 32, 48), resBytes);
         } else if (!rnaVersion.equalsIgnoreCase(RnaVersion.V2.getValue()) && !rnaVersion.equalsIgnoreCase(RnaVersion.V3.getValue())) {
            if (!RnaVersion.V4A.getValue().equalsIgnoreCase(rnaVersion) && !RnaVersion.V4B.getValue().equalsIgnoreCase(rnaVersion)) {
               encRetMsg = this.getEncryptedData(sessionKey, resBytes);
            } else {
               SecureRandom sr = new SecureRandom();
               byte[] retIV = new byte[12];
               sr.nextBytes(retIV);
               encRetMsg = this.getGCMEncryptedData(sessionKey, retIV, resBytes);
               byte[] signature = this.getServerSignature(serialNo, DatatypeConverter.parseBase64Binary(encRetMsg));
               byte[] ed = new byte[retIV.length + signature.length];
               System.arraycopy(retIV, 0, ed, 0, retIV.length);
               System.arraycopy(signature, 0, ed, retIV.length, signature.length);
               hres.addHeader(RnaHeader.XED.getValue(), DatatypeConverter.printBase64Binary(ed));
            }
         } else {
            BigInteger bigIV = new BigInteger(Arrays.copyOfRange(sessionKey, 32, 48)).add(new BigInteger(zqw.pE(new byte[] {(byte)-90,(byte)1,(byte)48})));
            byte[] srcIV = bigIV.toByteArray();
            byte[] dstIV = new byte[16];
            if (srcIV.length <= dstIV.length) {
               System.arraycopy(srcIV, 0, dstIV, dstIV.length - srcIV.length, srcIV.length);
            } else {
               System.arraycopy(srcIV, 0, dstIV, 0, 16);
            }

            encRetMsg = this.getEncryptedData(Arrays.copyOfRange(sessionKey, 0, 32), dstIV, resBytes);
         }
      }

      return encRetMsg;
   }

   public byte[] getSessionKey(String sn, String sk) {
      _logger.debug(zqw.pRV(new byte[] {(byte)16,(byte)23,(byte)84,(byte)-24,(byte)120,(byte)-63,(byte)87,(byte)-61,(byte)9,(byte)-33,(byte)74,(byte)-63,(byte)70,(byte)-47,(byte)84,(byte)-48,(byte)97,(byte)-81,(byte)34,(byte)-77,(byte)109,(byte)-74,(byte)60,(byte)-92,(byte)99,(byte)-4,(byte)36,(byte)-97,(byte)73,(byte)-109,(byte)22}), sn, sk);
      if (!keystore.containsKey(sn)) {
         _logger.info(zqw.py(new byte[] {(byte)-118,(byte)-97,(byte)-46,(byte)-50,(byte)-36,(byte)-60,(byte)-42,(byte)-87,(byte)-88,(byte)-9,(byte)-76,(byte)-126,(byte)-106,(byte)-51,(byte)-33,(byte)124,(byte)114}), sn);
         return null;
      } else {
         byte[] encSK = DatatypeConverter.parseBase64Binary(sk);
         KxKeyData key = keystore.get(sn);
         if (encSK.length > key.getBits()) {
            _logger.warn(zqw.ptA(new byte[] {(byte)33,(byte)-110,(byte)-59,(byte)22,(byte)89,(byte)102,(byte)-67,(byte)-116,(byte)19,(byte)53,(byte)81,(byte)-121,(byte)-89,(byte)-1,(byte)15,(byte)28,(byte)98,(byte)-123,(byte)-36,(byte)-29,(byte)34,(byte)64}));
            return null;
         } else {
            BigInteger c = new BigInteger(1, encSK);
            BigInteger cdp = c.modPow(key.getDp(), key.getP());
            BigInteger cdq = c.modPow(key.getDq(), key.getQ());
            BigInteger h = cdp.subtract(cdq).multiply(key.getQinv()).mod(key.getP());
            BigInteger m = cdq.add(h.multiply(key.getQ())).mod(key.getN());
            byte[] paddedMsg = m.toByteArray();
            int msgIndex = 0;

            for (int i = 2; i < paddedMsg.length; i++) {
               if (paddedMsg[i] == 0) {
                  msgIndex = i + 1;
                  break;
               }
            }

            _logger.debug(zqw.puz(new byte[] {(byte)-21,(byte)9,(byte)89,(byte)-97,(byte)-105,(byte)-116,(byte)-72,(byte)-74,(byte)-25,(byte)-48,(byte)-44,(byte)-56,(byte)-4,(byte)-28,(byte)-19,(byte)64,(byte)79,(byte)31,(byte)36,(byte)110,(byte)46,(byte)75,(byte)74,(byte)107,(byte)121,(byte)104,(byte)100,(byte)-114,(byte)-47,(byte)-64,(byte)-82,(byte)-73}), paddedMsg.length, msgIndex);
            _logger.debug(zqw.pk(new byte[] {(byte)-127,(byte)-28,(byte)-73,(byte)97,(byte)87,(byte)55,(byte)13,(byte)-21,(byte)-54,(byte)-28,(byte)-81,(byte)97,(byte)93,(byte)126,(byte)68,(byte)-1,(byte)-39}), this.printArr(Arrays.copyOfRange(paddedMsg, msgIndex, paddedMsg.length)));
            return Arrays.copyOfRange(paddedMsg, msgIndex, paddedMsg.length);
         }
      }
   }

   public String getDecryptedData(byte[] sk, String data) {
      return this.getDecryptedData(sk, Arrays.copyOfRange(sk, 0, 16), data);
   }

   public String getDecryptedData(byte[] sk, byte[] iv, String data) {
      _logger.debug(zqw.ptc(new byte[] {(byte)99,(byte)-113,(byte)-53,(byte)61,(byte)66,(byte)-104,(byte)-54,(byte)12,(byte)49,(byte)46,(byte)-77,(byte)-63,(byte)29,(byte)83,(byte)-63,(byte)-28,(byte)-10,(byte)43}), data);
      Aes256Cbc aes = new Aes256Cbc();
      byte[] encStr = DatatypeConverter.parseBase64Binary(data);
      if (sk.length == 32 && encStr.length % 16 == 0) {
         byte[] msgArr = aes.decrypt(encStr, sk, iv);
         String msg = new String(msgArr);
         _logger.debug(zqw.pu6(new byte[] {(byte)-109,(byte)92,(byte)24,(byte)60,(byte)53,(byte)33,(byte)41,(byte)61,(byte)62,(byte)34,(byte)32,(byte)97,(byte)90,(byte)90,(byte)76,(byte)84,(byte)8,(byte)15,(byte)87,(byte)84}), msg);
         return msg;
      } else {
         _logger.error(zqw.pQB(new byte[] {(byte)-69,(byte)88,(byte)29,(byte)-37,(byte)113,(byte)29,(byte)-75,(byte)89,(byte)-14,(byte)-118,(byte)47,(byte)-13,(byte)-38,(byte)59,(byte)-47,(byte)127,(byte)9,(byte)-65,(byte)64,(byte)-91,(byte)-117,(byte)76,(byte)-68,(byte)-114,(byte)36,(byte)-36,(byte)126,(byte)10,(byte)-22,(byte)78,(byte)-22,(byte)-63,(byte)122,(byte)-2,(byte)-101,(byte)39,(byte)-53,(byte)127,(byte)24}));
         return null;
      }
   }

   public String getDecryptedSignedData(byte[] sk, byte[] iv, String data) {
      _logger.debug(zqw.pY(new byte[] {(byte)-52,(byte)-114,(byte)-54,(byte)-57,(byte)-43,(byte)-72,(byte)-89,(byte)-126,(byte)114,(byte)58,(byte)93,(byte)43,(byte)49,(byte)4,(byte)27,(byte)-10,(byte)-122,(byte)-34,(byte)-81,(byte)-106,(byte)-105,(byte)48,(byte)62,(byte)73,(byte)59}), data);
      Aes256Cbc aes = new Aes256Cbc();
      byte[] encStr = DatatypeConverter.parseBase64Binary(data);
      if (sk.length == 32 && encStr.length % 16 == 0) {
         byte[] msgArr = aes.decrypt(encStr, sk, iv);
         String msg = this.isValidSignedData(msgArr);
         _logger.debug(zqw.ptf(new byte[] {(byte)-118,(byte)58,(byte)126,(byte)99,(byte)-79,(byte)-20,(byte)19,(byte)70,(byte)118,(byte)-85,(byte)-2,(byte)70,(byte)118,(byte)-97,(byte)-66,(byte)-9,(byte)66,(byte)6,(byte)-119,(byte)-81,(byte)-11,(byte)48,(byte)79,(byte)-110,(byte)-21,(byte)-76,(byte)122,(byte)93,(byte)-113}), msg);
         return msg;
      } else {
         _logger.error(zqw.ptv(new byte[] {(byte)-60,(byte)81,(byte)20,(byte)105,(byte)-34,(byte)1,(byte)80,(byte)-81,(byte)-31,(byte)34,(byte)110,(byte)-39,(byte)77,(byte)79,(byte)-68,(byte)-31,(byte)34,(byte)-113,(byte)-39,(byte)71,(byte)116,(byte)-96,(byte)-87,(byte)72,(byte)-121,(byte)-60,(byte)15,(byte)112,(byte)-31,(byte)-93,(byte)85,(byte)-118,(byte)-53,(byte)60,(byte)101,(byte)-81,(byte)71,(byte)19,(byte)-110,(byte)-30,(byte)121,(byte)43,(byte)-93,(byte)24,(byte)73,(byte)-102,(byte)-93,(byte)111,(byte)126,(byte)-58}), sk.length, encStr.length);
         return null;
      }
   }

   public String getEncryptedData(byte[] sk, byte[] data) {
      return this.getEncryptedData(sk, Arrays.copyOfRange(sk, 0, 16), data);
   }

   public String getEncryptedData(byte[] sk, byte[] iv, byte[] data) {
      Aes256Cbc aes = new Aes256Cbc();
      if (sk.length != 32) {
         _logger.error(zqw.pQH(new byte[] {(byte)-20,(byte)-25,(byte)-92,(byte)56,(byte)-44,(byte)96,(byte)7,(byte)-71,(byte)25,(byte)-16,(byte)-102,(byte)12,(byte)-94,(byte)92,(byte)-29,(byte)-50,(byte)56,(byte)-57,(byte)55,(byte)13,(byte)-81,(byte)47,(byte)-51,(byte)97,(byte)73,(byte)-91,(byte)65,(byte)-78,(byte)-80,(byte)54,(byte)-40,(byte)108,(byte)-8,(byte)-108,(byte)51}));
         return null;
      } else {
         byte[] msgArr = aes.encrypt(data, sk, iv);
         return DatatypeConverter.printBase64Binary(msgArr);
      }
   }

   private ByteArrayInputStream getByteArrayStream(byte[] input) {
      return new ByteArrayInputStream(input);
   }

   private PKIXParameters getPKIXParameters() throws InvalidAlgorithmParameterException {
      if (this.pkixParams != null) {
         return this.pkixParams;
      } else {
         Set<TrustAnchor> trustedCAs = new HashSet<>();
         String QACertPEM = zqw.pt7(new byte[] {(byte)-60,(byte)-76,(byte)-103,(byte)-93,(byte)69,(byte)111,(byte)49,(byte)-76,(byte)-107,(byte)-19,(byte)-51,(byte)16,(byte)24,(byte)81,(byte)-87,(byte)-108,(byte)-12,(byte)51,(byte)18,(byte)103,(byte)75,(byte)-93,(byte)-24,(byte)-45,(byte)93,(byte)103,(byte)9,(byte)-45,(byte)-11,(byte)-72,(byte)-63,(byte)47,(byte)9,(byte)94,(byte)-104,(byte)-102,(byte)-21,(byte)-63,(byte)29,(byte)88,(byte)34,(byte)-115,(byte)-123,(byte)-23,(byte)49,(byte)16,(byte)109,(byte)97,(byte)-87,(byte)-16,(byte)-43,(byte)32,(byte)29,(byte)119,(byte)-124,(byte)-111,(byte)-47,(byte)-61,(byte)16,(byte)113,(byte)122,(byte)-99,(byte)-127,(byte)-25,(byte)-80,(byte)29,(byte)119,(byte)93,(byte)-103,(byte)-123,(byte)-49,(byte)63,(byte)50,(byte)25,(byte)64,(byte)-113,(byte)-3,(byte)-48,(byte)47,(byte)49,(byte)117,(byte)-69,(byte)-103,(byte)-23,(byte)-51,(byte)26,(byte)127,(byte)108,(byte)-79,(byte)-128,(byte)-26,(byte)25,(byte)22,(byte)100,(byte)78,(byte)-89,(byte)-103,(byte)-50,(byte)53,(byte)37,(byte)92,(byte)81,(byte)-111,(byte)-28,(byte)-39,(byte)29,(byte)1,(byte)95,(byte)-95,(byte)-106,(byte)-6,(byte)-41,(byte)49,(byte)115,(byte)80,(byte)-81,(byte)-92,(byte)-18,(byte)25,(byte)14,(byte)102,(byte)127,(byte)-66,(byte)-116,(byte)-20,(byte)2,(byte)22,(byte)97,(byte)56,(byte)-94,(byte)-16,(byte)-28,(byte)41,(byte)15,(byte)94,(byte)-111,(byte)-98,(byte)-4,(byte)-58,(byte)31,(byte)91,(byte)95,(byte)-82,(byte)-112,(byte)-18,(byte)75,(byte)48,(byte)28,(byte)49,(byte)-105,(byte)-15,(byte)-60,(byte)7,(byte)61,(byte)99,(byte)-103,(byte)-127,(byte)-10,(byte)-38,(byte)55,(byte)17,(byte)81,(byte)-80,(byte)-116,(byte)-26,(byte)-42,(byte)5,(byte)97,(byte)33,(byte)-112,(byte)-96,(byte)-55,(byte)77,(byte)60,(byte)101,(byte)67,(byte)-74,(byte)-55,(byte)-50,(byte)57,(byte)6,(byte)18,(byte)-97,(byte)-69,(byte)-119,(byte)-1,(byte)5,(byte)105,(byte)86,(byte)-120,(byte)-127,(byte)-12,(byte)-63,(byte)45,(byte)112,(byte)105,(byte)-79,(byte)-122,(byte)-54,(byte)39,(byte)1,(byte)102,(byte)64,(byte)-97,(byte)-36,(byte)-34,(byte)14,(byte)43,(byte)25,(byte)-50,(byte)-99,(byte)-21,(byte)-58,(byte)32,(byte)113,(byte)84,(byte)-60,(byte)-110,(byte)-32,(byte)42,(byte)29,(byte)2,(byte)65,(byte)-94,(byte)-85,(byte)-19,(byte)58,(byte)26,(byte)105,(byte)48,(byte)-110,(byte)-30,(byte)-59,(byte)19,(byte)9,(byte)114,(byte)-105,(byte)-118,(byte)-24,(byte)-46,(byte)45,(byte)10,(byte)89,(byte)-86,(byte)-81,(byte)-40,(byte)49,(byte)2,(byte)113,(byte)56,(byte)-86,(byte)-22,(byte)-51,(byte)11,(byte)1,(byte)74,(byte)111,(byte)-83,(byte)-19,(byte)-38,(byte)45,(byte)14,(byte)81,(byte)-73,(byte)-69,(byte)-19,(byte)-59,(byte)111,(byte)109,(byte)87,(byte)-82,(byte)-82,(byte)-19,(byte)57,(byte)7,(byte)31,(byte)65,(byte)-102,(byte)-7,(byte)-4,(byte)49,(byte)27,(byte)102,(byte)-103,(byte)-106,(byte)-28,(byte)-50,(byte)39,(byte)39,(byte)87,(byte)-73,(byte)-101,(byte)-36,(byte)-73,(byte)56,(byte)97,(byte)37,(byte)-124,(byte)-91,(byte)-84,(byte)20,(byte)57,(byte)78,(byte)124,(byte)-91,(byte)-11,(byte)-39,(byte)47,(byte)63,(byte)101,(byte)-67,(byte)-25,(byte)-27,(byte)-49,(byte)38,(byte)73,(byte)111,(byte)-76,(byte)-103,(byte)-107,(byte)-42,(byte)105,(byte)86,(byte)60,(byte)-36,(byte)-70,(byte)-44,(byte)50,(byte)17,(byte)75,(byte)70,(byte)-71,(byte)-10,(byte)-60,(byte)46,(byte)7,(byte)79,(byte)-73,(byte)-111,(byte)-97,(byte)-58,(byte)10,(byte)94,(byte)78,(byte)-66,(byte)-5,(byte)-58,(byte)19,(byte)59,(byte)85,(byte)94,(byte)-79,(byte)-72,(byte)-10,(byte)45,(byte)125,(byte)122,(byte)123,(byte)-66,(byte)-124,(byte)-91,(byte)26,(byte)29,(byte)45,(byte)-75,(byte)-86,(byte)-23,(byte)-62,(byte)33,(byte)117,(byte)86,(byte)-119,(byte)-122,(byte)-12,(byte)62,(byte)23,(byte)67,(byte)71,(byte)-90,(byte)-114,(byte)-20,(byte)7,(byte)46,(byte)21,(byte)103,(byte)-67,(byte)-27,(byte)-66,(byte)45,(byte)53,(byte)123,(byte)-111,(byte)-107,(byte)-61,(byte)-55,(byte)31,(byte)8,(byte)85,(byte)-81,(byte)-107,(byte)-47,(byte)61,(byte)7,(byte)103,(byte)106,(byte)-47,(byte)-8,(byte)-57,(byte)53,(byte)8,(byte)101,(byte)-81,(byte)-115,(byte)-13,(byte)-51,(byte)82,(byte)9,(byte)88,(byte)-80,(byte)-71,(byte)-23,(byte)-11,(byte)59,(byte)81,(byte)85,(byte)-95,(byte)-123,(byte)-15,(byte)49,(byte)16,(byte)109,(byte)87,(byte)-93,(byte)-45,(byte)-1,(byte)30,(byte)60,(byte)91,(byte)-78,(byte)-68,(byte)-4,(byte)-19,(byte)93,(byte)107,(byte)94,(byte)-123,(byte)-69,(byte)-60,(byte)-18,(byte)17,(byte)68,(byte)76,(byte)-125,(byte)-76,(byte)-1,(byte)12,(byte)59,(byte)88,(byte)71,(byte)-114,(byte)-38,(byte)-91,(byte)92,(byte)49,(byte)67,(byte)-43,(byte)-116,(byte)-102,(byte)-55,(byte)7,(byte)78,(byte)36,(byte)-89,(byte)-114,(byte)-18,(byte)46,(byte)34,(byte)10,(byte)69,(byte)-85,(byte)-102,(byte)-85,(byte)59,(byte)55,(byte)127,(byte)107,(byte)-113,(byte)-124,(byte)-5,(byte)32,(byte)16,(byte)109,(byte)-79,(byte)-122,(byte)-58,(byte)-74,(byte)25,(byte)95,(byte)114,(byte)-105,(byte)-15,(byte)-45,(byte)13,(byte)59,(byte)70,(byte)50,(byte)-42,(byte)-24,(byte)-43,(byte)52,(byte)35,(byte)101,(byte)118,(byte)-84,(byte)-7,(byte)-1,(byte)28,(byte)47,(byte)68,(byte)-125,(byte)-28,(byte)-62,(byte)-58,(byte)18,(byte)94,(byte)81,(byte)-43,(byte)-16,(byte)-49,(byte)46,(byte)34,(byte)124,(byte)58,(byte)-125,(byte)-52,(byte)-61,(byte)34,(byte)19,(byte)73,(byte)-52,(byte)-81,(byte)-4,(byte)-1,(byte)14,(byte)114,(byte)92,(byte)-74,(byte)-8,(byte)-23,(byte)-50,(byte)16,(byte)6,(byte)81,(byte)-69,(byte)-11,(byte)-48,(byte)18,(byte)52,(byte)106,(byte)75,(byte)-81,(byte)-20,(byte)-15,(byte)26,(byte)63,(byte)70,(byte)-45,(byte)-3,(byte)-7,(byte)-62,(byte)8,(byte)122,(byte)45,(byte)-95,(byte)-82,(byte)-24,(byte)-7,(byte)44,(byte)90,(byte)126,(byte)-35,(byte)-105,(byte)-9,(byte)24,(byte)50,(byte)76,(byte)60,(byte)-112,(byte)-109,(byte)-7,(byte)32,(byte)37,(byte)68,(byte)-43,(byte)-31,(byte)-101,(byte)-54,(byte)50,(byte)86,(byte)98,(byte)-62,(byte)-114,(byte)-19,(byte)49,(byte)107,(byte)83,(byte)74,(byte)-110,(byte)-7,(byte)-40,(byte)64,(byte)25,(byte)81,(byte)101,(byte)-92,(byte)-59,(byte)-35,(byte)82,(byte)11,(byte)109,(byte)-119,(byte)-104,(byte)-30,(byte)-42,(byte)3,(byte)81,(byte)38,(byte)-113,(byte)-25,(byte)-107,(byte)26,(byte)46,(byte)115,(byte)121,(byte)-86,(byte)-20,(byte)-9,(byte)27,(byte)124,(byte)19,(byte)112,(byte)-128,(byte)-57,(byte)-38,(byte)45,(byte)47,(byte)111,(byte)-97,(byte)-23,(byte)-48,(byte)-29,(byte)11,(byte)122,(byte)85,(byte)-123,(byte)-98,(byte)-58,(byte)56,(byte)123,(byte)118,(byte)74,(byte)-128,(byte)-50,(byte)-17,(byte)52,(byte)1,(byte)109,(byte)-89,(byte)-109,(byte)-121,(byte)-36,(byte)82,(byte)51,(byte)92,(byte)-94,(byte)-118,(byte)-29,(byte)-64,(byte)30,(byte)25,(byte)122,(byte)-63,(byte)-93,(byte)-8,(byte)31,(byte)121,(byte)90,(byte)69,(byte)-103,(byte)-117,(byte)-84,(byte)44,(byte)57,(byte)69,(byte)-98,(byte)-95,(byte)-11,(byte)-19,(byte)35,(byte)106,(byte)64,(byte)-99,(byte)-81,(byte)-10,(byte)-45,(byte)34,(byte)6,(byte)118,(byte)-83,(byte)-108,(byte)-60,(byte)30,(byte)29,(byte)109,(byte)118,(byte)-116,(byte)-120,(byte)-3,(byte)47,(byte)51,(byte)97,(byte)-81,(byte)-82,(byte)-8,(byte)-4,(byte)32,(byte)105,(byte)89,(byte)-89,(byte)-125,(byte)-9,(byte)45,(byte)52,(byte)107,(byte)67,(byte)-55,(byte)-74,(byte)-11,(byte)46,(byte)45,(byte)126,(byte)50,(byte)-98,(byte)-45,(byte)-23,(byte)12,(byte)50,(byte)104,(byte)-98,(byte)-124,(byte)-103,(byte)-80,(byte)75,(byte)121,(byte)123,(byte)-76,(byte)-25,(byte)-41,(byte)87,(byte)28,(byte)0,(byte)101,(byte)-46,(byte)-38,(byte)-12,(byte)57,(byte)56,(byte)64,(byte)114,(byte)-98,(byte)-37,(byte)-42,(byte)67,(byte)14,(byte)93,(byte)-111,(byte)-99,(byte)-24,(byte)-59,(byte)31,(byte)127,(byte)120,(byte)-71,(byte)-126,(byte)-30,(byte)53,(byte)25,(byte)108,(byte)56,(byte)-91,(byte)-3,(byte)-89,(byte)37,(byte)46,(byte)96,(byte)-103,(byte)-119,(byte)-27,(byte)-50,(byte)36,(byte)18,(byte)119,(byte)-123,(byte)-85,(byte)-3,(byte)-29,(byte)11,(byte)79,(byte)82,(byte)-120,(byte)-111,(byte)-48,(byte)33,(byte)10,(byte)117,(byte)74,(byte)-108,(byte)-116,(byte)-18,(byte)11,(byte)121,(byte)114,(byte)-88,(byte)-17,(byte)-62,(byte)-50,(byte)11,(byte)84,(byte)89,(byte)-108,(byte)-114,(byte)-63,(byte)-50,(byte)12,(byte)124,(byte)93,(byte)-91,(byte)-121,(byte)-37,(byte)50,(byte)17,(byte)125,(byte)99,(byte)-100,(byte)-22,(byte)-1,(byte)29,(byte)35,(byte)117,(byte)-101,(byte)-125,(byte)-41,(byte)-54,(byte)0,(byte)105,(byte)88,(byte)-87,(byte)-110,(byte)-3,(byte)50,(byte)44,(byte)4,(byte)118,(byte)-125,(byte)-15,(byte)-54,(byte)32,(byte)119,(byte)90,(byte)70,(byte)-77,(byte)-36,(byte)-47,(byte)39,(byte)6,(byte)121,(byte)-74,(byte)-124,(byte)-28,(byte)-44,(byte)45,(byte)127,(byte)86,(byte)-70,(byte)-119,(byte)-26,(byte)61,(byte)7,(byte)120,(byte)37,(byte)-87,(byte)-1,(byte)-88,(byte)53,(byte)15,(byte)117,(byte)113,(byte)-99,(byte)-25,(byte)-57,(byte)10,(byte)113,(byte)88,(byte)-89,(byte)-107,(byte)-24,(byte)-57,(byte)41,(byte)109,(byte)83,(byte)-83,(byte)-14,(byte)-23,(byte)56,(byte)21,(byte)127,(byte)75,(byte)-74,(byte)-18,(byte)-28,(byte)51,(byte)123,(byte)80,(byte)-90,(byte)-119,(byte)-48,(byte)-72,(byte)55,(byte)23,(byte)67,(byte)-105,(byte)-27,(byte)-16,(byte)-19,(byte)13,(byte)1,(byte)103,(byte)-126,(byte)-85,(byte)-58,(byte)8,(byte)10,(byte)94,(byte)76,(byte)-76,(byte)-52,(byte)-43,(byte)15,(byte)59,(byte)20,(byte)-54,(byte)-89,(byte)-124,(byte)-55,(byte)54,(byte)72,(byte)74,(byte)-68,(byte)-81,(byte)-31,(byte)-41,(byte)54,(byte)3,(byte)118,(byte)-67,(byte)-87,(byte)-9,(byte)47,(byte)36,(byte)99,(byte)126,(byte)-105,(byte)-46,(byte)-39,(byte)84,(byte)7,(byte)65,(byte)-114,(byte)-116,(byte)-38,(byte)-34,(byte)20,(byte)78,(byte)32,(byte)-97,(byte)-90,(byte)-22,(byte)14,(byte)13,(byte)124,(byte)109,(byte)-81,(byte)-107,(byte)-37,(byte)54,(byte)26,(byte)94,(byte)84,(byte)-120,(byte)-123,(byte)-2,(byte)9,(byte)48,(byte)103,(byte)-88,(byte)-77,(byte)-62,(byte)-29,(byte)35,(byte)98,(byte)108,(byte)-127,(byte)-16,(byte)-15,(byte)87,(byte)98,(byte)84,(byte)67,(byte)-121,(byte)-49,(byte)-31,(byte)24,(byte)43,(byte)101,(byte)113,(byte)-68,(byte)-115,(byte)-58,(byte)15,(byte)4,(byte)120,(byte)-39,(byte)-97,(byte)-21,(byte)-52,(byte)47,(byte)79,(byte)37,(byte)-126,(byte)-85,(byte)-57,(byte)19,(byte)49,(byte)120,(byte)98,(byte)-96,(byte)-116,(byte)-58,(byte)39,(byte)123,(byte)87,(byte)-86,(byte)-128,(byte)-61,(byte)-51,(byte)17,(byte)12,(byte)34,(byte)-109,(byte)-92,(byte)-49,(byte)-29,(byte)8,(byte)64,(byte)83,(byte)-71,(byte)-120,(byte)-42,(byte)9,(byte)107,(byte)105,(byte)106,(byte)-45,(byte)-10,(byte)-65,(byte)47,(byte)34,(byte)23,(byte)-53,(byte)-32,(byte)-121,(byte)-68,(byte)47,(byte)78,(byte)47,(byte)-117,(byte)-6,(byte)-109,(byte)-50,(byte)21,(byte)109,(byte)86,(byte)-86,(byte)-88,(byte)-19,(byte)70,(byte)5,(byte)101,(byte)70,(byte)-79,(byte)-7,(byte)-8,(byte)10,(byte)51,(byte)72,(byte)-84,(byte)-79,(byte)-103,(byte)-61,(byte)85,(byte)19,(byte)123,(byte)-122,(byte)-13,(byte)-17,(byte)12,(byte)25,(byte)117,(byte)91,(byte)-108,(byte)-109,(byte)-9,(byte)77,(byte)8,(byte)109,(byte)80,(byte)-79,(byte)-41,(byte)-1,(byte)57,(byte)14,(byte)108,(byte)-94,(byte)-26,(byte)-58,(byte)-41,(byte)75,(byte)91,(byte)80,(byte)-66,(byte)-71,(byte)-115,(byte)22,(byte)18,(byte)2,(byte)57,(byte)-114,(byte)-54,(byte)-19,(byte)29,(byte)4,(byte)104,(byte)100,(byte)-108,(byte)-14,(byte)-44,(byte)80,(byte)38,(byte)75,(byte)-101,(byte)-104,(byte)-29,(byte)-52,(byte)12,(byte)98,(byte)70,(byte)-35,(byte)-95,(byte)-19,(byte)59,(byte)13,(byte)65,(byte)120,(byte)-128,(byte)-118,(byte)-46,(byte)95,(byte)120,(byte)98,(byte)-70,(byte)-9,(byte)-9,(byte)-93,(byte)12,(byte)57,(byte)106,(byte)-67,(byte)-102,(byte)-112,(byte)-5,(byte)42,(byte)69,(byte)101,(byte)-81,(byte)-88,(byte)-58,(byte)27,(byte)52,(byte)74,(byte)109,(byte)-113,(byte)-49,(byte)-2,(byte)88,(byte)17,(byte)67,(byte)-107,(byte)-27,(byte)-10,(byte)-51,(byte)41,(byte)68,(byte)92,(byte)-69,(byte)-121,(byte)-24,(byte)-17,(byte)60,(byte)121,(byte)60,(byte)-82,(byte)-86,(byte)-73,(byte)55,(byte)33,(byte)126,(byte)98,(byte)-114,(byte)-41,(byte)-13,(byte)40,(byte)28,(byte)107,(byte)-94,(byte)-19,(byte)-23,(byte)-27,(byte)50,(byte)85,(byte)101,(byte)-118,(byte)-110,(byte)-14,(byte)63,(byte)61,(byte)85,(byte)64,(byte)-48,(byte)-109,(byte)-16,(byte)66,(byte)54,(byte)108,(byte)59,(byte)-9,(byte)-28,(byte)-89,(byte)6,(byte)78,(byte)51,(byte)-43,(byte)-1,(byte)-127,(byte)-85,(byte)37,(byte)116,(byte)80,(byte)-50,(byte)-117,(byte)-25,(byte)46,(byte)2,(byte)121,(byte)76,(byte)-83,(byte)-3,(byte)-39,(byte)38,(byte)9,(byte)11,(byte)45,(byte)-9,(byte)-103,(byte)-93});
         X509Certificate QACert = this.getX509Certificate(QACertPEM);
         trustedCAs.add(new TrustAnchor(QACert, null));
         String DRKOldCertPEM = zqw.pQn(new byte[] {(byte)116,(byte)-83,(byte)-128,(byte)48,(byte)-96,(byte)-48,(byte)64,(byte)-97,(byte)8,(byte)-6,(byte)100,(byte)-45,(byte)45,(byte)62,(byte)-88,(byte)15,(byte)-103,(byte)116,(byte)-21,(byte)84,(byte)-50,(byte)-68,(byte)57,(byte)-104,(byte)96,(byte)-112,(byte)0,(byte)-80,(byte)32,(byte)119,(byte)-96,(byte)20,(byte)-124,(byte)121,(byte)-58,(byte)119,(byte)-50,(byte)-66,(byte)44,(byte)-77,(byte)60,(byte)-38,(byte)108,(byte)-22,(byte)68,(byte)63,(byte)-84,(byte)58,(byte)-124,(byte)119,(byte)-20,(byte)82,(byte)-69,(byte)-78,(byte)63,(byte)-88,(byte)38,(byte)-4,(byte)21,(byte)-12,(byte)102,(byte)47,(byte)-96,(byte)28,(byte)-3,(byte)122,(byte)-18,(byte)78,(byte)-4,(byte)-70,(byte)62,(byte)-108,(byte)47,(byte)-114,(byte)105,(byte)-52,(byte)72,(byte)63,(byte)-82,(byte)42,(byte)-104,(byte)124,(byte)-32,(byte)91,(byte)-26,(byte)-123,(byte)46,(byte)-89,(byte)12,(byte)-9,(byte)111,(byte)-6,(byte)67,(byte)43,(byte)-81,(byte)28,(byte)-108,(byte)105,(byte)-20,(byte)118,(byte)-7,(byte)-82,(byte)32,(byte)-113,(byte)0,(byte)-54,(byte)104,(byte)-52,(byte)84,(byte)57,(byte)-69,(byte)12,(byte)-100,(byte)117,(byte)-23,(byte)92,(byte)-3,(byte)-87,(byte)9,(byte)-123,(byte)41,(byte)-53,(byte)79,(byte)-12,(byte)79,(byte)23,(byte)-116,(byte)5,(byte)-97,(byte)8,(byte)-32,(byte)79,(byte)-18,(byte)-118,(byte)43,(byte)-116,(byte)20,(byte)-7,(byte)123,(byte)-52,(byte)92,(byte)49,(byte)-87,(byte)28,(byte)-8,(byte)105,(byte)-12,(byte)74,(byte)-68,(byte)-121,(byte)9,(byte)-118,(byte)120,(byte)-45,(byte)100,(byte)-40,(byte)60,(byte)11,(byte)-76,(byte)48,(byte)-95,(byte)78,(byte)-9,(byte)73,(byte)-56,(byte)-98,(byte)32,(byte)-97,(byte)34,(byte)-6,(byte)108,(byte)-84,(byte)88,(byte)56,(byte)-84,(byte)42,(byte)-70,(byte)105,(byte)-8,(byte)47,(byte)-53,(byte)-119,(byte)14,(byte)-18,(byte)27,(byte)-56,(byte)119,(byte)-28,(byte)79,(byte)23,(byte)-113,(byte)110,(byte)-121,(byte)74,(byte)-49,(byte)46,(byte)-57,(byte)-107,(byte)9,(byte)-102,(byte)33,(byte)-53,(byte)79,(byte)-9,(byte)76,(byte)24,(byte)-85,(byte)42,(byte)-3,(byte)69,(byte)-32,(byte)103,(byte)-52,(byte)-52,(byte)32,(byte)-89,(byte)12,(byte)-59,(byte)96,(byte)-25,(byte)72,(byte)5,(byte)-93,(byte)9,(byte)-97,(byte)92,(byte)-21,(byte)106,(byte)-67,(byte)-121,(byte)32,(byte)-89,(byte)12,(byte)-116,(byte)96,(byte)-9,(byte)88,(byte)5,(byte)-96,(byte)39,(byte)-120,(byte)69,(byte)-29,(byte)73,(byte)-33,(byte)-100,(byte)32,(byte)-101,(byte)38,(byte)-59,(byte)110,(byte)-25,(byte)76,(byte)55,(byte)-81,(byte)58,(byte)-125,(byte)107,(byte)-17,(byte)92,(byte)-44,(byte)-87,(byte)44,(byte)-74,(byte)57,(byte)-18,(byte)96,(byte)-49,(byte)64,(byte)10,(byte)-88,(byte)12,(byte)-108,(byte)121,(byte)-5,(byte)76,(byte)-36,(byte)-75,(byte)41,(byte)-100,(byte)61,(byte)-23,(byte)73,(byte)-59,(byte)105,(byte)11,(byte)-113,(byte)52,(byte)-113,(byte)87,(byte)-52,(byte)69,(byte)-33,(byte)-56,(byte)32,(byte)-113,(byte)46,(byte)-54,(byte)107,(byte)-52,(byte)84,(byte)57,(byte)-69,(byte)12,(byte)-100,(byte)113,(byte)-23,(byte)92,(byte)-72,(byte)-87,(byte)52,(byte)-118,(byte)124,(byte)-57,(byte)73,(byte)-54,(byte)56,(byte)19,(byte)-92,(byte)24,(byte)-4,(byte)75,(byte)-12,(byte)112,(byte)-31,(byte)-114,(byte)55,(byte)-119,(byte)8,(byte)-34,(byte)96,(byte)-33,(byte)98,(byte)58,(byte)-84,(byte)108,(byte)-104,(byte)120,(byte)-20,(byte)106,(byte)-6,(byte)-87,(byte)56,(byte)-17,(byte)11,(byte)-55,(byte)78,(byte)-82,(byte)91,(byte)8,(byte)-73,(byte)36,(byte)-113,(byte)87,(byte)-49,(byte)46,(byte)-57,(byte)-118,(byte)15,(byte)-18,(byte)7,(byte)-43,(byte)73,(byte)-38,(byte)97,(byte)11,(byte)-113,(byte)55,(byte)-114,(byte)126,(byte)-20,(byte)78,(byte)-60,(byte)-118,(byte)41,(byte)-116,(byte)20,(byte)-9,(byte)102,(byte)-14,(byte)87,(byte)52,(byte)-123,(byte)43,(byte)-82,(byte)115,(byte)-20,(byte)76,(byte)-56,(byte)-65,(byte)47,(byte)-116,(byte)12,(byte)-7,(byte)74,(byte)-6,(byte)72,(byte)45,(byte)-84,(byte)25,(byte)-114,(byte)126,(byte)-20,(byte)76,(byte)-30,(byte)-66,(byte)10,(byte)-70,(byte)8,(byte)-1,(byte)108,(byte)-46,(byte)73,(byte)62,(byte)-118,(byte)4,(byte)-87,(byte)107,(byte)-33,(byte)36,(byte)-63,(byte)-81,(byte)89,(byte)-108,(byte)127,(byte)-41,(byte)78,(byte)-14,(byte)76,(byte)23,(byte)-104,(byte)59,(byte)-108,(byte)69,(byte)-54,(byte)83,(byte)-75,(byte)-73,(byte)32,(byte)-116,(byte)47,(byte)-33,(byte)120,(byte)-17,(byte)78,(byte)36,(byte)-70,(byte)45,(byte)-91,(byte)79,(byte)-27,(byte)113,(byte)-9,(byte)-121,(byte)56,(byte)-102,(byte)124,(byte)-48,(byte)91,(byte)-87,(byte)70,(byte)23,(byte)-100,(byte)36,(byte)-105,(byte)126,(byte)-56,(byte)44,(byte)-30,(byte)-77,(byte)24,(byte)-70,(byte)20,(byte)-110,(byte)24,(byte)-46,(byte)92,(byte)50,(byte)-123,(byte)49,(byte)-102,(byte)83,(byte)-56,(byte)113,(byte)-32,(byte)-106,(byte)26,(byte)-28,(byte)27,(byte)-55,(byte)90,(byte)-19,(byte)123,(byte)57,(byte)-117,(byte)46,(byte)-116,(byte)9,(byte)-32,(byte)45,(byte)-35,(byte)-71,(byte)27,(byte)-108,(byte)24,(byte)-12,(byte)95,(byte)-54,(byte)85,(byte)12,(byte)-38,(byte)108,(byte)-12,(byte)82,(byte)-64,(byte)72,(byte)-9,(byte)-72,(byte)88,(byte)-20,(byte)124,(byte)-21,(byte)65,(byte)-8,(byte)94,(byte)57,(byte)-87,(byte)52,(byte)-86,(byte)110,(byte)-21,(byte)109,(byte)-94,(byte)-88,(byte)21,(byte)-112,(byte)23,(byte)-50,(byte)105,(byte)-46,(byte)53,(byte)30,(byte)-82,(byte)4,(byte)-119,(byte)127,(byte)-39,(byte)123,(byte)-26,(byte)-52,(byte)60,(byte)-88,(byte)43,(byte)-11,(byte)26,(byte)-18,(byte)38,(byte)58,(byte)-94,(byte)58,(byte)-107,(byte)89,(byte)-63,(byte)95,(byte)-8,(byte)-114,(byte)26,(byte)-77,(byte)55,(byte)-33,(byte)100,(byte)-34,(byte)75,(byte)8,(byte)-113,(byte)26,(byte)-68,(byte)86,(byte)-30,(byte)41,(byte)-5,(byte)-51,(byte)43,(byte)-114,(byte)21,(byte)-9,(byte)96,(byte)-20,(byte)70,(byte)53,(byte)-84,(byte)22,(byte)-65,(byte)72,(byte)-55,(byte)121,(byte)-58,(byte)-115,(byte)70,(byte)-23,(byte)20,(byte)-14,(byte)31,(byte)-23,(byte)111,(byte)59,(byte)-120,(byte)47,(byte)-8,(byte)15,(byte)-36,(byte)89,(byte)-8,(byte)-60,(byte)15,(byte)-79,(byte)8,(byte)-25,(byte)66,(byte)-92,(byte)92,(byte)26,(byte)-124,(byte)111,(byte)-82,(byte)74,(byte)-98,(byte)116,(byte)-35,(byte)-66,(byte)38,(byte)-121,(byte)120,(byte)-49,(byte)29,(byte)-74,(byte)89,(byte)77,(byte)-67,(byte)51,(byte)-107,(byte)10,(byte)-59,(byte)120,(byte)-49,(byte)-120,(byte)56,(byte)-120,(byte)46,(byte)-24,(byte)94,(byte)-10,(byte)92,(byte)25,(byte)-43,(byte)18,(byte)-73,(byte)77,(byte)-104,(byte)80,(byte)-39,(byte)-107,(byte)63,(byte)-69,(byte)120,(byte)-20,(byte)79,(byte)-40,(byte)59,(byte)54,(byte)-88,(byte)63,(byte)-12,(byte)92,(byte)-34,(byte)106,(byte)-3,(byte)-75,(byte)41,(byte)-114,(byte)15,(byte)-8,(byte)100,(byte)-48,(byte)38,(byte)49,(byte)-40,(byte)62,(byte)-2,(byte)69,(byte)-103,(byte)95,(byte)-7,(byte)-50,(byte)15,(byte)-84,(byte)125,(byte)-42,(byte)89,(byte)-41,(byte)69,(byte)42,(byte)-125,(byte)109,(byte)-3,(byte)115,(byte)-7,(byte)120,(byte)-40,(byte)-124,(byte)6,(byte)-79,(byte)37,(byte)-10,(byte)73,(byte)-41,(byte)76,(byte)58,(byte)-113,(byte)57,(byte)-101,(byte)91,(byte)-8,(byte)73,(byte)-4,(byte)-123,(byte)32,(byte)-87,(byte)124,(byte)-27,(byte)2,(byte)-15,(byte)126,(byte)62,(byte)-91,(byte)44,(byte)-11,(byte)106,(byte)-23,(byte)94,(byte)-59,(byte)-66,(byte)53,(byte)-71,(byte)41,(byte)-39,(byte)89,(byte)-42,(byte)64,(byte)22,(byte)-88,(byte)57,(byte)-3,(byte)126,(byte)-20,(byte)106,(byte)-56,(byte)-68,(byte)44,(byte)-68,(byte)3,(byte)-39,(byte)96,(byte)-37,(byte)126,(byte)10,(byte)-91,(byte)12,(byte)-108,(byte)121,(byte)-5,(byte)79,(byte)-67,(byte)-78,(byte)47,(byte)-97,(byte)20,(byte)-8,(byte)107,(byte)-33,(byte)98,(byte)73,(byte)-66,(byte)11,(byte)-90,(byte)72,(byte)-32,(byte)116,(byte)-54,(byte)-66,(byte)41,(byte)-107,(byte)46,(byte)-48,(byte)105,(byte)-2,(byte)98,(byte)47,(byte)-97,(byte)57,(byte)-1,(byte)94,(byte)-44,(byte)118,(byte)-61,(byte)-60,(byte)32,(byte)-97,(byte)117,(byte)-6,(byte)108,(byte)-84,(byte)88,(byte)25,(byte)-92,(byte)42,(byte)-100,(byte)100,(byte)-32,(byte)95,(byte)-20,(byte)-68,(byte)43,(byte)-97,(byte)34,(byte)-119,(byte)126,(byte)-53,(byte)102,(byte)8,(byte)-96,(byte)52,(byte)-118,(byte)126,(byte)-23,(byte)85,(byte)-18,(byte)-112,(byte)41,(byte)-66,(byte)34,(byte)-17,(byte)95,(byte)-7,(byte)63,(byte)30,(byte)-108,(byte)54,(byte)-125,(byte)4,(byte)-32,(byte)92,(byte)-6,(byte)-70,(byte)44,(byte)-20,(byte)24,(byte)-39,(byte)104,(byte)-22,(byte)92,(byte)59,(byte)-96,(byte)28,(byte)-128,(byte)127,(byte)-20,(byte)123,(byte)-75,(byte)-118,(byte)46,(byte)-86,(byte)20,(byte)-7,(byte)123,(byte)-49,(byte)61,(byte)45,(byte)-81,(byte)28,(byte)-100,(byte)121,(byte)-20,(byte)122,(byte)-56,(byte)-70,(byte)32,(byte)-100,(byte)125,(byte)-6,(byte)110,(byte)-50,(byte)124,(byte)58,(byte)-66,(byte)20,(byte)-81,(byte)14,(byte)-23,(byte)76,(byte)-56,(byte)-65,(byte)46,(byte)-86,(byte)24,(byte)-4,(byte)108,(byte)-87,(byte)68,(byte)63,(byte)-84,(byte)12,(byte)-113,(byte)105,(byte)-97,(byte)72,(byte)-7,(byte)-54,(byte)14,(byte)-28,(byte)120,(byte)-5,(byte)105,(byte)-91,(byte)125,(byte)11,(byte)-37,(byte)18,(byte)-65,(byte)112,(byte)-59,(byte)94,(byte)-3,(byte)-116,(byte)93,(byte)-78,(byte)1,(byte)-10,(byte)87,(byte)-60,(byte)91,(byte)22,(byte)-101,(byte)13,(byte)-65,(byte)122,(byte)-2,(byte)91,(byte)-39,(byte)-53,(byte)42,(byte)-110,(byte)33,(byte)-25,(byte)6,(byte)-6,(byte)63,(byte)23,(byte)-40,(byte)42,(byte)-11,(byte)109,(byte)-4,(byte)113,(byte)-7,(byte)-85,(byte)5,(byte)-68,(byte)52,(byte)-60,(byte)103,(byte)-47,(byte)34,(byte)62,(byte)-72,(byte)18,(byte)-123,(byte)112,(byte)-55,(byte)75,(byte)-28,(byte)-73,(byte)36,(byte)-24,(byte)34,(byte)-22,(byte)105,(byte)-34,(byte)126,(byte)47,(byte)-107,(byte)109,(byte)-5,(byte)76,(byte)-35,(byte)104,(byte)-31,(byte)-89,(byte)58,(byte)-75,(byte)39,(byte)-5,(byte)28,(byte)-18,(byte)108,(byte)60,(byte)-125,(byte)110,(byte)-105,(byte)118,(byte)-103,(byte)45,(byte)-23,(byte)-109,(byte)36,(byte)-18,(byte)5,(byte)-116,(byte)101,(byte)-11,(byte)121,(byte)50,(byte)-36,(byte)63,(byte)-11,(byte)88,(byte)-41,(byte)105,(byte)-90,(byte)-92,(byte)9,(byte)-123,(byte)28,(byte)-19,(byte)125,(byte)-36,(byte)98,(byte)16,(byte)-121,(byte)17,(byte)-101,(byte)92,(byte)-50,(byte)83,(byte)-1,(byte)-113,(byte)1,(byte)-121,(byte)4,(byte)-53,(byte)105,(byte)-45,(byte)66,(byte)49,(byte)-40,(byte)100,(byte)-30,(byte)14,(byte)-35,(byte)78,(byte)-4,(byte)-112,(byte)58,(byte)-17,(byte)12,(byte)-54,(byte)99,(byte)-56,(byte)120,(byte)14,(byte)-93,(byte)39,(byte)-75,(byte)79,(byte)-108,(byte)107,(byte)-3,(byte)-111,(byte)34,(byte)-10,(byte)10,(byte)-60,(byte)90,(byte)-37,(byte)89,(byte)47,(byte)-37,(byte)30,(byte)-8,(byte)12,(byte)-41,(byte)77,(byte)-34,(byte)-105,(byte)70,(byte)-109,(byte)59,(byte)-60,(byte)69,(byte)-17,(byte)124,(byte)9,(byte)-40,(byte)10,(byte)-30,(byte)101,(byte)-39,(byte)124,(byte)-28,(byte)-84,(byte)34,(byte)-14,(byte)10,(byte)-10,(byte)27,(byte)-36,(byte)126,(byte)15,(byte)-125,(byte)108,(byte)-26,(byte)14,(byte)-107,(byte)114,(byte)-5,(byte)-75,(byte)6,(byte)-104,(byte)126,(byte)-15,(byte)88,(byte)-50,(byte)123,(byte)14,(byte)-120,(byte)22,(byte)-12,(byte)11,(byte)-104,(byte)43,(byte)-55,(byte)-86,(byte)34,(byte)-111,(byte)55,(byte)-34,(byte)106,(byte)-15,(byte)125,(byte)56,(byte)-121,(byte)27,(byte)-126,(byte)121,(byte)-61,(byte)46,(byte)-58,(byte)-53,(byte)12,(byte)-22,(byte)52,(byte)-118,(byte)71,(byte)-23,(byte)71,(byte)69,(byte)-38,(byte)104,(byte)-98,(byte)109,(byte)-49,(byte)119,(byte)-49,(byte)-73,(byte)89,(byte)-81,(byte)123,(byte)-106,(byte)64,(byte)-25,(byte)58,(byte)36,(byte)-123,(byte)41,(byte)-119,(byte)108,(byte)-41,(byte)46,(byte)-17,(byte)-92,(byte)89,(byte)-79,(byte)31,(byte)-23,(byte)85,(byte)-86,(byte)124,(byte)37,(byte)-90,(byte)21,(byte)-107,(byte)83,(byte)-44,(byte)107,(byte)-23,(byte)-80,(byte)57,(byte)-114,(byte)0,(byte)-19,(byte)110,(byte)-24,(byte)84,(byte)7,(byte)-118,(byte)58,(byte)-128,(byte)85,(byte)-9,(byte)118,(byte)-12,(byte)-54,(byte)37,(byte)-85,(byte)60,(byte)-22,(byte)119,(byte)-7,(byte)87,(byte)59,(byte)-104,(byte)7,(byte)-3,(byte)73,(byte)-122,(byte)108,(byte)-44,(byte)-52,(byte)44,(byte)-77,(byte)7,(byte)-4,(byte)105,(byte)-46,(byte)34,(byte)7,(byte)-113,(byte)31,(byte)-114,(byte)113,(byte)-30,(byte)106,(byte)-7,(byte)-100,(byte)103,(byte)-16,(byte)96,(byte)-112,(byte)0,(byte)-80,(byte)72,(byte)51,(byte)-87,(byte)125,(byte)-114,(byte)120,(byte)-1,(byte)73,(byte)-60,(byte)-69,(byte)36,(byte)-98,(byte)12,(byte)-23,(byte)104,(byte)-80,(byte)32,(byte)80,(byte)-64,(byte)112});
         String DRKCertPEMfromKnox3_1 = zqw.puP(new byte[] {(byte)-45,(byte)111,(byte)66,(byte)118,(byte)106,(byte)30,(byte)50,(byte)73,(byte)-78,(byte)-92,(byte)-122,(byte)-11,(byte)-121,(byte)-48,(byte)58,(byte)57,(byte)3,(byte)10,(byte)105,(byte)82,(byte)68,(byte)-78,(byte)-117,(byte)-114,(byte)-102,(byte)-114,(byte)-94,(byte)86,(byte)74,(byte)89,(byte)114,(byte)98,(byte)94,(byte)64,(byte)-123,(byte)-95,(byte)-124,(byte)-16,(byte)-34,(byte)-19,(byte)52,(byte)4,(byte)14,(byte)76,(byte)110,(byte)81,(byte)-66,(byte)-116,(byte)-98,(byte)-122,(byte)-8,(byte)-54,(byte)-52,(byte)92,(byte)43,(byte)15,(byte)118,(byte)104,(byte)77,(byte)-100,(byte)-128,(byte)-94,(byte)-41,(byte)-64,(byte)-3,(byte)-52,(byte)63,(byte)10,(byte)22,(byte)119,(byte)94,(byte)97,(byte)-75,(byte)-71,(byte)-126,(byte)-22,(byte)-44,(byte)-28,(byte)60,(byte)58,(byte)14,(byte)7,(byte)121,(byte)74,(byte)86,(byte)-76,(byte)-102,(byte)-68,(byte)-3,(byte)-17,(byte)-38,(byte)17,(byte)34,(byte)7,(byte)114,(byte)105,(byte)82,(byte)68,(byte)-82,(byte)-22,(byte)-110,(byte)-10,(byte)-35,(byte)-13,(byte)58,(byte)40,(byte)26,(byte)8,(byte)113,(byte)32,(byte)-99,(byte)-39,(byte)-29,(byte)-92,(byte)-10,(byte)-87,(byte)-21,(byte)67,(byte)58,(byte)31,(byte)114,(byte)123,(byte)66,(byte)-71,(byte)-78,(byte)-108,(byte)-2,(byte)-102,(byte)-62,(byte)-58,(byte)44,(byte)35,(byte)10,(byte)124,(byte)74,(byte)57,(byte)-79,(byte)-105,(byte)-84,(byte)-120,(byte)-15,(byte)-26,(byte)37,(byte)18,(byte)21,(byte)13,(byte)77,(byte)41,(byte)77,(byte)-125,(byte)-67,(byte)-116,(byte)-30,(byte)-37,(byte)-57,(byte)63,(byte)38,(byte)50,(byte)125,(byte)76,(byte)89,(byte)85,(byte)-83,(byte)-102,(byte)-118,(byte)-25,(byte)-38,(byte)-70,(byte)57,(byte)11,(byte)45,(byte)99,(byte)105,(byte)34,(byte)-99,(byte)-122,(byte)-76,(byte)-92,(byte)-10,(byte)-87,(byte)-66,(byte)10,(byte)60,(byte)12,(byte)14,(byte)90,(byte)86,(byte)-93,(byte)-75,(byte)-93,(byte)-35,(byte)-103,(byte)-93,(byte)-12,(byte)39,(byte)51,(byte)36,(byte)125,(byte)82,(byte)95,(byte)-108,(byte)-108,(byte)-127,(byte)-1,(byte)-18,(byte)-89,(byte)50,(byte)47,(byte)6,(byte)52,(byte)97,(byte)113,(byte)66,(byte)-118,(byte)-120,(byte)-93,(byte)-44,(byte)-19,(byte)-62,(byte)1,(byte)4,(byte)36,(byte)113,(byte)111,(byte)94,(byte)121,(byte)-94,(byte)-97,(byte)-106,(byte)-60,(byte)-47,(byte)-31,(byte)50,(byte)26,(byte)24,(byte)81,(byte)101,(byte)73,(byte)-78,(byte)-70,(byte)-92,(byte)-76,(byte)-20,(byte)-54,(byte)-34,(byte)55,(byte)9,(byte)26,(byte)102,(byte)100,(byte)74,(byte)-116,(byte)-83,(byte)-97,(byte)-22,(byte)-63,(byte)-46,(byte)-41,(byte)34,(byte)25,(byte)2,(byte)116,(byte)94,(byte)58,(byte)-94,(byte)-90,(byte)-115,(byte)-61,(byte)-22,(byte)-40,(byte)42,(byte)88,(byte)1,(byte)112,(byte)77,(byte)41,(byte)51,(byte)-108,(byte)-122,(byte)-7,(byte)-37,(byte)-109,(byte)-22,(byte)47,(byte)34,(byte)11,(byte)114,(byte)105,(byte)66,(byte)68,(byte)-82,(byte)-22,(byte)-110,(byte)-10,(byte)-36,(byte)-13,(byte)58,(byte)44,(byte)26,(byte)9,(byte)97,(byte)103,(byte)-100,(byte)-40,(byte)-127,(byte)-74,(byte)-11,(byte)-30,(byte)-59,(byte)61,(byte)61,(byte)121,(byte)125,(byte)83,(byte)109,(byte)-68,(byte)-78,(byte)-85,(byte)-9,(byte)-17,(byte)-42,(byte)-30,(byte)45,(byte)60,(byte)9,(byte)101,(byte)93,(byte)74,(byte)-70,(byte)-73,(byte)-118,(byte)-118,(byte)-23,(byte)-5,(byte)29,(byte)51,(byte)25,(byte)114,(byte)77,(byte)118,(byte)100,(byte)-108,(byte)-122,(byte)-7,(byte)-114,(byte)-38,(byte)-20,(byte)60,(byte)94,(byte)42,(byte)102,(byte)115,(byte)69,(byte)115,(byte)-115,(byte)-23,(byte)-13,(byte)-60,(byte)-8,(byte)-47,(byte)4,(byte)20,(byte)10,(byte)122,(byte)126,(byte)91,(byte)-76,(byte)-124,(byte)-115,(byte)-118,(byte)-43,(byte)-15,(byte)-73,(byte)48,(byte)30,(byte)26,(byte)110,(byte)101,(byte)68,(byte)-49,(byte)-94,(byte)-106,(byte)-2,(byte)-24,(byte)-38,(byte)-57,(byte)8,(byte)2,(byte)30,(byte)114,(byte)93,(byte)74,(byte)-80,(byte)-103,(byte)-2,(byte)-8,(byte)-24,(byte)-27,(byte)80,(byte)82,(byte)18,(byte)16,(byte)104,(byte)73,(byte)99,(byte)-111,(byte)-86,(byte)-123,(byte)-28,(byte)-46,(byte)-63,(byte)17,(byte)87,(byte)60,(byte)12,(byte)105,(byte)77,(byte)115,(byte)-107,(byte)-78,(byte)-79,(byte)-35,(byte)-87,(byte)-39,(byte)70,(byte)50,(byte)46,(byte)111,(byte)18,(byte)93,(byte)-110,(byte)-91,(byte)-112,(byte)-87,(byte)-7,(byte)-4,(byte)-43,(byte)1,(byte)53,(byte)56,(byte)115,(byte)107,(byte)76,(byte)-85,(byte)-120,(byte)-110,(byte)-46,(byte)-45,(byte)-28,(byte)-75,(byte)32,(byte)49,(byte)47,(byte)112,(byte)104,(byte)110,(byte)-67,(byte)-117,(byte)-120,(byte)-15,(byte)-3,(byte)-34,(byte)46,(byte)30,(byte)111,(byte)21,(byte)25,(byte)80,(byte)51,(byte)-76,(byte)-88,(byte)-70,(byte)-59,(byte)-24,(byte)-69,(byte)35,(byte)51,(byte)27,(byte)118,(byte)106,(byte)86,(byte)114,(byte)-41,(byte)-108,(byte)-81,(byte)-117,(byte)-40,(byte)-6,(byte)4,(byte)48,(byte)61,(byte)99,(byte)31,(byte)88,(byte)-85,(byte)-84,(byte)-67,(byte)-94,(byte)-51,(byte)-53,(byte)-13,(byte)55,(byte)56,(byte)122,(byte)117,(byte)21,(byte)117,(byte)-98,(byte)-93,(byte)-69,(byte)-50,(byte)-19,(byte)-36,(byte)-52,(byte)93,(byte)25,(byte)21,(byte)120,(byte)87,(byte)88,(byte)-93,(byte)-103,(byte)-93,(byte)-126,(byte)-51,(byte)-41,(byte)62,(byte)14,(byte)26,(byte)9,(byte)27,(byte)109,(byte)77,(byte)-99,(byte)-78,(byte)-102,(byte)-28,(byte)-46,(byte)-50,(byte)24,(byte)5,(byte)99,(byte)9,(byte)64,(byte)35,(byte)101,(byte)-127,(byte)-71,(byte)-88,(byte)-26,(byte)-54,(byte)-54,(byte)5,(byte)6,(byte)54,(byte)109,(byte)109,(byte)64,(byte)-66,(byte)-89,(byte)-81,(byte)-122,(byte)-102,(byte)-17,(byte)-15,(byte)59,(byte)20,(byte)125,(byte)121,(byte)73,(byte)66,(byte)-68,(byte)-94,(byte)-92,(byte)-5,(byte)-36,(byte)-50,(byte)-57,(byte)57,(byte)9,(byte)119,(byte)103,(byte)94,(byte)90,(byte)-65,(byte)-52,(byte)-115,(byte)-6,(byte)-14,(byte)-28,(byte)62,(byte)28,(byte)18,(byte)1,(byte)0,(byte)97,(byte)70,(byte)-68,(byte)-99,(byte)-84,(byte)-7,(byte)-11,(byte)-57,(byte)42,(byte)95,(byte)17,(byte)126,(byte)77,(byte)47,(byte)70,(byte)-83,(byte)-102,(byte)-118,(byte)-16,(byte)-34,(byte)-38,(byte)46,(byte)20,(byte)7,(byte)106,(byte)126,(byte)87,(byte)-87,(byte)-71,(byte)-25,(byte)-116,(byte)-19,(byte)-39,(byte)-34,(byte)54,(byte)25,(byte)10,(byte)5,(byte)68,(byte)56,(byte)-126,(byte)-91,(byte)-117,(byte)-3,(byte)-4,(byte)-13,(byte)-32,(byte)27,(byte)52,(byte)1,(byte)101,(byte)89,(byte)78,(byte)-100,(byte)-121,(byte)-10,(byte)-63,(byte)-34,(byte)-62,(byte)70,(byte)41,(byte)24,(byte)117,(byte)98,(byte)89,(byte)63,(byte)-76,(byte)-98,(byte)-6,(byte)-30,(byte)-57,(byte)-58,(byte)12,(byte)54,(byte)10,(byte)114,(byte)105,(byte)118,(byte)66,(byte)-87,(byte)-102,(byte)-11,(byte)-44,(byte)-88,(byte)-14,(byte)53,(byte)59,(byte)13,(byte)108,(byte)67,(byte)112,(byte)-117,(byte)-124,(byte)-111,(byte)-107,(byte)-23,(byte)-34,(byte)-20,(byte)23,(byte)102,(byte)49,(byte)78,(byte)114,(byte)54,(byte)-71,(byte)-88,(byte)-27,(byte)-14,(byte)-22,(byte)-8,(byte)-60,(byte)44,(byte)24,(byte)54,(byte)116,(byte)76,(byte)70,(byte)-61,(byte)-38,(byte)-115,(byte)-6,(byte)-22,(byte)-48,(byte)62,(byte)95,(byte)16,(byte)14,(byte)110,(byte)95,(byte)68,(byte)-79,(byte)-74,(byte)-118,(byte)-3,(byte)-32,(byte)-50,(byte)53,(byte)34,(byte)21,(byte)123,(byte)24,(byte)68,(byte)69,(byte)-116,(byte)-24,(byte)-96,(byte)-28,(byte)-12,(byte)-58,(byte)21,(byte)14,(byte)126,(byte)15,(byte)21,(byte)127,(byte)-68,(byte)-101,(byte)-95,(byte)-87,(byte)-7,(byte)-83,(byte)-27,(byte)7,(byte)116,(byte)96,(byte)24,(byte)78,(byte)77,(byte)-82,(byte)-78,(byte)-103,(byte)-4,(byte)-40,(byte)-37,(byte)-22,(byte)22,(byte)30,(byte)4,(byte)86,(byte)48,(byte)67,(byte)-78,(byte)-80,(byte)-123,(byte)-11,(byte)-10,(byte)-29,(byte)9,(byte)14,(byte)53,(byte)27,(byte)92,(byte)104,(byte)81,(byte)-110,(byte)-74,(byte)-6,(byte)-33,(byte)-109,(byte)-50,(byte)51,(byte)32,(byte)35,(byte)105,(byte)89,(byte)82,(byte)77,(byte)-97,(byte)-100,(byte)-67,(byte)-128,(byte)-17,(byte)-6,(byte)38,(byte)22,(byte)0,(byte)11,(byte)23,(byte)56,(byte)-73,(byte)-110,(byte)-123,(byte)-126,(byte)-18,(byte)-16,(byte)-50,(byte)49,(byte)10,(byte)122,(byte)116,(byte)76,(byte)122,(byte)-51,(byte)-73,(byte)-85,(byte)-43,(byte)-19,(byte)-60,(byte)-5,(byte)37,(byte)107,(byte)51,(byte)1,(byte)101,(byte)121,(byte)-99,(byte)-107,(byte)-3,(byte)-36,(byte)-110,(byte)-89,(byte)11,(byte)47,(byte)15,(byte)34,(byte)87,(byte)92,(byte)102,(byte)-96,(byte)-105,(byte)-2,(byte)-128,(byte)-14,(byte)-34,(byte)26,(byte)86,(byte)48,(byte)119,(byte)127,(byte)92,(byte)118,(byte)-65,(byte)-18,(byte)-73,(byte)-39,(byte)-3,(byte)-45,(byte)35,(byte)8,(byte)10,(byte)16,(byte)110,(byte)66,(byte)-112,(byte)-86,(byte)-79,(byte)-126,(byte)-99,(byte)-8,(byte)-17,(byte)56,(byte)16,(byte)49,(byte)71,(byte)117,(byte)100,(byte)-109,(byte)-128,(byte)-72,(byte)-116,(byte)-47,(byte)-59,(byte)-24,(byte)61,(byte)11,(byte)40,(byte)93,(byte)71,(byte)91,(byte)-66,(byte)-46,(byte)-102,(byte)-56,(byte)-64,(byte)-82,(byte)117,(byte)70,(byte)122,(byte)110,(byte)2,(byte)54,(byte)66,(byte)-67,(byte)-101,(byte)-21,(byte)-12,(byte)-26,(byte)-35,(byte)47,(byte)46,(byte)21,(byte)118,(byte)104,(byte)86,(byte)87,(byte)-86,(byte)-10,(byte)-22,(byte)-98,(byte)-78,(byte)-90});
         String DRKCertPEMfromKnox3_4 = zqw.pQ(new byte[] {(byte)-93,(byte)59,(byte)22,(byte)17,(byte)16,(byte)19,(byte)18,(byte)2,(byte)4,(byte)5,(byte)10,(byte)10,(byte)101,(byte)5,(byte)2,(byte)26,(byte)29,(byte)3,(byte)13,(byte)5,(byte)14,(byte)15,(byte)27,(byte)21,(byte)124,(byte)127,(byte)126,(byte)121,(byte)120,(byte)92,(byte)26,(byte)17,(byte)16,(byte)25,(byte)49,(byte)38,(byte)30,(byte)29,(byte)30,(byte)6,(byte)34,(byte)5,(byte)34,(byte)19,(byte)44,(byte)36,(byte)38,(byte)15,(byte)32,(byte)47,(byte)51,(byte)36,(byte)52,(byte)4,(byte)43,(byte)36,(byte)48,(byte)57,(byte)49,(byte)19,(byte)18,(byte)7,(byte)31,(byte)19,(byte)19,(byte)53,(byte)43,(byte)45,(byte)44,(byte)58,(byte)61,(byte)-60,(byte)-61,(byte)-40,(byte)-50,(byte)-43,(byte)-10,(byte)-15,(byte)-60,(byte)-39,(byte)-48,(byte)-50,(byte)-35,(byte)-35,(byte)-36,(byte)-55,(byte)-54,(byte)-25,(byte)-37,(byte)-34,(byte)-58,(byte)-2,(byte)-48,(byte)-62,(byte)-38,(byte)-38,(byte)-36,(byte)-35,(byte)-38,(byte)-83,(byte)-56,(byte)-37,(byte)-35,(byte)-40,(byte)-20,(byte)-23,(byte)-10,(byte)-105,(byte)-13,(byte)-107,(byte)-59,(byte)-102,(byte)-99,(byte)-51,(byte)-14,(byte)-98,(byte)-63,(byte)-98,(byte)-54,(byte)-28,(byte)-12,(byte)-22,(byte)-2,(byte)-10,(byte)-32,(byte)-15,(byte)-10,(byte)-119,(byte)-20,(byte)-1,(byte)-8,(byte)-60,(byte)-16,(byte)-15,(byte)-22,(byte)-14,(byte)-121,(byte)-74,(byte)-96,(byte)-9,(byte)-109,(byte)-77,(byte)-99,(byte)-79,(byte)-117,(byte)-124,(byte)-87,(byte)-2,(byte)-121,(byte)-66,(byte)-83,(byte)-105,(byte)-124,(byte)-86,(byte)-101,(byte)-112,(byte)-108,(byte)-73,(byte)-107,(byte)-65,(byte)-105,(byte)-116,(byte)-103,(byte)-99,(byte)-112,(byte)-118,(byte)-102,(byte)-47,(byte)-81,(byte)-118,(byte)-127,(byte)-68,(byte)-85,(byte)-41,(byte)-123,(byte)-123,(byte)-118,(byte)-115,(byte)-78,(byte)-34,(byte)-44,(byte)-105,(byte)-116,(byte)-73,(byte)-56,(byte)-117,(byte)-86,(byte)-84,(byte)-89,(byte)-122,(byte)-107,(byte)-54,(byte)-51,(byte)-115,(byte)-77,(byte)-108,(byte)-98,(byte)-80,(byte)-78,(byte)84,(byte)106,(byte)117,(byte)78,(byte)110,(byte)76,(byte)53,(byte)74,(byte)76,(byte)92,(byte)58,(byte)70,(byte)88,(byte)64,(byte)116,(byte)88,(byte)120,(byte)114,(byte)92,(byte)94,(byte)110,(byte)126,(byte)97,(byte)90,(byte)114,(byte)80,(byte)99,(byte)86,(byte)88,(byte)72,(byte)46,(byte)82,(byte)116,(byte)108,(byte)88,(byte)116,(byte)78,(byte)103,(byte)124,(byte)106,(byte)121,(byte)90,(byte)93,(byte)104,(byte)125,(byte)116,(byte)106,(byte)121,(byte)97,(byte)96,(byte)117,(byte)118,(byte)67,(byte)127,(byte)122,(byte)98,(byte)82,(byte)124,(byte)110,(byte)118,(byte)126,(byte)120,(byte)121,(byte)126,(byte)113,(byte)20,(byte)7,(byte)1,(byte)60,(byte)8,(byte)13,(byte)18,(byte)123,(byte)31,(byte)121,(byte)41,(byte)126,(byte)121,(byte)41,(byte)22,(byte)98,(byte)61,(byte)98,(byte)54,(byte)0,(byte)16,(byte)14,(byte)26,(byte)26,(byte)12,(byte)29,(byte)26,(byte)109,(byte)8,(byte)27,(byte)28,(byte)24,(byte)44,(byte)45,(byte)54,(byte)86,(byte)35,(byte)18,(byte)4,(byte)91,(byte)63,(byte)31,(byte)49,(byte)21,(byte)47,(byte)32,(byte)13,(byte)66,(byte)59,(byte)2,(byte)17,(byte)51,(byte)32,(byte)14,(byte)63,(byte)60,(byte)56,(byte)27,(byte)57,(byte)27,(byte)51,(byte)40,(byte)61,(byte)-63,(byte)-52,(byte)-42,(byte)-58,(byte)-75,(byte)-53,(byte)-18,(byte)-27,(byte)-48,(byte)-57,(byte)-69,(byte)-23,(byte)-31,(byte)-18,(byte)-23,(byte)-42,(byte)-94,(byte)-88,(byte)-21,(byte)-16,(byte)-45,(byte)-84,(byte)-17,(byte)-50,(byte)-64,(byte)-53,(byte)-22,(byte)-7,(byte)-82,(byte)-87,(byte)-23,(byte)-8,(byte)-6,(byte)-46,(byte)-43,(byte)-26,(byte)-27,(byte)-4,(byte)-18,(byte)-20,(byte)-57,(byte)-13,(byte)-29,(byte)-47,(byte)-58,(byte)-99,(byte)-19,(byte)-18,(byte)-31,(byte)-24,(byte)-12,(byte)-8,(byte)-128,(byte)-16,(byte)-13,(byte)-10,(byte)-5,(byte)-12,(byte)-2,(byte)-36,(byte)-27,(byte)-28,(byte)-1,(byte)-3,(byte)-127,(byte)-122,(byte)-124,(byte)-80,(byte)-91,(byte)-15,(byte)-77,(byte)-78,(byte)-91,(byte)-72,(byte)-110,(byte)-96,(byte)-90,(byte)-105,(byte)-105,(byte)-94,(byte)-79,(byte)-94,(byte)-122,(byte)-66,(byte)-123,(byte)-121,(byte)-128,(byte)-68,(byte)-18,(byte)-77,(byte)-17,(byte)-23,(byte)-99,(byte)-103,(byte)-76,(byte)-82,(byte)-71,(byte)-112,(byte)-106,(byte)-74,(byte)-120,(byte)-54,(byte)-51,(byte)-98,(byte)-84,(byte)-89,(byte)-59,(byte)-92,(byte)-106,(byte)-116,(byte)-39,(byte)-100,(byte)-118,(byte)-64,(byte)-120,(byte)-91,(byte)-98,(byte)-60,(byte)-101,(byte)-90,(byte)-79,(byte)-86,(byte)-79,(byte)-79,(byte)-107,(byte)-82,(byte)-72,(byte)-78,(byte)85,(byte)85,(byte)48,(byte)59,(byte)61,(byte)113,(byte)119,(byte)126,(byte)82,(byte)91,(byte)51,(byte)109,(byte)70,(byte)123,(byte)77,(byte)77,(byte)126,(byte)72,(byte)67,(byte)105,(byte)114,(byte)68,(byte)82,(byte)66,(byte)89,(byte)92,(byte)35,(byte)40,(byte)68,(byte)127,(byte)119,(byte)121,(byte)67,(byte)77,(byte)81,(byte)114,(byte)106,(byte)14,(byte)81,(byte)111,(byte)7,(byte)106,(byte)73,(byte)92,(byte)74,(byte)120,(byte)108,(byte)86,(byte)115,(byte)70,(byte)92,(byte)122,(byte)95,(byte)96,(byte)15,(byte)68,(byte)106,(byte)119,(byte)87,(byte)119,(byte)112,(byte)87,(byte)103,(byte)104,(byte)8,(byte)2,(byte)14,(byte)116,(byte)29,(byte)0,(byte)15,(byte)3,(byte)36,(byte)61,(byte)61,(byte)47,(byte)123,(byte)57,(byte)5,(byte)59,(byte)98,(byte)3,(byte)23,(byte)59,(byte)60,(byte)30,(byte)46,(byte)103,(byte)30,(byte)31,(byte)53,(byte)52,(byte)27,(byte)53,(byte)51,(byte)39,(byte)17,(byte)15,(byte)39,(byte)43,(byte)55,(byte)36,(byte)39,(byte)81,(byte)18,(byte)58,(byte)36,(byte)34,(byte)85,(byte)43,(byte)8,(byte)4,(byte)70,(byte)63,(byte)24,(byte)62,(byte)51,(byte)48,(byte)1,(byte)51,(byte)15,(byte)32,(byte)62,(byte)45,(byte)46,(byte)77,(byte)42,(byte)62,(byte)-47,(byte)-55,(byte)-83,(byte)-63,(byte)-59,(byte)-48,(byte)-15,(byte)-58,(byte)-1,(byte)-52,(byte)-56,(byte)-92,(byte)-10,(byte)-52,(byte)-63,(byte)-51,(byte)-9,(byte)-33,(byte)-60,(byte)-37,(byte)-59,(byte)-83,(byte)-44,(byte)-42,(byte)-2,(byte)-95,(byte)-33,(byte)-39,(byte)-35,(byte)-48,(byte)-35,(byte)-34,(byte)-15,(byte)-8,(byte)-43,(byte)-21,(byte)-11,(byte)-4,(byte)-30,(byte)-15,(byte)-6,(byte)-103,(byte)-27,(byte)-23,(byte)-18,(byte)-12,(byte)-21,(byte)-23,(byte)-9,(byte)-45,(byte)-63,(byte)-25,(byte)-38,(byte)-98,(byte)-13,(byte)-12,(byte)-34,(byte)-19,(byte)-5,(byte)-16,(byte)-48,(byte)-28,(byte)-19,(byte)-44,(byte)-119,(byte)-111,(byte)-23,(byte)-85,(byte)-81,(byte)-124,(byte)-10,(byte)-10,(byte)-101,(byte)-2,(byte)-27,(byte)-122,(byte)-114,(byte)-11,(byte)-119,(byte)-114,(byte)-31,(byte)-124,(byte)-74,(byte)-102,(byte)-93,(byte)-124,(byte)-113,(byte)-102,(byte)-102,(byte)-72,(byte)-101,(byte)-99,(byte)-101,(byte)-65,(byte)-83,(byte)-117,(byte)-114,(byte)-54,(byte)-89,(byte)-96,(byte)-126,(byte)-79,(byte)-89,(byte)-84,(byte)-124,(byte)-80,(byte)-71,(byte)-128,(byte)-91,(byte)-67,(byte)-59,(byte)-121,(byte)-101,(byte)-80,(byte)-62,(byte)-62,(byte)-89,(byte)-62,(byte)-39,(byte)-70,(byte)-71,(byte)-106,(byte)-67,(byte)-72,(byte)-65,(byte)-116,(byte)-71,(byte)-84,(byte)77,(byte)53,(byte)59,(byte)65,(byte)69,(byte)72,(byte)67,(byte)70,(byte)60,(byte)78,(byte)71,(byte)74,(byte)72,(byte)78,(byte)76,(byte)102,(byte)81,(byte)91,(byte)81,(byte)82,(byte)113,(byte)82,(byte)91,(byte)112,(byte)91,(byte)85,(byte)47,(byte)72,(byte)122,(byte)73,(byte)75,(byte)102,(byte)67,(byte)123,(byte)117,(byte)71,(byte)15,(byte)22,(byte)17,(byte)12,(byte)75,(byte)120,(byte)99,(byte)109,(byte)127,(byte)67,(byte)27,(byte)106,(byte)1,(byte)112,(byte)72,(byte)127,(byte)125,(byte)113,(byte)65,(byte)6,(byte)72,(byte)74,(byte)11,(byte)83,(byte)89,(byte)82,(byte)105,(byte)80,(byte)20,(byte)43,(byte)114,(byte)39,(byte)9,(byte)124,(byte)21,(byte)23,(byte)37,(byte)30,(byte)8,(byte)36,(byte)99,(byte)25,(byte)34,(byte)24,(byte)10,(byte)35,(byte)48,(byte)39,(byte)16,(byte)97,(byte)17,(byte)46,(byte)16,(byte)107,(byte)12,(byte)18,(byte)107,(byte)43,(byte)36,(byte)108,(byte)23,(byte)10,(byte)18,(byte)33,(byte)93,(byte)50,(byte)81,(byte)8,(byte)60,(byte)80,(byte)56,(byte)42,(byte)7,(byte)36,(byte)47,(byte)3,(byte)5,(byte)48,(byte)20,(byte)34,(byte)50,(byte)59,(byte)51,(byte)6,(byte)59,(byte)22,(byte)35,(byte)21,(byte)24,(byte)43,(byte)59,(byte)6,(byte)-57,(byte)-23,(byte)-9,(byte)-74,(byte)-42,(byte)-17,(byte)-63,(byte)-77,(byte)-71,(byte)-69,(byte)-56,(byte)-38,(byte)-24,(byte)-61,(byte)-20,(byte)-25,(byte)-88,(byte)-56,(byte)-89,(byte)-35,(byte)-18,(byte)-49,(byte)-17,(byte)-6,(byte)-19,(byte)-83,(byte)-75,(byte)-63,(byte)-5,(byte)-86,(byte)-18,(byte)-36,(byte)-112,(byte)-62,(byte)-42,(byte)-42,(byte)-41,(byte)-109,(byte)-50,(byte)-61,(byte)-30,(byte)-111,(byte)-32,(byte)-98,(byte)-24,(byte)-57,(byte)-53,(byte)-60,(byte)-1,(byte)-12,(byte)-38,(byte)-123,(byte)-64,(byte)-31,(byte)-49,(byte)-113,(byte)-56,(byte)-42,(byte)-53,(byte)-11,(byte)-27,(byte)-2,(byte)-107,(byte)-56,(byte)-74,(byte)-119,(byte)-91,(byte)-126,(byte)-114,(byte)-94,(byte)-5,(byte)-51,(byte)-27,(byte)-28,(byte)-25,(byte)-26,(byte)-31,(byte)-120,(byte)-128,(byte)-117,(byte)-16,(byte)-110,(byte)-105,(byte)-127,(byte)-128,(byte)-100,(byte)-112,(byte)-98,(byte)-101,(byte)-104,(byte)-114,(byte)-98,(byte)-15,(byte)-16,(byte)-13,(byte)-14,(byte)-51});
         X509Certificate DRKOldCert = this.getX509Certificate(DRKOldCertPEM);
         X509Certificate DRKNewCert = this.getX509Certificate(DRKCertPEMfromKnox3_1);
         X509Certificate DRKNewCertv2 = this.getX509Certificate(DRKCertPEMfromKnox3_4);
         trustedCAs.add(new TrustAnchor(DRKOldCert, null));
         trustedCAs.add(new TrustAnchor(DRKNewCert, null));
         trustedCAs.add(new TrustAnchor(DRKNewCertv2, null));
         this.pkixParams = new PKIXParameters(trustedCAs);
         this.pkixParams.setRevocationEnabled(false);
         return this.pkixParams;
      }
   }


   private String isValidSignedData(byte[] data) {
      CMSSignedData signedData = null;

      try {
         signedData = new CMSSignedData(data);
      } catch (CMSException var16) {
         _logger.warn(zqw.pRx(new byte[] {(byte)112,(byte)-74,(byte)-13,(byte)75,(byte)-45,(byte)72,(byte)-38,(byte)83,(byte)-51,(byte)78,(byte)-16,(byte)59,(byte)-17,(byte)125,(byte)-5,(byte)99,(byte)-23,(byte)41,(byte)-16,(byte)98,(byte)-20,(byte)-108,(byte)30,(byte)-106,(byte)0,(byte)-104,(byte)0,(byte)-116,(byte)72,(byte)-106,(byte)11,(byte)-72,(byte)50,(byte)-72,(byte)34,(byte)-90,(byte)34,(byte)-88,(byte)112,(byte)-25,(byte)63,(byte)-68,(byte)30}), var16.getMessage(), var16);
         return null;
      }

      Store<X509CertificateHolder> certStore = signedData.getCertificates();
      SignerInformationStore signers = signedData.getSignerInfos();
      SignerInformation signer = (SignerInformation)signers.getSigners().iterator().next();
      @SuppressWarnings("unchecked")
      Iterator<X509CertificateHolder> certIter = certStore.getMatches(signer.getSID()).iterator();
      JcaSimpleSignerInfoVerifierBuilder jcaBuilder = new JcaSimpleSignerInfoVerifierBuilder().setProvider(zqw.ptc(new byte[] {(byte)-117,(byte)45,(byte)111,(byte)-75}));

      try {
         CertificateFactory cf = CertificateFactory.getInstance(zqw.pu(new byte[] {(byte)115,(byte)125,(byte)37,(byte)-81,(byte)-80,(byte)-71,(byte)-76}));
         int verified = 0;

         while (certIter.hasNext()) {
            X509Certificate cert = (X509Certificate)cf.generateCertificate(this.getByteArrayStream(certIter.next().getEncoded()));
            if (signer.verify(jcaBuilder.build(cert))) {
               verified++;
            }
         }

         if (verified < 1) {
            _logger.error(zqw.pty(new byte[] {(byte)106,(byte)76,(byte)24,(byte)109,(byte)-37,(byte)87,(byte)67,(byte)-128,(byte)-59,(byte)53,(byte)113,(byte)-87,(byte)-90,(byte)91,(byte)-103,(byte)-59,(byte)11,(byte)3,(byte)-75,(byte)-26,(byte)110,(byte)110,(byte)-82,(byte)15,(byte)83,(byte)-121,(byte)-51,(byte)57,(byte)54,(byte)-87,(byte)-25,(byte)51,(byte)-38,(byte)-48,(byte)9,(byte)87,(byte)-86,(byte)-28}));
            return null;
         } else if (!this.isValidCertChain(certStore)) {
            _logger.error(zqw.pR3(new byte[] {(byte)-42,(byte)-114,(byte)-35,(byte)123,(byte)-15,(byte)116,(byte)-1,(byte)86,(byte)-45,(byte)88,(byte)-53,(byte)18,(byte)-64,(byte)95,(byte)-52,(byte)43,(byte)-96,(byte)35,(byte)-83,(byte)51,(byte)-94,(byte)51,(byte)-79,(byte)12,(byte)-58,(byte)12,(byte)-113,(byte)27,(byte)-102,(byte)31,(byte)-102,(byte)-94,(byte)96,(byte)-27,(byte)124,(byte)-78,(byte)117,(byte)-1,(byte)108,(byte)-42,(byte)79,(byte)-52,(byte)71,(byte)-47,(byte)87,(byte)-50,(byte)91}));
            return null;
         } else {
            CMSTypedData msg = signedData.getSignedContent();
            return new String((byte[])msg.getContent());
         }
      } catch (CertificateException | IOException | OperatorCreationException | CMSException var12) {
         _logger.error(zqw.pRO(new byte[] {(byte)97,(byte)-61,(byte)-128,(byte)14,(byte)97,(byte)-49,(byte)10,(byte)109,(byte)-38,(byte)56,(byte)98,(byte)-33,(byte)54,(byte)-37,(byte)-64,(byte)35,(byte)-106,(byte)-8,(byte)40,(byte)-53,(byte)-10,(byte)73,(byte)-111,(byte)-28,(byte)65}), var12);
         return null;
      }
   }

   private X509Certificate getCertFromHolder(X509CertificateHolder holder) throws CertificateException {
      return new JcaX509CertificateConverter().setProvider(zqw.pQR(new byte[] {(byte)82,(byte)1,(byte)67,(byte)125})).getCertificate(holder);
   }

   private boolean isValidCertChain(Store certStore) {
      @SuppressWarnings("unchecked")
      List<X509CertificateHolder> holders = (List<X509CertificateHolder>)certStore.getMatches(null);
      List<X509Certificate> certs = new ArrayList<>();
      JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider(zqw.pRz(new byte[] {(byte)-113,(byte)-72,(byte)-6,(byte)116}));

      for (X509CertificateHolder holder : holders) {
         try {
            certs.add(certConverter.getCertificate(holder));
         } catch (CertificateException var14) {
            _logger.error(zqw.ptS(new byte[] {(byte)10,(byte)-17,(byte)-84,(byte)-59,(byte)11,(byte)86,(byte)-66,(byte)-28,(byte)34,(byte)101,(byte)-88,(byte)-20,(byte)29,(byte)-99,(byte)-63,(byte)28,(byte)70,(byte)-106}), var14);
         }
      }

      try {
         CertificateFactory cf = CertificateFactory.getInstance(zqw.pRP(new byte[] {(byte)55,(byte)10,(byte)82,(byte)-82,(byte)-61,(byte)92,(byte)-37}));
         CertPath certPath = cf.generateCertPath(certs);
         PKIXParameters params = this.getPKIXParameters();
         CertPathValidator cpv = CertPathValidator.getInstance(zqw.pty(new byte[] {(byte)-54,(byte)127,(byte)47,(byte)115,(byte)-72,(byte)-14}), zqw.p8(new byte[] {(byte)-64,(byte)41,(byte)107,(byte)16}));
         cpv.validate(certPath, params);
         return true;
      } catch (InvalidAlgorithmParameterException | NoSuchProviderException | CertificateException | CertPathValidatorException | NoSuchAlgorithmException var9) {
         _logger.error(zqw.pRx(new byte[] {(byte)120,(byte)-100,(byte)-33,(byte)124,(byte)-28,(byte)103,(byte)-7,(byte)107,(byte)-29,(byte)100,(byte)-27,(byte)117,(byte)27,(byte)-37,(byte)27,(byte)-99,(byte)19,(byte)-122,(byte)2,(byte)-55,(byte)5,(byte)-117,(byte)5,(byte)-66,(byte)49,(byte)-9,(byte)49,(byte)-93,(byte)60,(byte)-92,(byte)58}), var9);
         return false;
      }
   }

   private X509Certificate getX509Certificate(String PEM) {
      try {
         return (X509Certificate)CertificateFactory.getInstance(zqw.pw(new byte[] {(byte)-82,(byte)57,(byte)97,(byte)17,(byte)112,(byte)123,(byte)104})).generateCertificate(new ByteArrayInputStream(PEM.getBytes()));
      } catch (CertificateException var4) {
         _logger.error(zqw.ptQ(new byte[] {(byte)-53,(byte)-13,(byte)-125,(byte)-60,(byte)37,(byte)122,(byte)-46,(byte)3,(byte)120,(byte)-15,(byte)-15,(byte)90,(byte)-120,(byte)-19,(byte)107,(byte)-98,(byte)-54,(byte)19,(byte)103,(byte)-27,(byte)17,(byte)72,(byte)-78,(byte)-31,(byte)90,(byte)-107,(byte)-115}), var4);
         return null;
      }
   }

   public String getGCMDecryptedSignedData(byte[] sk, byte[] iv, String data) {
      byte[] msgArr = this.getGCMDecryptedDataBytes(sk, iv, data);
      String msg = null;
      if (msgArr != null) {
         msg = this.isValidSignedData(msgArr);
         _logger.debug(zqw.pQd(new byte[] {(byte)-27,(byte)4,(byte)64,(byte)61,(byte)-49,(byte)114,(byte)45,(byte)-40,(byte)-120,(byte)53,(byte)-64,(byte)-40,(byte)40,(byte)-63,(byte)-128,(byte)41,(byte)-68,(byte)-40,(byte)55,(byte)-15,(byte)-117,(byte)46,(byte)-15,(byte)-116,(byte)21,(byte)-86,(byte)-60,(byte)67,(byte)-15}), msg);
      }

      return msg;
   }

   public byte[] getGCMDecryptedDataBytes(byte[] sk, byte[] iv, String data) {
      IvParameterSpec IVSpec = new IvParameterSpec(iv);

      try {
         SecretKeySpec keySpec = new SecretKeySpec(sk, zqw.pl(new byte[] {(byte)110,(byte)11,(byte)74,(byte)123,(byte)34}));
         Cipher cipher = Cipher.getInstance(zqw.pRm(new byte[] {(byte)-51,(byte)108,(byte)45,(byte)83,(byte)-109,(byte)69,(byte)83,(byte)-3,(byte)37,(byte)61,(byte)-14,(byte)9,(byte)64,(byte)-37,(byte)0,(byte)106,(byte)-47,(byte)12,(byte)107}));
         cipher.init(2, keySpec, IVSpec);
         byte[] dataBytes = DatatypeConverter.parseBase64Binary(data);
         byte[] ret = cipher.doFinal(dataBytes);
         return ret;
      } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
               InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException var9) {
         _logger.error(zqw.ptx(new byte[] {(byte)8,(byte)-111,(byte)-42,(byte)10,(byte)76,(byte)-103,(byte)20,(byte)71,(byte)-126,(byte)-21,(byte)40,(byte)121,(byte)-75,(byte)16,(byte)94,(byte)-121,(byte)-127,(byte)60,(byte)99,(byte)-69,(byte)-18,(byte)75,(byte)-53,(byte)-119,(byte)26,(byte)100,(byte)-15}), var9.getMessage(), var9);
         return null;
      }
   }

   public byte[] getOAEPSessionKey(String sn, String XED) {
      if (!keystore.containsKey(sn)) {
         _logger.warn(zqw.p8(new byte[] {(byte)61,(byte)83,(byte)24,(byte)24,(byte)-34,(byte)-15,(byte)-107,(byte)74,(byte)59,(byte)89,(byte)-59,(byte)-94,(byte)-126,(byte)79,(byte)47,(byte)79,(byte)-65,(byte)-78,(byte)-114}), sn);
         return null;
      } else {
         PrivateKey privateKey = keystore.get(sn).getPrivateKey();
         byte[] XEDbytes = DatatypeConverter.parseBase64Binary(XED);

         try {
            Cipher cipher = Cipher.getInstance(zqw.pm(new byte[] {(byte)-19,(byte)58,(byte)104,(byte)61,(byte)-29,(byte)-7,(byte)68,(byte)81,(byte)28,(byte)-61,(byte)-11,(byte)65,(byte)3,(byte)51,(byte)-6,(byte)-119,(byte)123,(byte)50,(byte)18,(byte)-3,(byte)-86,(byte)87,(byte)123,(byte)63,(byte)-36,(byte)-126,(byte)87,(byte)9,(byte)-60,(byte)-121,(byte)-70,(byte)127,(byte)54,(byte)-30,(byte)-45,(byte)-128,(byte)69}), zqw.pQ4(new byte[] {(byte)51,(byte)55,(byte)117,(byte)-62}));
            cipher.init(2, privateKey);
            byte[] Kc = cipher.doFinal(Arrays.copyOfRange(XEDbytes, 12, XEDbytes.length));
            MessageDigest md = MessageDigest.getInstance(zqw.p3(new byte[] {(byte)98,(byte)-68,(byte)-17,(byte)-126,(byte)-103,(byte)-53,(byte)-58,(byte)55,(byte)38}));
            md.update(Kc);
            return md.digest();
         } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException var8) {
            _logger.error(zqw.pQH(new byte[] {(byte)-68,(byte)-11,(byte)-70,(byte)25,(byte)-2,(byte)78,(byte)-95,(byte)-128,(byte)34,(byte)-55,(byte)127,(byte)9,(byte)-93,(byte)66,(byte)-71,(byte)-103,(byte)45,(byte)-80,(byte)74,(byte)-6}), var8);
            return null;
         }
      }
   }

   public byte[] getServerSignature(String sn, byte[] msg) {
      PrivateKey privateKey = keystore.get(sn).getPrivateKey();

      try {
         Signature sign = Signature.getInstance(zqw.pRE(new byte[] {(byte)-78,(byte)-47,(byte)-126,(byte)36,(byte)70,(byte)-112,(byte)8,(byte)-18,(byte)4,(byte)103,(byte)-35,(byte)44,(byte)-115,(byte)41,(byte)84}));
         sign.initSign(privateKey);
         sign.update(msg);
         return sign.sign();
      } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException var6) {
         _logger.error(zqw.pQa(new byte[] {(byte)-98,(byte)110,(byte)61,(byte)-42,(byte)119,(byte)15,(byte)-45,(byte)119,(byte)33,(byte)-41,(byte)-109,(byte)103,(byte)-5,(byte)-101,(byte)95,(byte)-22,(byte)-88,(byte)68,(byte)17,(byte)-95,(byte)0,(byte)20,(byte)-80,(byte)97,(byte)11,(byte)-57}), var6);
         return null;
      }
   }

   public String getGCMEncryptedData(byte[] sk, byte[] iv, byte[] data) {
      IvParameterSpec IVSpec = new IvParameterSpec(iv);
      SecretKeySpec keySpec = new SecretKeySpec(sk, zqw.pRC(new byte[] {(byte)-110,(byte)69,(byte)4,(byte)-101,(byte)36}));

      try {
         Cipher cipher = Cipher.getInstance(zqw.pRq(new byte[] {(byte)-92,(byte)5,(byte)68,(byte)-10,(byte)50,(byte)32,(byte)-6,(byte)40,(byte)84,(byte)-24,(byte)59,(byte)76,(byte)-127,(byte)30,(byte)73,(byte)-65,(byte)-32,(byte)89,(byte)-126}));
         cipher.init(1, keySpec, IVSpec);
         byte[] ret = cipher.doFinal(data);
         return ret == null ? null : DatatypeConverter.printBase64Binary(ret);
      } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
               InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException var8) {
         _logger.error(zqw.pR3(new byte[] {(byte)127,(byte)121,(byte)62,(byte)-66,(byte)-52,(byte)37,(byte)-20,(byte)99,(byte)-14,(byte)103,(byte)-32,(byte)109,(byte)-43,(byte)76,(byte)-58,(byte)67,(byte)-111,(byte)80,(byte)-53,(byte)79,(byte)-82,(byte)55}), var8);
         return null;
      }
   }

   public String getGCMEncryptedData(byte[] sk, byte[] iv, String data) {
      return this.getGCMEncryptedData(sk, iv, DatatypeConverter.parseBase64Binary(data));
   }

   public String getGCMDecryptedData(byte[] sk, byte[] iv, String data) {
      String decryptedString = null;
      byte[] decryptedBytes = this.getGCMDecryptedDataBytes(sk, iv, data);
      if (decryptedBytes != null) {
         decryptedString = new String(decryptedBytes);
      }

      return decryptedString;
   }

}
