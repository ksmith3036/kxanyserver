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
      convertAndSaveEncryptionKey("4112a48093cdae42b1611566050787dfa279fb8cd52dab5dd83e87d6398ba920", xsn, encDER);
   }

   public static void convertAndSaveELMEncryptionKey(String xsn, String encDER) {
      convertAndSaveEncryptionKey("fedded01fa4fada7a44947356db11aa8ed217e121cc6db3770c2fc624eb4b53d", xsn, encDER);
   }

   public byte[] getSessionKey(HttpServletRequest hreq) {
      _logger.info("Creating session key from headers");
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
      String ret = "";
      if (arr != null && arr.length >= 1) {
         int printLen = 0;
         if (arr.length > 500) {
            printLen = 500;
         } else {
            printLen = arr.length;
         }

         for (int i = 0; i < printLen; i++) {
            ret = ret + String.format("%02X", arr[i]);
         }

         return ret;
      } else {
         return "";
      }
   }

   public String getEncryptedResponse(byte[] resBytes, String rnaVersion, byte[] sessionKey, String serialNo, HttpServletResponse hres) {
      String encRetMsg = null;
      if (resBytes != null && resBytes.length > 0) {
         _logger.info("Response RNA version: {}", rnaVersion);
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
            BigInteger bigIV = new BigInteger(Arrays.copyOfRange(sessionKey, 32, 48)).add(new BigInteger("1"));
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
      _logger.debug("Create session key for: {},{}", sn, sk);
      if (!keystore.containsKey(sn)) {
         _logger.info("Missing key: {}", sn);
         return null;
      } else {
         byte[] encSK = DatatypeConverter.parseBase64Binary(sk);
         KxKeyData key = keystore.get(sn);
         if (encSK.length > key.getBits()) {
            _logger.warn("Wrong message length");
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

            _logger.debug("Padded length: {} msgIndex: {}", paddedMsg.length, msgIndex);
            _logger.debug("Session Key: {}", this.printArr(Arrays.copyOfRange(paddedMsg, msgIndex, paddedMsg.length)));
            return Arrays.copyOfRange(paddedMsg, msgIndex, paddedMsg.length);
         }
      }
   }

   public String getDecryptedData(byte[] sk, String data) {
      return this.getDecryptedData(sk, Arrays.copyOfRange(sk, 0, 16), data);
   }

   public String getDecryptedData(byte[] sk, byte[] iv, String data) {
      _logger.debug("Decrypt data: {}", data);
      Aes256Cbc aes = new Aes256Cbc();
      byte[] encStr = DatatypeConverter.parseBase64Binary(data);
      if (sk.length == 32 && encStr.length % 16 == 0) {
         byte[] msgArr = aes.decrypt(encStr, sk, iv);
         String msg = new String(msgArr);
         _logger.debug("Decrypted data: {}", msg);
         return msg;
      } else {
         _logger.error("Encryption length is wrong in Decrypt");
         return null;
      }
   }

   public String getDecryptedSignedData(byte[] sk, byte[] iv, String data) {
      _logger.debug("Decrypt signed data: {}", data);
      Aes256Cbc aes = new Aes256Cbc();
      byte[] encStr = DatatypeConverter.parseBase64Binary(data);
      if (sk.length == 32 && encStr.length % 16 == 0) {
         byte[] msgArr = aes.decrypt(encStr, sk, iv);
         String msg = this.isValidSignedData(msgArr);
         _logger.debug("Decrypted Data (signed): {}", msg);
         return msg;
      } else {
         _logger.error("Encryption length is wrong, length: {}, body: {}", sk.length, encStr.length);
         return null;
      }
   }

   public String getEncryptedData(byte[] sk, byte[] data) {
      return this.getEncryptedData(sk, Arrays.copyOfRange(sk, 0, 16), data);
   }

   public String getEncryptedData(byte[] sk, byte[] iv, byte[] data) {
      Aes256Cbc aes = new Aes256Cbc();
      if (sk.length != 32) {
         _logger.error("Crypto length is wrong in Encrypt");
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
         String QACertPEM = "-----BEGIN CERTIFICATE-----\nMIIDlTCCAn2gAwIBAgIJANUUxGaItOboMA0GCSqGSIb3DQEBCwUAMGExCzAJBgNVBAYTAktSMRIwEAYDVQQIDAlLeXVuZ2tpZG8xDjAMBgNVBAcMBVN1d29uMRwwGgYDVQQKDBNTYW1zdW5nIEVsZWN0cm9uaWNzMRAwDgYDVQQLDAdLbm94IENBMB4XDTE0MDkwNTA2NTUyMloXDTM0MDgzMTA2NTUyMlowYTELMAkGA1UEBhMCS1IxEjAQBgNVBAgMCUt5dW5na2lkbzEOMAwGA1UEBwwFU3V3b24xHDAaBgNVBAoME1NhbXN1bmcgRWxlY3Ryb25pY3MxEDAOBgNVBAsMB0tub3ggQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCikptyNjLg9UFwwbnKpBkvczkrCPb70wc/X4Aer2WDJPz8IMZ1OyWiS2kJTsITj0yefy9qqmv82VMFoCvvMqtmXu4hBLfC96oTvR2apURYm2wNsh2FB6ALL0AQ1NjfFMOVetwd/+IHlD5SbNyvnp5Uknbf8N+kLcd/55BPjt2DIO3aFt9B4WygxsM8OsqJNPck2a/7fxCsNRoi05pZsTEmsi9zgUBGiXfB/XBbryDKIYK5P4sFVDKBB/j+gfg+vCy18BqgbwEgGTXocPSx2xEVXhMGrR0oCuAUzVtBUOWISSlYO/voZcV0BeyfvvfV56+CoZ/u+J0o6dlKtfrDoX+LAgMBAAGjUDBOMB0GA1UdDgQWBBRmqeUaWyBbUNYXYLt6ze1PT9rDojAfBgNVHSMEGDAWgBRmqeUaWyBbUNYXYLt6ze1PT9rDojAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCTRrC1tXQb4QWYc+XoQ7whoXpXrJTvAas66q4CRvRNcGWl7xUkkYtIzIjK8AatXtVvr6olNpUNaIUABTvVT3nctyPaneCXxo8S+4dIcqyjgCqf9HgFd/OAHqw7nmgieVjB0PW1sTXqAwL8gjgaTvCSLHq9El3L+Aj57676Kp7y65NOYXBjq0UOBoAjfuhVe7K7/mv9KrAGWrSm9FERmaoSJrZ4jQ+aDPq/jD23jtuoHNdNFZ8dWmHIHRZT1gMAYopb6D/2FD/E/jypIT8yvsuElXcffkouj6Yai3FGMzDIKNofM2Fh+AqTfPoaDZKX9GmPiszXVAegL6Sj6xD9+R7l\n-----END CERTIFICATE-----";
         X509Certificate QACert = this.getX509Certificate(QACertPEM);
         trustedCAs.add(new TrustAnchor(QACert, null));
         String DRKOldCertPEM = "-----BEGIN CERTIFICATE-----\nMIIDkjCCAnqgAwIBAgIJAO6ORukA8ikRMA0GCSqGSIb3DQEBCwUAMFkxCzAJBgNVBAYTAktSMRMwEQYDVQQHDApTdXdvbiBjaXR5MRcwFQYDVQQLDA5TYW1zdW5nIE1vYmlsZTEcMBoGA1UEAwwTU2Ftc3VuZyBjb3Jwb3JhdGlvbjAeFw0xMzA1MzAxMzExNTRaFw0zMzA1MjUxMzExNTRaMFkxCzAJBgNVBAYTAktSMRMwEQYDVQQHDApTdXdvbiBjaXR5MRcwFQYDVQQLDA5TYW1zdW5nIE1vYmlsZTEcMBoGA1UEAwwTU2Ftc3VuZyBjb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAODCgYdVr9LR4I2jcoAjufYxgN8JMQbbUrCYWphrHlzzUG1mv4KjqyZCe1oNugY/5OQOhlWnelmkw9VtwpvDfsA4M0PDvIUIrWXq719omUzE511VleSDDigSFp/UxMZsDO8cCYDBtfk1QufH7s+GOgXdlBuswnzbICFubGqkO4v0FSXJMqKHAKruddKp+4YO2tbFer52qDu9blEZo9Qgi2cw3iPCKZ5r0+T0PnX7heBuUUcUskQd8Ozp5MThRf5QbE6KEb9aswpHDSBEIM+L5c3x4Bt3bq0ktJHWn00NTeUyklhKdJAGbdVfUTqxMt1X/lsCHq8WDCHCXdddtKMkEd0CAwEAAaNdMFswHQYDVR0OBBYEFBo4SVkuMiGCDHcmDcoRrd2cykN9MB8GA1UdIwQYMBaAFBo4SVkuMiGCDHcmDcoRrd2cykN9MAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBT2Ut7c95FD8pv6OrMhCpq0oLKzYVkvPrGSFT6GOlZ+g2j5w8PQltVhayyJL/CUOHMdViJI5oWDCsRx06qpulZWhjF1saAn3ZK40dnI3H1HhtO1b8ezt+YdXQPPAomjLVacNrrlZIvDNOL59/3pSqmW2AwNUusNzxr9vplO+GywFTR6C51zPSj+Nvyhrqt5W/XtaiQO/GK6Asrn1+38ovHkE3LuSvseK9656DWOLzcGlpEjFODn3K6a7y7jtJ875SPbjBJ4r6+mz7YhtDQz3bY4lRTx7qXKHXnyvdMTSMPCuYzggMhZky7HvqWZdZFuZ0t+qY1AnJADO/zbBCLOwta\n-----END CERTIFICATE-----";
         String DRKCertPEMfromKnox3_1 = "-----BEGIN CERTIFICATE-----\nMIICjzCCAfCgAwIBAgIEWQK/tDAKBggqhkjOPQQDAjBZMQswCQYDVQQGEwJLUjETMBEGA1UEBxMKU3V3b24gY2l0eTEXMBUGA1UECxMOU2Ftc3VuZyBNb2JpbGUxHDAaBgNVBAMTE1NhbXN1bmcgY29ycG9yYXRpb24wHhcNMTcwNDI4MDQwNjEyWhcNMzcwNDIzMDQwNjEyWjBZMQswCQYDVQQGEwJLUjETMBEGA1UEBxMKU3V3b24gY2l0eTEXMBUGA1UECxMOU2Ftc3VuZyBNb2JpbGUxHDAaBgNVBAMTE1NhbXN1bmcgY29ycG9yYXRpb24wgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGz1COv/9ESGRdbuNSqNj0o3BZpzivn6R1QaT5NmNGjVgRrjsDHCPoAmxs6OjhCweJhGJZMQu8V6K4GwqrK4XTHIAAq8Oh8GqsSrX8KTGjabPtDg1B6zeDhqFKO2BRKHSTzl9jDAeMJ4vJnmQSqAcb06k4fnboUUAreyVJSALxE5tvHK6NjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFA2g7yBXBWdctoFVFEkd9zyQ9BO6MB8GA1UdIwQYMBaAFA2g7yBXBWdctoFVFEkd9zyQ9BO6MAoGCCqGSM49BAMCA4GMADCBiAJCANEFD3SFc3gWkMbm142lCpvjV6bt++/mBUUJCsLiyECe/HESJNQpvebXssVai1h0AHGpVrENpGz3pqQuO00+HyRAAkIBU1Cou6PxjFSxJ0t2zrjv2g54tDXaxGaSH57QQa1cHTKuP5pjbXTkE+IQoAfA2chKOzpVkhgk3zRkRPonXPI1Usg=\n-----END CERTIFICATE-----";
         String DRKCertPEMfromKnox3_4 = "-----BEGIN CERTIFICATE-----\nMIICjzCCAfCgAwIBAgIEXHYjDTAKBggqhkjOPQQDBDBZMQswCQYDVQQGEwJLUjETMBEGA1UEBxMKU3V3b24gY2l0eTEXMBUGA1UECxMOU2Ftc3VuZyBNb2JpbGUxHDAaBgNVBAMTE1NhbXN1bmcgY29ycG9yYXRpb24wHhcNMTkwMjI3MDU0MTMzWhcNMzkwMjIyMDU0MTMzWjBZMQswCQYDVQQGEwJLUjETMBEGA1UEBxMKU3V3b24gY2l0eTEXMBUGA1UECxMOU2Ftc3VuZyBNb2JpbGUxHDAaBgNVBAMTE1NhbXN1bmcgY29ycG9yYXRpb24wgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGFsa4uumqXkjZYmasTmQRVk6j52ADjqYqtUl/+yDN/Oza7sz1zVj1mQISKJiSFMUT289tqyZR9fJvCBnYQzfQDUAE93XbifclsQN+wH/CcwfUByCwnIkU9sRNmLLjYWHCL7YEIDltwd7tKt2REhhKx0FFooGhmxqnEHSAA6zSNI9Ffk6NjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFGbsTn+ECfTAKlYSkIP+hkA01S7/MB8GA1UdIwQYMBaAFGbsTn+ECfTAKlYSkIP+hkA01S7/MAoGCCqGSM49BAMEA4GMADCBiAJCAeGMgCL5SfTUycZWd+37+cQIFSn5E1AzLIDw1ps1heoWoTj0dM9SPmWBo/TlWZrbtD4GyH2VI7vz3wkpB9W7oT9RAkIAluAfQFNEqCoYndVEyGhu5RjG412BQdNbh8Y5NzZymu4/Zg7pC0ctus6hdJ8J5DjekOEh6tTy8poqNYC+wvHgAJg=\n-----END CERTIFICATE-----";
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
         _logger.warn("Exception while validating signature: {} ", var16.getMessage(), var16);
         return null;
      }

      Store<X509CertificateHolder> certStore = signedData.getCertificates();
      SignerInformationStore signers = signedData.getSignerInfos();
      SignerInformation signer = (SignerInformation)signers.getSigners().iterator().next();
      @SuppressWarnings("unchecked")
      Iterator<X509CertificateHolder> certIter = certStore.getMatches(signer.getSID()).iterator();
      JcaSimpleSignerInfoVerifierBuilder jcaBuilder = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC");

      try {
         CertificateFactory cf = CertificateFactory.getInstance("X.509");
         int verified = 0;

         while (certIter.hasNext()) {
            X509Certificate cert = (X509Certificate)cf.generateCertificate(this.getByteArrayStream(certIter.next().getEncoded()));
            if (signer.verify(jcaBuilder.build(cert))) {
               verified++;
            }
         }

         if (verified < 1) {
            _logger.error("The signed data is invalid for certs");
            return null;
         } else if (!this.isValidCertChain(certStore)) {
            _logger.error("Signature verification failed for certificate");
            return null;
         } else {
            CMSTypedData msg = signedData.getSignedContent();
            return new String((byte[])msg.getContent());
         }
      } catch (CertificateException | IOException | OperatorCreationException | CMSException var12) {
         _logger.error("Certificate check error", var12);
         return null;
      }
   }

   private X509Certificate getCertFromHolder(X509CertificateHolder holder) throws CertificateException {
      return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
   }

   private boolean isValidCertChain(Store certStore) {
      @SuppressWarnings("unchecked")
      List<X509CertificateHolder> holders = (List<X509CertificateHolder>)certStore.getMatches(null);
      List<X509Certificate> certs = new ArrayList<>();
      JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");

      for (X509CertificateHolder holder : holders) {
         try {
            certs.add(certConverter.getCertificate(holder));
         } catch (CertificateException var14) {
            _logger.error("Conversion error", var14);
         }
      }

      try {
         CertificateFactory cf = CertificateFactory.getInstance("X.509");
         CertPath certPath = cf.generateCertPath(certs);
         PKIXParameters params = this.getPKIXParameters();
         CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
         cpv.validate(certPath, params);
         return true;
      } catch (InvalidAlgorithmParameterException | NoSuchProviderException | CertificateException | CertPathValidatorException | NoSuchAlgorithmException var9) {
         _logger.error("Certificate chain check error", var9);
         return false;
      }
   }

   private X509Certificate getX509Certificate(String PEM) {
      try {
         return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(PEM.getBytes()));
      } catch (CertificateException var4) {
         _logger.error("parsing root cert failed.", var4);
         return null;
      }
   }

   public String getGCMDecryptedSignedData(byte[] sk, byte[] iv, String data) {
      byte[] msgArr = this.getGCMDecryptedDataBytes(sk, iv, data);
      String msg = null;
      if (msgArr != null) {
         msg = this.isValidSignedData(msgArr);
         _logger.debug("Decrypted data (signed): {}", msg);
      }

      return msg;
   }

   public byte[] getGCMDecryptedDataBytes(byte[] sk, byte[] iv, String data) {
      IvParameterSpec IVSpec = new IvParameterSpec(iv);

      try {
         SecretKeySpec keySpec = new SecretKeySpec(sk, "AES");
         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
         cipher.init(2, keySpec, IVSpec);
         byte[] dataBytes = DatatypeConverter.parseBase64Binary(data);
         byte[] ret = cipher.doFinal(dataBytes);
         return ret;
      } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
               InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException var9) {
         _logger.error("GCM encryption error: {} ", var9.getMessage(), var9);
         return null;
      }
   }

   public byte[] getOAEPSessionKey(String sn, String XED) {
      if (!keystore.containsKey(sn)) {
         _logger.warn("Key not found: {}", sn);
         return null;
      } else {
         PrivateKey privateKey = keystore.get(sn).getPrivateKey();
         byte[] XEDbytes = DatatypeConverter.parseBase64Binary(XED);

         try {
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
            cipher.init(2, privateKey);
            byte[] Kc = cipher.doFinal(Arrays.copyOfRange(XEDbytes, 12, XEDbytes.length));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Kc);
            return md.digest();
         } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException var8) {
            _logger.error("OAEP decrypt error", var8);
            return null;
         }
      }
   }

   public byte[] getServerSignature(String sn, byte[] msg) {
      PrivateKey privateKey = keystore.get(sn).getPrivateKey();

      try {
         Signature sign = Signature.getInstance("SHA256withRSA");
         sign.initSign(privateKey);
         sign.update(msg);
         return sign.sign();
      } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException var6) {
         _logger.error("Signature creation error", var6);
         return null;
      }
   }

   public String getGCMEncryptedData(byte[] sk, byte[] iv, byte[] data) {
      IvParameterSpec IVSpec = new IvParameterSpec(iv);
      SecretKeySpec keySpec = new SecretKeySpec(sk, "AES");

      try {
         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
         cipher.init(1, keySpec, IVSpec);
         byte[] ret = cipher.doFinal(data);
         return ret == null ? null : DatatypeConverter.printBase64Binary(ret);
      } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
               InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException var8) {
         _logger.error("GCM encryption error", var8);
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
