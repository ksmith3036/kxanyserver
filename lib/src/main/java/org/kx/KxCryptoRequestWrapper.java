package org.kx;

// Fixed

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.Locale;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import javax.xml.bind.DatatypeConverter;

public class KxCryptoRequestWrapper extends HttpServletRequestWrapper {
   Logger _logger = LoggerFactory.getLogger(KxCryptoRequestWrapper.class);
   String body;
   String hexSK = null;
   boolean isDccVerified = false;

   public KxCryptoRequestWrapper(HttpServletRequest request, byte[] sk) throws IOException, KxRequestEntityTooLargeException {
      super(request);
      KxCryptoUtil cryptoUtil = KxCryptoUtil.getInstance();
      String SS = request.getHeader(RnaHeader.XSS.getValue());
      String XED = request.getHeader(RnaHeader.XED.getValue());
      String inStr = null;

      try {
         inStr = this.getRequestString(request.getInputStream());
         this.hexSK = DatatypeConverter.printHexBinary(sk);
         if (RnaVersion.V1.getValue().equalsIgnoreCase(SS) || RnaVersion.V2.getValue().equalsIgnoreCase(SS)) {
            _logger.info("Encrypting request for : {}", SS);
            body = cryptoUtil.getDecryptedData(Arrays.copyOfRange(sk, 0, 32), Arrays.copyOfRange(sk, 32, 48), inStr);
         } else if (RnaVersion.V3.getValue().equalsIgnoreCase(SS)) {
            _logger.info("Encrypting request for : {}", SS);
            body = cryptoUtil.getDecryptedSignedData(Arrays.copyOfRange(sk, 0, 32), Arrays.copyOfRange(sk, 32, 48), inStr);
            this.isDccVerified = true;
         } else if (RnaVersion.V4A.getValue().equalsIgnoreCase(SS)) {
            byte[] xed = DatatypeConverter.parseBase64Binary(XED);
            body = cryptoUtil.getGCMDecryptedData(sk, Arrays.copyOfRange(xed, 0, 12), inStr);
         } else if (RnaVersion.V4B.getValue().equalsIgnoreCase(SS)) {
            byte[] xed = DatatypeConverter.parseBase64Binary(XED);
            body = cryptoUtil.getGCMDecryptedSignedData(sk, Arrays.copyOfRange(xed, 0, 12), inStr);
            this.isDccVerified = true;
         } else {
            body = cryptoUtil.getDecryptedData(sk, inStr);
         }

         if (body == null) {
            _logger.warn("Request decryption failed");
            throw new IOException("Request decryption failed");
         }
      } catch (SocketTimeoutException var8) {
         _logger
            .warn(
               "HTTP method: {}, path: {}, TimeOut while reading http request : {}",
               new Object[]{request.getMethod(), request.getServletPath(), var8.getMessage()}
            );
         throw var8;
      } catch (KxRequestEntityTooLargeException var9) {
         _logger.warn("Request too large, max: {}", 1048576);
         throw var9;
      } catch (IOException var10) {
         _logger.warn("Request decryption failed", var10.getMessage());
         throw var10;
      } catch (Exception var11) {
         _logger.warn("Request decryption failed", var11.getMessage());
         throw new IOException(var11);
      }
   }

   private String getRequestString(ServletInputStream sis) throws IOException, KxRequestEntityTooLargeException {
      final int BUFLEN = 2048;

      try {
         byte[] buffer = new byte[BUFLEN];
         StringBuilder ret = new StringBuilder();
         int requestLength = 0;
         do {
            int res = sis.read(buffer, 0, BUFLEN);
            if (res < 0) {
               return ret.toString();
            }

            ret.append(this.getStringFromBytes(buffer, 0, res));
            requestLength += BUFLEN;
         } while (requestLength <= 1048576);

         throw new KxRequestEntityTooLargeException("Request entity too large");
      } catch (IOException var8) {
         _logger.warn("Input stream conversion failed: {}", var8.getMessage());
         throw var8;
      }
   }

   private String getStringFromBytes(byte[] bytes, int offset, int length) {
      return new String(bytes, offset, length);
   }

   public ServletInputStream getInputStream() throws IOException {
      final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(body.getBytes());
      return new ServletInputStream() {
         public int read() throws IOException {
            return byteArrayInputStream.read();
         }

         public boolean isFinished() {
            return byteArrayInputStream.available() == 0;
         }

         public boolean isReady() {
            return true;
         }

         public void setReadListener(ReadListener readListener) {
         }
      };
   }

   @Override
   public String getContentType() {
      return getHeader("content-type");
   }

   public String getHeader(String name) {
      if ("content-type".equals(name.toLowerCase(Locale.ENGLISH))) {
         return "application/json";
      } else if ("x-sk-hex".equals(name.toLowerCase(Locale.ENGLISH))) {
         return "hexSK";
      } else if (RnaHeader.XDCC_VERIFIED.getValue().equalsIgnoreCase(name)) {
         return this.isDccVerified ? "true" : "false";
      } else {
         return super.getHeader(name);
      }
   }

   public String getBody() {
      return body;
   }

   public BufferedReader getReader() throws IOException {
      return new BufferedReader(new InputStreamReader(this.getInputStream()));
   }
}
