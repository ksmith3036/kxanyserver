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
            _logger.info(zqw.ptO(new byte[] {(byte)-3,(byte)68,(byte)1,(byte)73,(byte)105,(byte)-97,(byte)-87,(byte)-61,(byte)-30,(byte)16,(byte)50,(byte)88,(byte)2,(byte)119,(byte)-115,(byte)-70,(byte)-37,(byte)-12,(byte)7,(byte)35,(byte)26,(byte)123,(byte)111,(byte)-111,(byte)-26,(byte)-109,(byte)-84,(byte)20,(byte)47}), SS);
            body = cryptoUtil.getDecryptedData(Arrays.copyOfRange(sk, 0, 32), Arrays.copyOfRange(sk, 32, 48), inStr);
         } else if (RnaVersion.V3.getValue().equalsIgnoreCase(SS)) {
            _logger.info(zqw.pQ6(new byte[] {(byte)-67,(byte)115,(byte)54,(byte)-47,(byte)104,(byte)37,(byte)-38,(byte)-97,(byte)79,(byte)-18,(byte)-67,(byte)120,(byte)75,(byte)-59,(byte)102,(byte)62,(byte)-18,(byte)-126,(byte)64,(byte)11,(byte)-21,(byte)113,(byte)12,(byte)-35,(byte)-37,(byte)125,(byte)-77,(byte)-92,(byte)86}), SS);
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
            _logger.warn(zqw.pQM(new byte[] {(byte)30,(byte)-57,(byte)-107,(byte)87,(byte)-20,(byte)125,(byte)22,(byte)-83,(byte)61,(byte)-108,(byte)123,(byte)-17,(byte)-106,(byte)18,(byte)-78,(byte)70,(byte)-43,(byte)101,(byte)24,(byte)-116,(byte)109,(byte)-34,(byte)66,(byte)-25,(byte)-107,(byte)1,(byte)-85}));
            throw new IOException(zqw.pQT(new byte[] {(byte)-112,(byte)-62,(byte)-112,(byte)109,(byte)63,(byte)-31,(byte)-65,(byte)83,(byte)18,(byte)-116,(byte)-106,(byte)93,(byte)29,(byte)-74,(byte)115,(byte)32,(byte)-30,(byte)-75,(byte)77,(byte)6,(byte)-114,(byte)-110,(byte)91,(byte)-23,(byte)-86,(byte)105,(byte)54}));
         }
      } catch (SocketTimeoutException var8) {
         _logger
            .warn(
               zqw.pRS(new byte[] {(byte)23,(byte)6,(byte)78,(byte)-46,(byte)82,(byte)-42,(byte)38,(byte)-21,(byte)99,(byte)-14,(byte)110,(byte)-23,(byte)98,(byte)-68,(byte)38,(byte)-3,(byte)123,(byte)-86,(byte)38,(byte)-10,(byte)103,(byte)-14,(byte)110,(byte)-68,(byte)38,(byte)-3,(byte)123,(byte)-86,(byte)38,(byte)-46,(byte)111,(byte)-21,(byte)99,(byte)-55,(byte)115,(byte)-14,(byte)38,(byte)-15,(byte)110,(byte)-17,(byte)106,(byte)-29,(byte)38,(byte)-12,(byte)99,(byte)-25,(byte)98,(byte)-17,(byte)104,(byte)-31,(byte)38,(byte)-18,(byte)114,(byte)-14,(byte)118,(byte)-90,(byte)116,(byte)-29,(byte)119,(byte)-13,(byte)99,(byte)-11,(byte)114,(byte)-90,(byte)60,(byte)-90,(byte)125,(byte)-5}),
               new Object[]{request.getMethod(), request.getServletPath(), var8.getMessage()}
            );
         throw var8;
      } catch (KxRequestEntityTooLargeException var9) {
         _logger.warn(zqw.pQG(new byte[] {(byte)75,(byte)-90,(byte)-12,(byte)109,(byte)27,(byte)-71,(byte)75,(byte)-29,(byte)-122,(byte)116,(byte)-62,(byte)119,(byte)21,(byte)-4,(byte)82,(byte)-63,(byte)112,(byte)3,(byte)-93,(byte)4,(byte)-86,(byte)-127,(byte)47,(byte)-56,(byte)40,(byte)84,(byte)-83,(byte)69}), 1048576);
         throw var9;
      } catch (IOException var10) {
         _logger.warn(zqw.pRY(new byte[] {(byte)-99,(byte)7,(byte)85,(byte)-12,(byte)106,(byte)-48,(byte)74,(byte)-54,(byte)55,(byte)-19,(byte)51,(byte)-124,(byte)8,(byte)-121,(byte)6,(byte)121,(byte)-25,(byte)116,(byte)-56,(byte)95,(byte)-101,(byte)35,(byte)-82,(byte)48,(byte)-113,(byte)8,(byte)-109}), var10.getMessage());
         throw var10;
      } catch (Exception var11) {
         _logger.warn(zqw.pk(new byte[] {(byte)58,(byte)118,(byte)36,(byte)-13,(byte)-57,(byte)-93,(byte)-109,(byte)101,(byte)66,(byte)118,(byte)18,(byte)-13,(byte)-43,(byte)-92,(byte)-113,(byte)102,(byte)66,(byte)63,(byte)25,(byte)-8,(byte)-106,(byte)-80,(byte)-105,(byte)127,(byte)90,(byte)51,(byte)18}), var11.getMessage());
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

         throw new KxRequestEntityTooLargeException(zqw.puv(new byte[] {(byte)54,(byte)109,(byte)63,(byte)59,(byte)62,(byte)53,(byte)84,(byte)81,(byte)103,(byte)36,(byte)-112,(byte)-120,(byte)-93,(byte)-95,(byte)-51,(byte)-45,(byte)-69,(byte)-8,(byte)18,(byte)1,(byte)127,(byte)60,(byte)32,(byte)64,(byte)68,(byte)113}));
      } catch (IOException var8) {
         _logger.warn(zqw.pRY(new byte[] {(byte)-18,(byte)6,(byte)79,(byte)-2,(byte)106,(byte)-47,(byte)90,(byte)-104,(byte)49,(byte)-72,(byte)36,(byte)-123,(byte)11,(byte)-103,(byte)94,(byte)107,(byte)-3,(byte)114,(byte)-48,(byte)85,(byte)-56,(byte)55,(byte)-89,(byte)55,(byte)-116,(byte)76,(byte)-112,(byte)-31,(byte)99,(byte)-8,(byte)123,(byte)-52,(byte)8,(byte)-100,(byte)61,(byte)-83}), var8.getMessage());
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
      return getHeader(zqw.pRh(new byte[] {(byte)-52,(byte)48,(byte)83,(byte)-84,(byte)56,(byte)-99,(byte)25,(byte)97,(byte)-42,(byte)24,(byte)-68,(byte)34,(byte)-98,(byte)-28}));
   }

   public String getHeader(String name) {
      if (zqw.pl(new byte[] {(byte)-55,(byte)-32,(byte)-125,(byte)124,(byte)40,(byte)13,(byte)-55,(byte)-79,(byte)102,(byte)104,(byte)12,(byte)-46,(byte)-82,(byte)116}).equals(name.toLowerCase(Locale.ENGLISH))) {
         return zqw.pQn(new byte[] {(byte)-70,(byte)-112,(byte)-15,(byte)112,(byte)0,(byte)-116,(byte)57,(byte)-93,(byte)81,(byte)-44,(byte)121,(byte)-17,(byte)-98,(byte)79,(byte)-70,(byte)51,(byte)-33,(byte)78});
      } else if (zqw.pRg(new byte[] {(byte)-5,(byte)-60,(byte)-68,(byte)123,(byte)-101,(byte)17,(byte)33,(byte)-10,(byte)85,(byte)-70}).equals(name.toLowerCase(Locale.ENGLISH))) {
         return zqw.pQN(new byte[] {(byte)105,(byte)121,(byte)17,(byte)-128,(byte)41,(byte)-18,(byte)98});
      } else if (RnaHeader.XDCC_VERIFIED.getValue().equalsIgnoreCase(name)) {
         return this.isDccVerified ? zqw.p5(new byte[] {(byte)-54,(byte)15,(byte)123,(byte)109,(byte)90,(byte)90}) : zqw.po(new byte[] {(byte)-25,(byte)-53,(byte)-83,(byte)96,(byte)91,(byte)30,(byte)-58});
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
