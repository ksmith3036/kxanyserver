package org.kx;

// Fixed

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.security.Security;
import java.util.Set;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class KxCrypto  {
   private static final Logger _logger = LoggerFactory.getLogger(KxCrypto.class);

   private static final Set<KxKeyStore> kxKeyStore = Configuration.getKeyStore();

   public static void createHTTPResponse(HttpServletResponse response, String responseBody, String contentType) {
      response.setContentType(contentType);
      response.resetBuffer();

      try {
         if (responseBody == null) {
            response.setStatus(403);
            responseBody = zqw.ptQ(new byte[] {(byte)120,(byte)1,(byte)71,(byte)-4,(byte)55,(byte)85,(byte)-128,(byte)63,(byte)105,(byte)-102,(byte)-33});
         }

         response.setContentLength(responseBody.length());
         response.getOutputStream().write(responseBody.getBytes());
      } catch (IOException var4) {
         _logger.warn(zqw.pte(new byte[] {(byte)98,(byte)-58,(byte)-125,(byte)-23,(byte)63,(byte)66,(byte)-126,(byte)-55,(byte)-31,(byte)60,(byte)112,(byte)-55,(byte)-46,(byte)16,(byte)56,(byte)53,(byte)-120,(byte)-33,(byte)2,(byte)49,(byte)44,(byte)-91,(byte)-57,(byte)30,(byte)72,(byte)108,(byte)-96,(byte)-22,(byte)1,(byte)21,(byte)-38,(byte)-66,(byte)-19,(byte)123}), var4.getMessage(), var4);
      }
   }

   /*
   TODO Remove
   private String getReplayResponse(String rnaVersion, String signature) {
      if (this.isRnaV4(rnaVersion)) {
         return zqw.pQf(new byte[] {(byte)17,(byte)53,(byte)78,(byte)-87,(byte)-111,(byte)86,(byte)-12,(byte)-81,(byte)86,(byte)-18,(byte)-127,(byte)25,(byte)-85,(byte)-100,(byte)31,(byte)-31,(byte)-116,(byte)76,(byte)-27,(byte)-124,(byte)47,(byte)-28,(byte)-120,(byte)0,(byte)-10,(byte)-117,(byte)32,(byte)-71,(byte)-53,(byte)103,(byte)-85,(byte)-61,(byte)121,(byte)-82,(byte)-43,(byte)103,(byte)-125,(byte)-123,(byte)40,(byte)-48,(byte)-119,(byte)32,(byte)-53,(byte)-120,(byte)52,(byte)-22,(byte)-104,(byte)32,(byte)-38,(byte)-98,(byte)50,(byte)-50,(byte)35,(byte)109,(byte)-113,(byte)74,(byte)55,(byte)-39,(byte)100,(byte)55,(byte)-40,(byte)99,(byte)125,(byte)-63,(byte)108,(byte)46,(byte)-64,(byte)110,(byte)18,(byte)-61,(byte)47,(byte)30,(byte)-107,(byte)45,(byte)22,(byte)-46,(byte)118,(byte)9,(byte)-36,(byte)103,(byte)28,(byte)-51,(byte)112,(byte)73,(byte)-5,(byte)53}) + signature + zqw.pQO(new byte[] {(byte)93,(byte)-95,(byte)-125,(byte)115});
      }
      return zqw.ptR(new byte[] {(byte)24,(byte)-80,(byte)-53,(byte)65,(byte)101,(byte)-67,(byte)29,(byte)91,(byte)-105,(byte)-26,(byte)11,(byte)-108,(byte)-54,(byte)4,(byte)54,(byte)-3,(byte)90,(byte)15,(byte)-45,(byte)-93,(byte)118,(byte)-56,(byte)-114,(byte)127,(byte)62,(byte)-25,(byte)11,(byte)95,(byte)-65,(byte)-27,(byte)49,(byte)-124,(byte)-25,(byte)56,(byte)99,(byte)-80,(byte)23,(byte)78,(byte)-71,(byte)-83,(byte)120,(byte)-41,(byte)-31,(byte)53,(byte)120,(byte)-96,(byte)24,(byte)78,(byte)-66,(byte)-83,(byte)50,(byte)-106,(byte)-41,(byte)44,(byte)105,(byte)-52,(byte)6,(byte)7,(byte)-12,(byte)-87,(byte)77,(byte)-104,(byte)-61,(byte)57,(byte)107,(byte)-55,(byte)5,(byte)81,(byte)-77,(byte)-85,(byte)6,(byte)-51}) + signature + zqw.pRT(new byte[] {(byte)98,(byte)78,(byte)108,(byte)-78});
   }

   private int getReplayHTTPError(String rnaVersion) {
      return this.isRnaV4(rnaVersion) ? 400 : 403;
   }

   private boolean isRnaV4(String rnaVersion) {
      return rnaVersion != null && (rnaVersion.equalsIgnoreCase(RnaVersion.V4A.getValue()) || rnaVersion.equalsIgnoreCase(RnaVersion.V4B.getValue()));
   }
*/

   public void doEncryption(ServletRequest req, ServletResponse res, KxRequestRunner processor) throws IOException, ServletException {
      HttpServletRequest hreq = (HttpServletRequest) req;
      /*
      TODO Remove
      if (FilterUtil.checkForExclusions(hreq.getRequestURI())) {
         req.setAttribute(zqw.pQJ(new byte[] {(byte)-48,(byte)-121,(byte)-20,(byte)-99,(byte)46,(byte)-49,(byte)83,(byte)-32,(byte)-65,(byte)62,(byte)-87,(byte)75,(byte)-5,(byte)-102,(byte)3}), true);
         chain.doFilter(req, res);
      } else {
       */
      /*
      TODO Remove
      _logger.debug(
              zqw.pr(new byte[] {(byte)-122,(byte)88,(byte)0,(byte)-68,(byte)-103,(byte)80,(byte)28,(byte)79,(byte)-114,(byte)-100,(byte)93,(byte)117,(byte)-78,(byte)-109,(byte)41,(byte)110,(byte)56,(byte)-113,(byte)-46,(byte)1,(byte)33,(byte)-18,(byte)-32,(byte)37,(byte)102,(byte)90,(byte)-29,(byte)-94,(byte)2,(byte)97,(byte)-76,(byte)-74,(byte)123,(byte)19,(byte)88,(byte)-23,(byte)-57,(byte)102,(byte)24,(byte)-75,(byte)-12,(byte)39,(byte)59,(byte)4,(byte)-98,(byte)-53,(byte)103,(byte)50,(byte)-8,(byte)-69,(byte)109,(byte)47,(byte)14,(byte)-98,(byte)-72,(byte)92,(byte)46,(byte)-14,(byte)-16,(byte)51,(byte)98,(byte)0,(byte)-55,(byte)-63,(byte)6,(byte)60,(byte)-12,(byte)-72,(byte)111,(byte)45,(byte)8,(byte)-22,(byte)-100,(byte)66,(byte)17,(byte)-20,(byte)-73,(byte)120,(byte)48,(byte)34,(byte)-62,(byte)-122,(byte)69,(byte)4,(byte)-59,(byte)-96,(byte)120,(byte)36,(byte)19,(byte)-57,(byte)-48,(byte)19,(byte)66,(byte)-32,(byte)-87}),
              new Object[]{
                      hreq.getHeader(RnaHeader.XSS.getValue()),
                      hreq.getHeader(RnaHeader.XSN.getValue()),
                      hreq.getHeader(RnaHeader.XSK.getValue()),
                      hreq.getHeader(RnaHeader.XED.getValue()),
                      hreq.getHeader(zqw.pQi(new byte[] {(byte)-18,(byte)-63,(byte)-126,(byte)117,(byte)29,(byte)-72,(byte)64,(byte)16,(byte)-93,(byte)29,(byte)-35,(byte)-101,(byte)75,(byte)-15})),
                      hreq.getHeader(RnaHeader.TIMESTAMP.getValue())
              }
      );
      _logger.info(
              zqw.pQj(new byte[] {(byte)38,(byte)58,(byte)104,(byte)-15,(byte)-97,(byte)61,(byte)-57,(byte)-113,(byte)34,(byte)-112,(byte)122,(byte)5,(byte)-54,(byte)112,(byte)72,(byte)-20,(byte)93,(byte)-3,(byte)-10,(byte)20,(byte)-58,(byte)-115,(byte)35,(byte)-8,(byte)-109,(byte)34,(byte)-39,(byte)36,(byte)40,(byte)-39,(byte)126,(byte)5,(byte)-94,(byte)73,(byte)14,(byte)-83,(byte)14,(byte)-78,(byte)-62,(byte)71,(byte)-21,(byte)-48}),
              hreq.getRequestURI(),
              hreq.getHeader(RnaHeader.XSK.getValue()) != null || hreq.getHeader(RnaHeader.XED.getValue()) != null
      );
       */

      if (hreq.getHeader(RnaHeader.XSN.getValue()) == null
              || hreq.getHeader(RnaHeader.XSK.getValue()) == null && hreq.getHeader(RnaHeader.XED.getValue()) == null) {
         _logger.info(zqw.pQQ(new byte[] {(byte)-88,(byte)-21,(byte)-96,(byte)73,(byte)12,(byte)-25,(byte)-104,(byte)101,(byte)42,(byte)-1,(byte)-65,(byte)104,(byte)5,(byte)22,(byte)-41,(byte)-125,(byte)86,(byte)29,(byte)-117,(byte)-114,(byte)80,(byte)127,(byte)-8,(byte)-74,(byte)127,(byte)35,(byte)-18,(byte)-93,(byte)47,(byte)31,(byte)19,(byte)-46,(byte)-110,(byte)75,(byte)14,(byte)-43,(byte)-112,(byte)63,(byte)53,(byte)-8,(byte)-89,(byte)47,(byte)59,(byte)-11,(byte)-90,(byte)-116,(byte)94,(byte)25,(byte)-57}));
         // TODO: Call AesFilter: chain.doFilter(req, res);
      } else {
         _logger.info(zqw.pt6(new byte[] {(byte)-29,(byte)126,(byte)53,(byte)46,(byte)109,(byte)-68,(byte)-59,(byte)58,(byte)115,(byte)-68,(byte)-6,(byte)63,(byte)84,(byte)-67,(byte)-6,(byte)44,(byte)127,(byte)-82,(byte)-66,(byte)9,(byte)81,(byte)-60,(byte)-59,(byte)9,(byte)70,(byte)-128,(byte)-53,(byte)20,(byte)30,(byte)-44,(byte)-34,(byte)29,(byte)91,(byte)-104,(byte)-37,(byte)-14,(byte)49,(byte)36,(byte)-74,(byte)-6,(byte)47,(byte)127,(byte)-85,(byte)-2,(byte)38}));
         //req.setAttribute("kryptoHandled", true);
         this.handleRNARequest(req, res, processor);
      }
   }

   /*
   TODO Remove
   private void logHeaders(HttpServletRequest hreq) {
      _logger.warn(
         zqw.pRf(new byte[] {(byte)77,(byte)4,(byte)86,(byte)-16,(byte)87,(byte)-62,(byte)45,(byte)-86,(byte)30,(byte)-37,(byte)-4,(byte)124,(byte)-38,(byte)87,(byte)-22,(byte)65,(byte)-119,(byte)-2,(byte)56,(byte)-123,(byte)110,(byte)-22,(byte)11,(byte)-70,(byte)90,(byte)49,(byte)-68,(byte)86,(byte)-61,(byte)99,(byte)-64,(byte)41,(byte)47,(byte)-64,(byte)106,(byte)-107,(byte)124,(byte)-9,(byte)19,(byte)-124,(byte)-90,(byte)59,(byte)-12,(byte)16,(byte)-99,(byte)20,(byte)-48,(byte)-69,(byte)50,(byte)-40,(byte)73,(byte)-23,(byte)118,(byte)-65,(byte)85,(byte)76,(byte)-34,(byte)11,(byte)-122,(byte)109,(byte)-91,(byte)18,(byte)44,(byte)-79,(byte)97,(byte)-36,(byte)42,(byte)-95,(byte)3,(byte)-103,(byte)-4,(byte)52,(byte)-2,(byte)66,(byte)-68,(byte)56,(byte)-50,(byte)69,(byte)48,(byte)-38,(byte)79,(byte)-17,(byte)116,(byte)-122,(byte)26,(byte)110,(byte)-3,(byte)71,(byte)-50,(byte)20,(byte)-82,(byte)8,(byte)-113,(byte)-6,(byte)69,(byte)-62,(byte)54,(byte)-116,(byte)16,(byte)-100,(byte)-21,(byte)114,(byte)-9,(byte)74,(byte)-66,(byte)58,(byte)-127,(byte)13,(byte)46,(byte)-91,(byte)16,(byte)-70,(byte)47}),
         new Object[]{
            hreq.getRequestURI(),
            hreq.getHeader(RnaHeader.XSS.getValue()),
            hreq.getHeader(RnaHeader.XSN.getValue()),
            hreq.getHeader(RnaHeader.XSK.getValue()),
            hreq.getHeader(RnaHeader.XED.getValue()),
            hreq.getHeader(zqw.pRu(new byte[] {(byte)-120,(byte)-16,(byte)-77,(byte)5,(byte)-118,(byte)42,(byte)-67,(byte)60,(byte)-72,(byte)107,(byte)-108,(byte)67,(byte)-60,(byte)75})),
            hreq.getHeader(RnaHeader.TIMESTAMP.getValue())
         }
      );
   }
    */

   private void printError(HttpServletResponse response, int httpStatus) {
      response.setStatus(httpStatus);
      createHTTPResponse(response, zqw.ptY(new byte[] {(byte)32,(byte)18,(byte)84,(byte)-104,(byte)-50,(byte)35,(byte)111,(byte)-81,(byte)-12,(byte)48,(byte)116}), zqw.p3(new byte[] {(byte)-31,(byte)39,(byte)70,(byte)69,(byte)51,(byte)61,(byte)54,(byte)14,(byte)26,(byte)-3,(byte)-2,(byte)-54,(byte)-35,(byte)-18,(byte)-92,(byte)-77,(byte)-124,(byte)-127,(byte)42,(byte)118,(byte)81,(byte)72,(byte)79,(byte)57,(byte)52,(byte)68,(byte)4,(byte)-15,(byte)-31,(byte)-60,(byte)-50,(byte)-48}));
   }

   private void printError403(HttpServletResponse res, HttpServletRequest hreq) {
      //this.logHeaders(hreq);
      this.printError(res, 403);
   }

   private void printError413(HttpServletResponse res) {
      this.printError(res, 413);
   }

   protected void handleRNARequest(ServletRequest req, ServletResponse res, KxRequestRunner processor) {
      HttpServletRequest hreq = (HttpServletRequest)req;
      HttpServletResponse hres = (HttpServletResponse)res;
      String xsn = hreq.getHeader(RnaHeader.XSN.getValue());
      String xss = hreq.getHeader(RnaHeader.XSS.getValue());
      String clientReqTime = hreq.getHeader(RnaHeader.TIMESTAMP.getValue());
      KxCryptoUtil cryptoUtil = KxCryptoUtil.getInstance();
      byte[] sk = cryptoUtil.getSessionKey(hreq);
      KxByteArrayResponseWrapper resWrapper = new KxByteArrayResponseWrapper(hres);

      try {
         if (sk == null) {
            _logger.warn(zqw.pQ7(new byte[] {(byte)100,(byte)2,(byte)80,(byte)3,(byte)-69,(byte)91,(byte)-9,(byte)-123,(byte)46,(byte)-98,(byte)82,(byte)-25,(byte)-98,(byte)38,(byte)-120,(byte)54,(byte)1,(byte)-93,(byte)110,(byte)-122,(byte)89,(byte)37,(byte)-14,(byte)95,(byte)-23,(byte)-34,(byte)12,(byte)-77,(byte)70,(byte)-30,(byte)-34,(byte)118,(byte)-45,(byte)112,(byte)-12,(byte)-121,(byte)38,(byte)-57,(byte)118,(byte)86,(byte)-78,(byte)91,(byte)-61,(byte)98,(byte)15,(byte)-68,(byte)18,(byte)-32,(byte)-101,(byte)50,(byte)-73,(byte)67,(byte)-7}), hreq.getRequestURI());
            this.printError403(hres, hreq);
            return;
         }

         //_logger.info("SK is not null, valid header values");
         KxCryptoRequestWrapper reqWrapper = new KxCryptoRequestWrapper(hreq, sk);
         /*
         TODO Remove
         if (!FilterUtil.isSignatureCheckByPass(hreq.getRequestURL().toString())) {
            long currentServerTime = DateTimeUtil.getCalendar().getTimeInMillis();
            if (clientReqTime == null || FilterUtil.isReplayRequest(currentServerTime, Long.valueOf(clientReqTime))) {
               _logger.warn(
                  zqw.pQa(new byte[] {(byte)-36,(byte)-46,(byte)-128,(byte)70,(byte)5,(byte)-80,(byte)115,(byte)20,(byte)-52,(byte)41,(byte)15,(byte)-7,(byte)-75,(byte)119,(byte)-66,(byte)-108,(byte)61,(byte)-79,(byte)-117,(byte)64,(byte)-92,(byte)-89,(byte)67,(byte)7,(byte)-92,(byte)120,(byte)19,(byte)-101,(byte)126,(byte)56,(byte)-33,(byte)-118,(byte)53,(byte)-46,(byte)-122,(byte)111,(byte)-76,(byte)-106,(byte)83,(byte)-11,(byte)-82,(byte)76,(byte)8,(byte)-21,(byte)104,(byte)4,(byte)-45,(byte)106,(byte)90,(byte)-111,(byte)121,(byte)46,(byte)-124,(byte)-104,(byte)53,(byte)-69,(byte)-56,(byte)90,(byte)-26,(byte)-78,(byte)73,(byte)19,(byte)-70,(byte)63,(byte)4,(byte)-88,(byte)127,(byte)6,(byte)-114,(byte)37,(byte)45,(byte)-38,(byte)-40,(byte)36,(byte)-23}),
                  new Object[]{hreq.getRequestURI(), currentServerTime, clientReqTime}
               );
               String responseStr = zqw.pR5(new byte[] {(byte)-28,(byte)-99});
               responseStr = this.getReplayResponse(xss, FilterUtil.getRequestSignature(reqWrapper.getBody()));
               responseStr = cryptoUtil.getEncryptedResponse(responseStr.getBytes(), xss, sk, xsn, hres);
               this.printError(hres, this.getReplayHTTPError(xss), responseStr);
               return;
            }
         }
          */

         processor.run(reqWrapper, resWrapper);
      } catch (SocketTimeoutException var16) {
         _logger.warn(
            zqw.pRY(new byte[] {(byte)-110,(byte)-116,(byte)-60,(byte)66,(byte)-12,(byte)122,(byte)-108,(byte)83,(byte)-83,(byte)38,(byte)-76,(byte)9,(byte)-108,(byte)64,(byte)36,(byte)-11,(byte)101,(byte)-114,(byte)12,(byte)-58,(byte)33,(byte)-66,(byte)60,(byte)-28,(byte)72,(byte)-119,(byte)1,(byte)42,(byte)-80,(byte)78,(byte)-51,(byte)67,(byte)-35,(byte)13,(byte)-71,(byte)34,(byte)-64,(byte)29,(byte)-100,(byte)23,(byte)100,(byte)-9,(byte)60,(byte)-44,(byte)85,(byte)-37,(byte)32,(byte)-89,(byte)54,(byte)-123,(byte)76,(byte)-98,(byte)-12,(byte)126,(byte)-28,(byte)62,(byte)-38,(byte)87,(byte)-51,(byte)51,(byte)-75,(byte)41,(byte)-112,(byte)78,(byte)-102,(byte)-19,(byte)104,(byte)-17,(byte)26,(byte)-118,(byte)79,(byte)-61}),
            new Object[]{hreq.getMethod(), hreq.getServletPath(), var16.getMessage()}
         );
         this.printError403(hres, hreq);
      } catch (KxRequestEntityTooLargeException var17) {
         _logger.error(zqw.pRS(new byte[] {(byte)95,(byte)-70,(byte)-24,(byte)95,(byte)-53,(byte)79,(byte)-33,(byte)73,(byte)-50,(byte)0,(byte)-102,(byte)65,(byte)-57,(byte)26,(byte)-50,(byte)85,(byte)-43,(byte)26,(byte)-42,(byte)91,(byte)-56,(byte)93,(byte)-33,(byte)22,(byte)-102,(byte)87,(byte)-37,(byte)66,(byte)-128,(byte)26,(byte)-63,(byte)71}), hreq.getRequestURI(), 1048576);
         this.printError413(hres);
         return;
      } catch (IOException | ServletException var18) {
         _logger.warn(
            zqw.ptw(new byte[] {(byte)14,(byte)37,(byte)119,(byte)-71,(byte)-30,(byte)63,(byte)100,(byte)-53,(byte)27,(byte)28,(byte)-3,(byte)-17,(byte)54,(byte)46,(byte)-103,(byte)21,(byte)95,(byte)-67,(byte)-16,(byte)60,(byte)119,(byte)-45,(byte)30,(byte)70,(byte)-1,(byte)-14,(byte)56,(byte)118,(byte)-46,(byte)28,(byte)78,(byte)-64,(byte)-13,(byte)43,(byte)102,(byte)-50,(byte)10,(byte)90,(byte)-107,(byte)-15,(byte)33,(byte)97,(byte)-99,(byte)6,(byte)78,(byte)-109,(byte)-20,(byte)53,(byte)116,(byte)-54,(byte)85,(byte)78,(byte)-116,(byte)-2,(byte)40,(byte)50,(byte)-97,(byte)13,(byte)80,(byte)-60}), new Object[]{hreq.getRequestURI(), var18.getMessage(), var18}
         );
         this.printError403(hres, hreq);
         return;
      }

      byte[] resBytes = resWrapper.getOutputBytes();
      String encRetMsg = cryptoUtil.getEncryptedResponse(resBytes, xss, sk, xsn, hres);
      createHTTPResponse(hres, encRetMsg, zqw.puV(new byte[] {(byte)-111,(byte)-9,(byte)-106,(byte)-128,(byte)-103,(byte)-114,(byte)-78,(byte)-73,(byte)-84,(byte)-78,(byte)-42,(byte)-41,(byte)-33,(byte)-123,(byte)-56,(byte)-14,(byte)-6,(byte)-10,(byte)-86,(byte)-29,(byte)11,(byte)11,(byte)27,(byte)16,(byte)50,(byte)123,(byte)60,(byte)60,(byte)51,(byte)95,(byte)82,(byte)65}));
      _logger.info(zqw.pQd(new byte[] {(byte)-27,(byte)-100,(byte)-50,(byte)-107,(byte)53,(byte)-19,(byte)-119,(byte)51,(byte)-32,(byte)-56,(byte)76,(byte)-15,(byte)-112,(byte)80,(byte)-74,(byte)-64,(byte)79,(byte)-11,(byte)-16,(byte)16,(byte)-42,(byte)-106,(byte)109,(byte)-96,(byte)-92,(byte)90,(byte)19,(byte)-77,(byte)65,(byte)11,(byte)-65,(byte)73,(byte)26,(byte)-81,(byte)60,(byte)19,(byte)-85,(byte)117,(byte)28,(byte)-84,(byte)113,(byte)28,(byte)-39}), hreq.getRequestURI());
   }

   public KxCrypto() {
      Security.addProvider(new BouncyCastleProvider());
//      ServletContext servletContext = config.getServletContext();
//      WebApplicationContext webApplicationContext = WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
//      AutowireCapableBeanFactory autowireCapableBeanFactory = webApplicationContext.getAutowireCapableBeanFactory();
//      autowireCapableBeanFactory.configureBean(this, "knoxcryptofilter");
      this.loadRnaKeys();
   }

   private void loadRnaKeys() {
      for (KxKeyStore keyStore : kxKeyStore) {
         String key = keyStore.getKey();
         String encDER = keyStore.getEncder();
         KxCryptoUtil.convertAndSaveEncryptionKey(key, encDER);
      }
   }

   public void destroy() {
   }

   /*
   TODO Remove
   public String getAesEncKey(boolean isWindows, String linuxKey1, String linuxKey2, String linuxKey3, String windowsKey) {
      String ekey = zqw.pRf(new byte[] {(byte)-36,(byte)-101});
      if (isWindows) {
         ekey = OnPremiseAgent.getInstance().getOrigString(windowsKey);
      } else {
         ekey = OnPremiseAgent.getInstance().getOrigString(linuxKey1)
            + OnPremiseAgent.getInstance().getOrigString(linuxKey2)
            + OnPremiseAgent.getInstance().getOrigString(linuxKey3);
      }

      return ekey;
   }
    */

}
