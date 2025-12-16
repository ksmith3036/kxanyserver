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
            responseBody = "FORBIDDEN";
         }

         response.setContentLength(responseBody.length());
         response.getOutputStream().write(responseBody.getBytes());
      } catch (IOException var4) {
         _logger.warn("Exception for http response: {} ", var4.getMessage(), var4);
      }
   }

   /*
   TODO Remove
   private String getReplayResponse(String rnaVersion, String signature) {
      if (this.isRnaV4(rnaVersion)) {
         return "{\"payLoad\":{\"responseCode\": 6001 ,\"responseMessage\":\"Invalid request\"},\"signature\":\"" + signature + "\"}";
      }
      return "{\"statusCode\": \"3001\" ,\"statusMessage\":\"Invalid request\",\"signature\":\"" + signature + "\"}";
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
         req.setAttribute("kryptoHandled", true);
         chain.doFilter(req, res);
      } else {
       */
      /*
      TODO Remove
      _logger.debug(
              "X-SS : {}, X-SN : {}, X-SK : {}, X-ED : {}, Content-Type : {}, client_request_time_stamp : {}",
              new Object[]{
                      hreq.getHeader(RnaHeader.XSS.getValue()),
                      hreq.getHeader(RnaHeader.XSN.getValue()),
                      hreq.getHeader(RnaHeader.XSK.getValue()),
                      hreq.getHeader(RnaHeader.XED.getValue()),
                      hreq.getHeader("Content-Type"),
                      hreq.getHeader(RnaHeader.TIMESTAMP.getValue())
              }
      );
      _logger.info(
              "Request path: {}, Headers validity : {} ",
              hreq.getRequestURI(),
              hreq.getHeader(RnaHeader.XSK.getValue()) != null || hreq.getHeader(RnaHeader.XED.getValue()) != null
      );
       */

      if (hreq.getHeader(RnaHeader.XSN.getValue()) == null
              || hreq.getHeader(RnaHeader.XSK.getValue()) == null && hreq.getHeader(RnaHeader.XED.getValue()) == null) {
         _logger.info("KnoxCryptoFilter is called, headers not present");
         // TODO: Call AesFilter: chain.doFilter(req, res);
      } else {
         _logger.info("KnoxCryptoFilter is called, headers present");
         //req.setAttribute("kryptoHandled", true);
         this.handleRNARequest(req, res, processor);
      }
   }

   /*
   TODO Remove
   private void logHeaders(HttpServletRequest hreq) {
      _logger.warn(
         "Request path: {}, X-SS : {}, X-SN : {}, X-SK : {}, X-ED : {}, Content-Type : {}, client_request_time_stamp : {}",
         new Object[]{
            hreq.getRequestURI(),
            hreq.getHeader(RnaHeader.XSS.getValue()),
            hreq.getHeader(RnaHeader.XSN.getValue()),
            hreq.getHeader(RnaHeader.XSK.getValue()),
            hreq.getHeader(RnaHeader.XED.getValue()),
            hreq.getHeader("Content-Type"),
            hreq.getHeader(RnaHeader.TIMESTAMP.getValue())
         }
      );
   }
    */

   private void printError(HttpServletResponse response, int httpStatus) {
      response.setStatus(httpStatus);
      createHTTPResponse(response, "FORBIDDEN", "application/knox-crypto-stream");
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
            _logger.warn("Request path: {}, SK is null, invalid header values", hreq.getRequestURI());
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
                  "Request URI: {} is replay request, server time: {} ms, client time: {} ms",
                  new Object[]{hreq.getRequestURI(), currentServerTime, clientReqTime}
               );
               String responseStr = "";
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
            "HTTP method: {}, path: {}, TimeOut while reading http request body: {}",
            new Object[]{hreq.getMethod(), hreq.getServletPath(), var16.getMessage()}
         );
         this.printError403(hres, hreq);
      } catch (KxRequestEntityTooLargeException var17) {
         _logger.error("Request: {} too large, max: {}", hreq.getRequestURI(), 1048576);
         this.printError413(hres);
         return;
      } catch (IOException | ServletException var18) {
         _logger.warn(
            "Request: {}, exception during decrypting request body: {} ", new Object[]{hreq.getRequestURI(), var18.getMessage(), var18}
         );
         this.printError403(hres, hreq);
         return;
      }

      byte[] resBytes = resWrapper.getOutputBytes();
      String encRetMsg = cryptoUtil.getEncryptedResponse(resBytes, xss, sk, xsn, hres);
      createHTTPResponse(hres, encRetMsg, "application/knox-crypto-stream");
      _logger.info("Request path: {}, RNA processing complete", hreq.getRequestURI());
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
      String ekey = "";
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
