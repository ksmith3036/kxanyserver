package org.kx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@WebServlet("/*")
public class KxServlet extends HttpServlet {

    private static final Logger _logger = LoggerFactory.getLogger(KxServlet.class);

    private static KxCrypto kxCrypto;
    private static final KxRequestRunner deviceInstallV4Handler = KxDeviceInstallV4Handler.getDeviceInstallV4Handler();
    private static final KxRequestRunner deviceUninstallV4Handler = KxDeviceUninstallV4Handler.getDeviceUninstallV4Handler();
    private static final KxRequestRunner deviceValidateV4Handler = KxDeviceValidateV4Handler.getDeviceValidateV4Handler();

    private void serve(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (kxCrypto == null) {
            kxCrypto = new KxCrypto();
        }

        try {
            _logger.info(zqw.pg(new byte[] {(byte)35,(byte)-92,(byte)-23,(byte)-91,(byte)-88,(byte)-112,(byte)123,(byte)84,(byte)108,(byte)11,(byte)-27,(byte)-52,(byte)-48,(byte)-30,(byte)-44,(byte)107,(byte)81,(byte)104,(byte)2,(byte)-14,(byte)-13,(byte)-43,(byte)-12,(byte)-117,(byte)113,(byte)4,(byte)100,(byte)21,(byte)14,(byte)-12,(byte)-114,(byte)-16,(byte)-105,(byte)117}), request.getMethod(), request.getRemoteAddr(), request.getRequestURL().toString());
            String uri = request.getRequestURI();
            if (uri.equals(zqw.pRy(new byte[] {(byte)-41,(byte)57,(byte)22,(byte)-4,(byte)91,(byte)-36,(byte)73,(byte)-24,(byte)126,(byte)-25,(byte)107,(byte)-120,(byte)85,(byte)-52,(byte)77,(byte)-10,(byte)126,(byte)-30})) && request.getMethod().equals(zqw.puy(new byte[] {(byte)118,(byte)-37,(byte)-100,(byte)-118,(byte)-105}))) {
                handleKnoxPolicy(response);
            }
            else if (uri.equals(zqw.pQ(new byte[] {(byte)55,(byte)110,(byte)65,(byte)36,(byte)30,(byte)30,(byte)10,(byte)52,(byte)39,(byte)57,(byte)52,(byte)88,(byte)20,(byte)22,(byte)21,(byte)16,(byte)9,(byte)13,(byte)81,(byte)20,(byte)-20,(byte)-20,(byte)-15})) && request.getMethod().equals(zqw.pu5(new byte[] {(byte)6,(byte)-125,(byte)-45,(byte)48,(byte)40,(byte)35}))) {
                handleKnoxServerLookup(request, response);
            }
            else if (uri.equals(zqw.ptA(new byte[] {(byte)80,(byte)81,(byte)126,(byte)72,(byte)-103,(byte)-86,(byte)-76,(byte)25,(byte)88,(byte)124,(byte)-107,(byte)-100,(byte)-13,(byte)99,(byte)6,(byte)-97,(byte)-88,(byte)-23,(byte)24,(byte)32,(byte)112,(byte)-56,(byte)-48,(byte)-27,(byte)46,(byte)91,(byte)96,(byte)-65,(byte)-55,(byte)89,(byte)45,(byte)116})) && request.getMethod().equals(zqw.ptz(new byte[] {(byte)-74,(byte)108,(byte)60,(byte)105,(byte)-77,(byte)-50}))) {
                kxCrypto.doEncryption(request, response, deviceInstallV4Handler);
            }
            else if (uri.equals(zqw.ptp(new byte[] {(byte)27,(byte)65,(byte)110,(byte)66,(byte)125,(byte)-108,(byte)-52,(byte)-69,(byte)-44,(byte)-22,(byte)-11,(byte)70,(byte)39,(byte)13,(byte)14,(byte)109,(byte)-108,(byte)-81,(byte)-88,(byte)-54,(byte)-12,(byte)86,(byte)20,(byte)39,(byte)88,(byte)119,(byte)114,(byte)-99,(byte)-80,(byte)-43,(byte)-51,(byte)-89,(byte)21,(byte)54})) && request.getMethod().equals(zqw.pV(new byte[] {(byte)11,(byte)-8,(byte)-88,(byte)74,(byte)65,(byte)75}))) {
                kxCrypto.doEncryption(request, response, deviceUninstallV4Handler);
            }
            else if (uri.equals(zqw.puW(new byte[] {(byte)-74,(byte)37,(byte)10,(byte)72,(byte)77,(byte)114,(byte)48,(byte)105,(byte)124,(byte)100,(byte)97,(byte)60,(byte)103,(byte)59,(byte)34,(byte)125,(byte)104,(byte)107,(byte)108,(byte)103,(byte)96,(byte)-117,(byte)-104,(byte)-81,(byte)-117,(byte)-106,(byte)-106,(byte)-104,(byte)-70,(byte)-118,(byte)-108,(byte)-59,(byte)-115,(byte)-120})) && request.getMethod().equals(zqw.pQU(new byte[] {(byte)62,(byte)43,(byte)123,(byte)61,(byte)-22,(byte)84}))) {
                kxCrypto.doEncryption(request, response, deviceValidateV4Handler);
            }
        } catch (IOException e) {
            _logger.error(zqw.pRd(new byte[] {(byte)-33,(byte)69,(byte)0,(byte)-90,(byte)17,(byte)-99,(byte)-13,(byte)48,(byte)-17,(byte)92,(byte)-46,(byte)47,(byte)-66,(byte)25,(byte)-118,(byte)-31,(byte)121,(byte)-63,(byte)21,(byte)-74,(byte)54,(byte)-109,(byte)4,(byte)101,(byte)-4,(byte)106}), e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, zqw.pQm(new byte[] {(byte)-69,(byte)43,(byte)98,(byte)-43,(byte)76,(byte)0,(byte)-124,(byte)51,(byte)-75,(byte)64,(byte)-54,(byte)125,(byte)-17}));
        } catch (ServletException e) {
            _logger.error(zqw.ptO(new byte[] {(byte)-121,(byte)98,(byte)39,(byte)55,(byte)90,(byte)100,(byte)-100,(byte)-15,(byte)-60,(byte)-27,(byte)21,(byte)62,(byte)37,(byte)80,(byte)117,(byte)-128,(byte)-94,(byte)-56,(byte)-78,(byte)7,(byte)61,(byte)74,(byte)107,(byte)100,(byte)-105,(byte)-77}), e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, zqw.pRH(new byte[] {(byte)-89,(byte)-35,(byte)-114,(byte)30,(byte)107,(byte)-63,(byte)57,(byte)-106,(byte)-27,(byte)106,(byte)-75,(byte)8,(byte)108,(byte)-41,(byte)49,(byte)-118,(byte)-18,(byte)113}));
        }

    }

    private static void handleKnoxServerLookup(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.getContentType().equals(zqw.pA(new byte[] {(byte)-24,(byte)27,(byte)122,(byte)76,(byte)45,(byte)18,(byte)-10,(byte)-93,(byte)-128,(byte)118,(byte)74,(byte)43,(byte)11,(byte)-87,(byte)-51,(byte)-69,(byte)-122,(byte)100})) && request.getMethod().equals(zqw.pQG(new byte[] {(byte)64,(byte)-108,(byte)-60,(byte)-71,(byte)11,(byte)-18}))) {
            try (ServletInputStream inputStream = request.getInputStream()) {
                byte[] stringBytes = inputStream.readAllBytes(); // Read all bytes into a byte array
                String json = new String(stringBytes, StandardCharsets.UTF_8); // Decode bytes into a String

                response.setContentType(zqw.pM(new byte[] {(byte)-35,(byte)9,(byte)104,(byte)73,(byte)25,(byte)-11,(byte)-96,(byte)-102,(byte)72,(byte)45,(byte)-32,(byte)-42,(byte)-121,(byte)54,(byte)35,(byte)10,(byte)-58,(byte)-73}));
                response.setStatus(HttpServletResponse.SC_OK);
                // TODO: Sjekk om dette blir sendt på samme format som fra Samsung server
                response.setDateHeader(zqw.pte(new byte[] {(byte)50,(byte)35,(byte)103,(byte)-113,(byte)-51,(byte)-31}), new Date().getTime());

                try (ServletOutputStream outstream = response.getOutputStream()) {
                    String s = Configuration.getKnoxServerLookupResponse(request.getServerName(), request.getServerPort());
                    byte[] strData = s.getBytes(StandardCharsets.UTF_8);

                    response.setContentLength(strData.length);

                    outstream.write(strData);
                    outstream.flush();
                }
                return;
            }
        }
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, zqw.ptU(new byte[] {(byte)115,(byte)26,(byte)83,(byte)-71,(byte)-30,(byte)48,(byte)98,(byte)-94,(byte)-20,(byte)101,(byte)107,(byte)-47,(byte)12,(byte)76,(byte)-126}));
    }

    private static void handleKnoxPolicy(HttpServletResponse response) throws IOException {
        response.setContentType(zqw.p4(new byte[] {(byte)62,(byte)-93,(byte)-62,(byte)-62,(byte)-79,(byte)-68,(byte)-74,(byte)-115,(byte)-100,(byte)120,(byte)114,(byte)69,(byte)87,(byte)103,(byte)61,(byte)21,(byte)26,(byte)-22}));
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(zqw.pQV(new byte[] {(byte)-15,(byte)11,(byte)64,(byte)54,(byte)-2,(byte)-109,(byte)6,(byte)50,(byte)-41,(byte)106,(byte)61,(byte)-10}), zqw.pRu(new byte[] {(byte)-65,(byte)-55,(byte)-67,(byte)42,(byte)-48,(byte)82,(byte)-34,(byte)94,(byte)-47,(byte)34,(byte)-85,(byte)35}));
        // TODO: Sjekk om dette blir sendt på samme format som fra Samsung server
        response.setDateHeader(zqw.pJ(new byte[] {(byte)-66,(byte)19,(byte)87,(byte)33,(byte)25,(byte)-1}), new Date().getTime());

        try (ServletOutputStream outstream = response.getOutputStream()) {
            String s = Configuration.getKnoxPolicy();
            byte[] strData = s.getBytes(StandardCharsets.UTF_8);

            response.setContentLength(strData.length);

            outstream.write(strData);
            outstream.flush();
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Process POST request data
        serve(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Process GET request data
        serve(request, response);
    }

    private void sendMethodNotAllowed(HttpServletRequest req, HttpServletResponse resp, String msg) throws IOException {
        _logger.info(zqw.ptI(new byte[] {(byte)-15,(byte)-81,(byte)-30,(byte)-23,(byte)29,(byte)46,(byte)76,(byte)100,(byte)-3,(byte)-44,(byte)-8,(byte)0,(byte)113,(byte)79,(byte)103,(byte)-124,(byte)-86,(byte)-43,(byte)26,(byte)56,(byte)3,(byte)54,(byte)-120,(byte)-83,(byte)-115,(byte)-20,(byte)21,(byte)43,(byte)76,(byte)-34,(byte)-96,(byte)-59,(byte)-71,(byte)82,(byte)58,(byte)94,(byte)101,(byte)-36,(byte)-29,(byte)-37,(byte)0}), req.getMethod(), req.getRemoteAddr(), req.getRequestURL().toString());
        String protocol = req.getProtocol();
        // Note: Tomcat reports "" for HTTP/0.9 although some implementations
        // may report HTTP/0.9
        if (protocol.isEmpty() || protocol.endsWith(zqw.pRD(new byte[] {(byte)-15,(byte)34,(byte)18,(byte)-110,(byte)111})) || protocol.endsWith(zqw.ptr(new byte[] {(byte)11,(byte)78,(byte)127,(byte)22,(byte)18}))) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, msg);
        } else {
            resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, msg);
        }
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        sendMethodNotAllowed(request, response, zqw.pt7(new byte[] {(byte)117,(byte)67,(byte)11,(byte)73,(byte)-93,(byte)-127,(byte)-117,(byte)-24,(byte)58,(byte)77,(byte)123,(byte)-126,(byte)-93,(byte)-127,(byte)21,(byte)58,(byte)91,(byte)41,(byte)-112,(byte)-56,(byte)-25,(byte)1,(byte)36,(byte)87,(byte)-117,(byte)-68,(byte)-41}));
    }

    @Override
    protected void doHead(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Process HEAD request data
        sendMethodNotAllowed(request, response, zqw.pRA(new byte[] {(byte)-121,(byte)34,(byte)106,(byte)-19,(byte)4,(byte)-73,(byte)94,(byte)120,(byte)-55,(byte)55,(byte)-78,(byte)30,(byte)108,(byte)-65,(byte)88,(byte)-94,(byte)16,(byte)-37,(byte)-31,(byte)92,(byte)-80,(byte)39,(byte)-127,(byte)-9,(byte)104,(byte)-42,(byte)46}));
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Process OPTIONS request data
        response.setHeader(zqw.ptf(new byte[] {(byte)3,(byte)-13,(byte)-78,(byte)-45,(byte)-25,(byte)56,(byte)84}), zqw.ptZ(new byte[] {(byte)46,(byte)-80,(byte)-9,(byte)51,(byte)104,(byte)46,(byte)-24,(byte)-34,(byte)27,(byte)73,(byte)-76}));
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Process PUT request data
        sendMethodNotAllowed(request, response, zqw.pU(new byte[] {(byte)95,(byte)-104,(byte)-48,(byte)-16,(byte)-28,(byte)-20,(byte)-24,(byte)-71,(byte)-123,(byte)-104,(byte)-112,(byte)107,(byte)116,(byte)60,(byte)70,(byte)91,(byte)52,(byte)108,(byte)43,(byte)17,(byte)0,(byte)12,(byte)-25,(byte)-26,(byte)-44,(byte)-55,(byte)-36}));
    }

}
