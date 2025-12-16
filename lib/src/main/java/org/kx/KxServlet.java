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
            _logger.info("Method call: {} from {}, url: {}", request.getMethod(), request.getRemoteAddr(), request.getRequestURL().toString());
            String uri = request.getRequestURI();
            if (uri.equals("/KnoxGSLB/policy") && request.getMethod().equals("GET")) {
                handleKnoxPolicy(response);
            }
            else if (uri.equals("/KnoxGSLB/lookup/klms") && request.getMethod().equals("POST")) {
                handleKnoxServerLookup(request, response);
            }
            else if (uri.equals("/klm-rest/v4/device/install.do") && request.getMethod().equals("POST")) {
                kxCrypto.doEncryption(request, response, deviceInstallV4Handler);
            }
            else if (uri.equals("/klm-rest/v4/device/uninstall.do") && request.getMethod().equals("POST")) {
                kxCrypto.doEncryption(request, response, deviceUninstallV4Handler);
            }
            else if (uri.equals("/klm-rest/v4/validateTrackKey.do") && request.getMethod().equals("POST")) {
                kxCrypto.doEncryption(request, response, deviceValidateV4Handler);
            }
        } catch (IOException e) {
            _logger.error("Error processing request", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "IOException");
        } catch (ServletException e) {
            _logger.error("Error processing request", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "ServletException");
        }

    }

    private static void handleKnoxServerLookup(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.getContentType().equals("application/json") && request.getMethod().equals("POST")) {
            try (ServletInputStream inputStream = request.getInputStream()) {
                byte[] stringBytes = inputStream.readAllBytes(); // Read all bytes into a byte array
                String json = new String(stringBytes, StandardCharsets.UTF_8); // Decode bytes into a String

                response.setContentType("application/json");
                response.setStatus(HttpServletResponse.SC_OK);
                // TODO: Sjekk om dette blir sendt på samme format som fra Samsung server
                response.setDateHeader("Date", new Date().getTime());

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
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid input");
    }

    private static void handleKnoxPolicy(HttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader("Keep-Alive", "timeout=20");
        // TODO: Sjekk om dette blir sendt på samme format som fra Samsung server
        response.setDateHeader("Date", new Date().getTime());

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
        _logger.info("Method not allowed: {} from {}, url: {}", req.getMethod(), req.getRemoteAddr(), req.getRequestURL().toString());
        String protocol = req.getProtocol();
        // Note: Tomcat reports "" for HTTP/0.9 although some implementations
        // may report HTTP/0.9
        if (protocol.isEmpty() || protocol.endsWith("0.9") || protocol.endsWith("1.0")) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, msg);
        } else {
            resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, msg);
        }
    }

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        sendMethodNotAllowed(request, response, "HTTP method not supported");
    }

    @Override
    protected void doHead(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Process HEAD request data
        sendMethodNotAllowed(request, response, "HTTP method not supported");
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Process OPTIONS request data
        response.setHeader("Allow", "GET, POST");
    }

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Process PUT request data
        sendMethodNotAllowed(request, response, "HTTP method not supported");
    }

}
