package org.kx;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletResponse;

public class KxDeviceValidateV4Handler {

    private static final Logger _logger = LoggerFactory.getLogger(KxServlet.class);

    static KxRequestRunner getDeviceValidateV4Handler() {
        return new KxRequestRunner() {
            @Override
            public void run(KxCryptoRequestWrapper request, ServletResponse response) throws IOException, ServletException {
                // Inndata er noe slikt:
                // TODO Remove
                // {
                //  "payLoad": {
                //    "carrierId": "NEE",
                //    "deviceTrackerId": "99jBmMPMx9t/L3lG7CgZibHP5pVt1k\/VSyz42XIxWDAe43rN6Y6CBUFzD\/6Ka2v4C\/IPuKObAB7dxn92hYHriWREC2pUxiJPLdS5TgBFWOjCzikQnRw\/elsiaqsY",
                //    "platformType": "android",
                //    "packageInfo": {
                //      "packageName": "s2.mdm.mdmagent",
                //      "packageVersionName": "1.0.56",
                //      "packageVersionCode": 56,
                //      "publicKeyHash": "BE:42:9F:E3:8D:E9:70:B5:EF:76:D9:F0:4F:FB:93:33:95:6D:0A:25:B7:04:36:7D:90:9D:D8:A5:3D:01:BA:D0",
                //      "apkHash": "pLYK4nHJLbMT9o19VjoaQ1urIo+\/SWsLjEsiiB7RAG8="
                //    }
                //  },
                //  "signature": "95f6ec79edab50ef1b500751212ed4ff"
                //}

                if (!request.getContentType().equals("application/json")) {
                    throw new ServletException("Invalid content type: " + request.getContentType());
                }

                String body = "failed";
                try {
                    body = request.getBody();
                    JSONObject jsonObject = new JSONObject(body);

                    JSONObject payLoad = jsonObject.getJSONObject("payLoad");
                    String signature = JsonHelper.getString(jsonObject, "signature", "");
                    String carrierId = JsonHelper.getString(payLoad, "carrierId", "");
                    String deviceTrackerId = JsonHelper.getString(payLoad, "deviceTrackerId", "android").replace("\\/", "/");
                    String platformType = JsonHelper.getString(payLoad, "platformType", "android");
                    JSONObject packageInfo = payLoad.getJSONObject("packageInfo");
                    String packageName = JsonHelper.getString(packageInfo, "packageName", "");
                    String packageVersionName = JsonHelper.getString(packageInfo, "packageVersionName", "");
                    String packageVersionCode = JsonHelper.getString(packageInfo, "packageVersionCode", "");
                    String publicKeyHash = JsonHelper.getString(packageInfo, "publicKeyHash", "");
                    String apkHash = JsonHelper.getString(packageInfo, "apkHash", "").replace("\\/", "/");

                    if (!signature.isBlank() && !deviceTrackerId.isBlank()) {
                        String licenseKey = TrackerId.findLicenseKeyFromTrackerId(null, deviceTrackerId);
                        if (licenseKey == null) licenseKey = "Unknown";
                        _logger.info("Validating license for: {}, {}, {}, {}, {}, {}, {}", signature, carrierId, licenseKey, deviceTrackerId, packageName, packageVersionName, packageVersionCode);

                        // Går ut om 6 år
                        long expiry = new Date().getTime() + ((86400L * 365 * 6) * 1000);

                        String[] permissions = Configuration.getOnpremisePremiumCustomPermissions();

                        JSONObject responseJson = new JSONObject().put("payLoad",
                                        new JSONObject().put("deviceTrackerId", deviceTrackerId)
                                                .put("licenseStatus", 1)
                                                .put("enrollStatus", 1)
                                                .put("permissions", permissions)
                                                .put("expiry", expiry)
                                                .put("nextValidation", (86400 * 1000) + 5200)
                                                .put("permissionProcessType", 2)
                                                .put("responseMessage", "success")
                                                .put("responseCode", 1000))
                                .put("signature", signature);

                        _logger.debug("JSON for {}: {}", deviceTrackerId, responseJson.toString());
                        response.getWriter().print(responseJson.toString());
                    }
                } catch (KxDataEncryptException e) {
                    _logger.error("Validation failed for " + body.substring(0, 1000), e);
                    throw new ServletException("Validation processing failed with KxDataEncryptException");
                }
            }
        };
    }
}
