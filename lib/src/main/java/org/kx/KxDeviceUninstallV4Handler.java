package org.kx;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletResponse;

public class KxDeviceUninstallV4Handler {
    private static final Logger _logger = LoggerFactory.getLogger(KxServlet.class);

    static KxRequestRunner getDeviceUninstallV4Handler() {
        return new KxRequestRunner() {
            @Override
            public void run(KxCryptoRequestWrapper request, ServletResponse response) throws IOException, ServletException {
                // Inndata er noe slikt:
                // TODO Remove
                // {
                //  "payLoad": {
                //    "carrierId": "NEE",
                //    "packageInfo": {
                //      "packageName": "s2.mdm.mdmagent",
                //      "packageVersionName": "0.0",
                //      "packageVersionCode": 0
                //    },
                //    "deviceTrackerId": "99jBmMPMx9t\/L3lG7CgZibHP5pVt1k\/VSyz42XIxWDAe43rN6Y6CBUFzD\/6Ka2v4C\/IPuKObAB7dxn92hYHriWREC2pUxiJPLdS5TgBFWOjCzikQnRmFMFFMiIXn",
                //    "platformType": "android",
                //    "deviceId": "tlb7Rw\/4DW8dTs49gyvBsZDQGPSvsMAlqjKmfSAGrEM="
                //  },
                //  "signature": "28d1e6c3f0109df60ade9718b2998c5e"
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
                    String deviceId = JsonHelper.getString(payLoad, "deviceId", "").replace("\\/", "/");
                    JSONObject packageInfo = payLoad.getJSONObject("packageInfo");
                    String packageName = JsonHelper.getString(packageInfo, "packageName", "");
                    String packageVersionName = JsonHelper.getString(packageInfo, "packageVersionName", "");
                    String packageVersionCode = JsonHelper.getString(packageInfo, "packageVersionCode", "");

                    if (!signature.isBlank() && !deviceId.isBlank() && !deviceTrackerId.isBlank()) {
                        String licenseKey = TrackerId.findLicenseKeyFromTrackerId(deviceId, deviceTrackerId);
                        if (licenseKey == null) licenseKey = "Unknown";
                        _logger.info("Removing license for: {}, {}, {}, {}, {}, {}", deviceId, signature, carrierId, licenseKey, deviceTrackerId, packageName);

                        JSONObject responseJson = new JSONObject().put("payLoad",
                                        new JSONObject().put("deviceTrackerId", deviceTrackerId)
                                                .put("deviceId", deviceId)
                                                .put("permissionProcessType", 2)
                                                .put("responseCode", 1000))
                                .put("signature", signature);

                        _logger.debug("JSON for {}: {}", deviceId, responseJson.toString());
                        response.getWriter().print(responseJson.toString());
                    }
                } catch (KxDataEncryptException e) {
                    _logger.error("Deactivation failed for " + body.substring(0, 1000), e);
                    throw new ServletException("Deactivation processing failed with KxDataEncryptException");
                }
            }
        };
    }
}
