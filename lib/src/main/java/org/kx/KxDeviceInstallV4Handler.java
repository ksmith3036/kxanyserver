package org.kx;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Date;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletResponse;

public class KxDeviceInstallV4Handler {
    private static final Logger _logger = LoggerFactory.getLogger(KxServlet.class);
    static KxRequestRunner getDeviceInstallV4Handler() {
        return new KxRequestRunner() {
            @Override
            public void run(KxCryptoRequestWrapper request, ServletResponse response) throws IOException, ServletException {
                // Inndata er noe slikt:
                // TODO Remove
                // {
                //  "payLoad": {
                //    "carrierId": "NEE",
                //    "licenseKey": "KLM05-U9SBT-H1RXW-Q7MKL-FKZRZ-HOSOD-6JRNK-J7090-KBRPH-RV79E#kx.server.com",
                //    "installType": 3,
                //    "deviceEnrollTime": "1764544571140",
                //    "deviceInfo": {
                //      "deviceId": "tlb7Rw/4DW8dTs49gyvBsZDQGPSvsMAlqjKmfSAGrEM=",
                //      "model": "SM-G973F",
                //      "platformVersion": "12",
                //      "platformType": "android",
                //      "buildNumber": "SP1A.210812.016.G973FXXSGHWC1",
                //      "sdkVersion": "ENTERPRISE_SDK_VERSION_6_8"
                //    },
                //    "packageInfo": {
                //      "packageName": "edu.ucla.minormdm",
                //      "packageVersionName": "1.0.56",
                //      "packageVersionCode": 56,
                //      "publicKeyHash": "44:55:9F:E3:8D:E9:70:B5:EF:76:D9:F0:4F:FB:93:33:95:6D:0A:25:B7:04:36:7D:90:9D:D8:A5:3D:01:BA:D0",
                //      "apkHash": "pLYK4nHJLbMT9o19VjoaQ1urIo+\/SWsLjEsiiB7RAG8="
                //    }
                //  },
                //  "signature": "db47d402e78aaa92b8b6e9aa1acc2f26"
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
                    String licenseKey = JsonHelper.getString(payLoad, "licenseKey", "");
                    int installType = JsonHelper.getInt(payLoad, "installType", 3);
                    String deviceEnrollTime = JsonHelper.getString(payLoad, "deviceEnrollTime", String.valueOf(new Date().getTime()));
                    JSONObject deviceInfo = payLoad.getJSONObject("deviceInfo");
                    String deviceId = JsonHelper.getString(deviceInfo, "deviceId", "").replace("\\/", "/");
                    String model = JsonHelper.getString(deviceInfo, "model", "");
                    String platformVersion = JsonHelper.getString(deviceInfo, "platformVersion", "");
                    String platformType = JsonHelper.getString(deviceInfo, "platformType", "android");
                    String buildNumber = JsonHelper.getString(deviceInfo, "buildNumber", "");
                    String sdkVersion = JsonHelper.getString(deviceInfo, "sdkVersion", "ENTERPRISE_SDK_VERSION_6_8");
                    JSONObject packageInfo = payLoad.getJSONObject("packageInfo");
                    String packageName = JsonHelper.getString(packageInfo, "packageName", "");
                    String packageVersionName = JsonHelper.getString(packageInfo, "packageVersionName", "");
                    String packageVersionCode = JsonHelper.getString(packageInfo, "packageVersionCode", "");
                    String publicKeyHash = JsonHelper.getString(packageInfo, "publicKeyHash", "");
                    String apkHash = JsonHelper.getString(packageInfo, "apkHash", "").replace("\\/", "/");

                    if (!signature.isBlank() && !deviceId.isBlank() && !licenseKey.isBlank() && licenseKey.length() >= 35) {
                        String licenseHead = TrackerId.getLicensePart(licenseKey);
                        String deviceTrackerId = TrackerId.getTrackerId(deviceId, licenseHead);
                        _logger.info("Creating license for: {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}", deviceId, signature, model, carrierId, licenseHead, deviceTrackerId, platformVersion, buildNumber, packageName, packageVersionName, packageVersionCode);
                        // Går ut om 6 år
                        long expiry = new Date().getTime() + ((86400L * 365 * 6) * 1000);

//                        String maskedLicenseKey = licenseKey.substring(0, 35);
                        String maskedLicenseKey = licenseKey.substring(0, 6) + "*****-*****-*****-*****" + licenseKey.substring(29, 35);

                        String[] permissions = Configuration.getOnpremisePremiumCustomPermissions();

                        JSONObject responseJson = new JSONObject().put("payLoad",
                                        new JSONObject().put("deviceTrackerId", deviceTrackerId)
                                                .put("attestationVerdict", 3)
                                                .put("nextValidation", (86400 * 1000) + 5200)
                                                .put("expiry", expiry)
                                                .put("permissions", permissions)
                                                .put("permissionProcessType", 2)
                                                .put("licenseInfo", new JSONObject().put("productType", "Onpremise-PremiumCustom")
                                                        .put("licenseKey", maskedLicenseKey))
                                                .put("responseMessage", "success")
                                                .put("responseCode", 1000))
                                .put("signature", signature);

                        _logger.debug("JSON for {}: {}", deviceId, responseJson.toString());
                        response.getWriter().print(responseJson.toString());
                    }
                } catch (KxDataEncryptException e) {
                    _logger.error("Activation failed for " + body.substring(0, 1000), e);
                    throw new ServletException("Activation processing failed with KxDataEncryptException");
                }
            }
        };
    }
}
