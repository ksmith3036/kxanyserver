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

                if (!request.getContentType().equals(zqw.pe(new byte[] {(byte)-100,(byte)46,(byte)79,(byte)56,(byte)18,(byte)16,(byte)-1,(byte)-45,(byte)-85,(byte)-112,(byte)-105,(byte)119,(byte)92,(byte)99,(byte)12,(byte)-13,(byte)-11,(byte)-38}))) {
                    throw new ServletException(zqw.pRj(new byte[] {(byte)26,(byte)-26,(byte)-81,(byte)21,(byte)102,(byte)-60,(byte)86,(byte)-90,(byte)0,(byte)-39,(byte)-19,(byte)76,(byte)-42,(byte)57,(byte)-121,(byte)25,(byte)120,(byte)-127,(byte)66,(byte)-78,(byte)16,(byte)-112,(byte)-80,(byte)63}) + request.getContentType());
                }

                String body = zqw.pi(new byte[] {(byte)98,(byte)-120,(byte)-18,(byte)-57,(byte)-83,(byte)-114,(byte)101,(byte)122});
                try {
                    body = request.getBody();
                    JSONObject jsonObject = new JSONObject(body);

                    JSONObject payLoad = jsonObject.getJSONObject(zqw.pRC(new byte[] {(byte)-81,(byte)124,(byte)12,(byte)116,(byte)-41,(byte)11,(byte)-113,(byte)24,(byte)118}));
                    String signature = JsonHelper.getString(jsonObject, zqw.pRD(new byte[] {(byte)-113,(byte)48,(byte)67,(byte)-93,(byte)3,(byte)-112,(byte)-7,(byte)70,(byte)-71,(byte)20,(byte)101}), zqw.pQg(new byte[] {(byte)109,(byte)-3}));
                    String carrierId = JsonHelper.getString(payLoad, zqw.ptp(new byte[] {(byte)-85,(byte)90,(byte)57,(byte)35,(byte)88,(byte)96,(byte)-109,(byte)-121,(byte)-72,(byte)-5,(byte)-2}), zqw.pRI(new byte[] {(byte)-6,(byte)-98}));
                    String licenseKey = JsonHelper.getString(payLoad, zqw.pti(new byte[] {(byte)-24,(byte)79,(byte)35,(byte)119,(byte)-114,(byte)-39,(byte)-27,(byte)41,(byte)76,(byte)-77,(byte)-94,(byte)-17}), zqw.ptS(new byte[] {(byte)94,(byte)-115}));
                    int installType = JsonHelper.getInt(payLoad, zqw.pQo(new byte[] {(byte)-41,(byte)91,(byte)50,(byte)-94,(byte)78,(byte)-38,(byte)126,(byte)-4,(byte)109,(byte)38,(byte)-102,(byte)36,(byte)-96}), 3);
                    String deviceEnrollTime = JsonHelper.getString(payLoad, zqw.pt(new byte[] {(byte)-123,(byte)59,(byte)95,(byte)91,(byte)55,(byte)45,(byte)36,(byte)47,(byte)8,(byte)62,(byte)33,(byte)57,(byte)53,(byte)48,(byte)11,(byte)11,(byte)8,(byte)13}), String.valueOf(new Date().getTime()));
                    JSONObject deviceInfo = payLoad.getJSONObject(zqw.p9(new byte[] {(byte)-100,(byte)87,(byte)51,(byte)-25,(byte)-37,(byte)-79,(byte)96,(byte)75,(byte)16,(byte)-22,(byte)-55,(byte)-75}));
                    String deviceId = JsonHelper.getString(deviceInfo, zqw.pRT(new byte[] {(byte)-57,(byte)115,(byte)23,(byte)-111,(byte)3,(byte)-97,(byte)20,(byte)-99,(byte)48,(byte)-98}), zqw.pt3(new byte[] {(byte)126,(byte)-43})).replace(zqw.ptA(new byte[] {(byte)45,(byte)-94,(byte)-2,(byte)91}), zqw.ptt(new byte[] {(byte)-21,(byte)17,(byte)62}));
                    String model = JsonHelper.getString(deviceInfo, zqw.pQN(new byte[] {(byte)122,(byte)-27,(byte)-120,(byte)62,(byte)-39,(byte)76,(byte)-7}), zqw.ptb(new byte[] {(byte)81,(byte)49}));
                    String platformVersion = JsonHelper.getString(deviceInfo, zqw.pt8(new byte[] {(byte)21,(byte)-79,(byte)-63,(byte)-32,(byte)6,(byte)54,(byte)123,(byte)-105,(byte)-95,(byte)-61,(byte)-33,(byte)1,(byte)77,(byte)105,(byte)-100,(byte)-65,(byte)-59}), zqw.ptE(new byte[] {(byte)82,(byte)-116}));
                    String platformType = JsonHelper.getString(deviceInfo, zqw.pU(new byte[] {(byte)109,(byte)49,(byte)65,(byte)81,(byte)40,(byte)33,(byte)7,(byte)2,(byte)11,(byte)-24,(byte)-59,(byte)-28,(byte)-39,(byte)-48}), zqw.pQo(new byte[] {(byte)59,(byte)-36,(byte)-67,(byte)35,(byte)-38,(byte)93,(byte)-49,(byte)120,(byte)-26}));
                    String buildNumber = JsonHelper.getString(deviceInfo, zqw.pt3(new byte[] {(byte)110,(byte)-79,(byte)-45,(byte)5,(byte)70,(byte)-126,(byte)-55,(byte)34,(byte)94,(byte)-121,(byte)-53,(byte)13,(byte)85}), zqw.pRx(new byte[] {(byte)-51,(byte)-83}));
                    String sdkVersion = JsonHelper.getString(deviceInfo, zqw.pQE(new byte[] {(byte)33,(byte)-77,(byte)-64,(byte)119,(byte)24,(byte)-123,(byte)86,(byte)-31,(byte)-128,(byte)58,(byte)-36,(byte)125}), zqw.ptF(new byte[] {(byte)-72,(byte)115,(byte)54,(byte)4,(byte)117,(byte)-67,(byte)-99,(byte)-10,(byte)47,(byte)29,(byte)120,(byte)71,(byte)-122,(byte)-29,(byte)-61,(byte)21,(byte)106,(byte)90,(byte)-90,(byte)-24,(byte)-62,(byte)33,(byte)112,(byte)88,(byte)-78,(byte)-14,(byte)-60,(byte)74}));
                    JSONObject packageInfo = payLoad.getJSONObject(zqw.pto(new byte[] {(byte)-121,(byte)116,(byte)4,(byte)58,(byte)33,(byte)66,(byte)113,(byte)-112,(byte)-69,(byte)-116,(byte)-62,(byte)-11,(byte)21}));
                    String packageName = JsonHelper.getString(packageInfo, zqw.pc(new byte[] {(byte)82,(byte)-6,(byte)-118,(byte)115,(byte)73,(byte)41,(byte)59,(byte)21,(byte)-17,(byte)-20,(byte)-37,(byte)-65,(byte)-113}), zqw.pRq(new byte[] {(byte)83,(byte)23}));
                    String packageVersionName = JsonHelper.getString(packageInfo, zqw.pRP(new byte[] {(byte)117,(byte)54,(byte)70,(byte)-51,(byte)65,(byte)-13,(byte)111,(byte)-29,(byte)-97,(byte)38,(byte)-125,(byte)46,(byte)-95,(byte)33,(byte)-47,(byte)90,(byte)-28,(byte)65,(byte)-5,(byte)105}), zqw.pt3(new byte[] {(byte)21,(byte)-82}));
                    String packageVersionCode = JsonHelper.getString(packageInfo, zqw.pQL(new byte[] {(byte)-117,(byte)-93,(byte)-45,(byte)108,(byte)20,(byte)-118,(byte)42,(byte)-46,(byte)122,(byte)-33,(byte)-106,(byte)47,(byte)-76,(byte)88,(byte)-12,(byte)107,(byte)44,(byte)-74,(byte)39,(byte)-56}), zqw.pRR(new byte[] {(byte)-25,(byte)-47}));
                    String publicKeyHash = JsonHelper.getString(packageInfo, zqw.pux(new byte[] {(byte)42,(byte)-84,(byte)-36,(byte)-22,(byte)-16,(byte)-23,(byte)17,(byte)8,(byte)21,(byte)52,(byte)61,(byte)127,(byte)75,(byte)110,(byte)120}), zqw.pRL(new byte[] {(byte)-60,(byte)-112}));
                    String apkHash = JsonHelper.getString(packageInfo, zqw.ptc(new byte[] {(byte)-45,(byte)-46,(byte)-77,(byte)-21,(byte)15,(byte)101,(byte)-105,(byte)-52,(byte)-32}), zqw.pg(new byte[] {(byte)17,(byte)-38})).replace(zqw.pRG(new byte[] {(byte)-76,(byte)-110,(byte)-50,(byte)0}), zqw.pQB(new byte[] {(byte)-2,(byte)-85,(byte)-124}));

                    if (!signature.isBlank() && !deviceId.isBlank() && !licenseKey.isBlank() && licenseKey.length() >= 35) {
                        String licenseHead = TrackerId.getLicensePart(licenseKey);
                        String deviceTrackerId = TrackerId.getTrackerId(deviceId, licenseHead);
                        _logger.info(zqw.pW(new byte[] {(byte)116,(byte)53,(byte)118,(byte)53,(byte)60,(byte)10,(byte)9,(byte)-26,(byte)-49,(byte)-44,(byte)-27,(byte)-69,(byte)-128,(byte)-104,(byte)104,(byte)113,(byte)66,(byte)38,(byte)117,(byte)1,(byte)22,(byte)-7,(byte)-89,(byte)-113,(byte)-70,(byte)-82,(byte)-55,(byte)-41,(byte)114,(byte)102,(byte)1,(byte)31,(byte)42,(byte)30,(byte)89,(byte)-89,(byte)-30,(byte)-42,(byte)-111,(byte)-17,(byte)-102,(byte)-114,(byte)41,(byte)55,(byte)82,(byte)70,(byte)97,(byte)127,(byte)10,(byte)-2,(byte)-71,(byte)-121,(byte)-62,(byte)-74,(byte)-15,(byte)-49,(byte)122,(byte)110,(byte)9,(byte)23,(byte)50,(byte)38,(byte)65,(byte)95,(byte)-22,(byte)-34}), deviceId, signature, model, carrierId, licenseHead, deviceTrackerId, platformVersion, buildNumber, packageName, packageVersionName, packageVersionCode);
                        // Går ut om 6 år
                        long expiry = new Date().getTime() + ((86400L * 365 * 6) * 1000);

//                        String maskedLicenseKey = licenseKey.substring(0, 35);
                        String maskedLicenseKey = licenseKey.substring(0, 6) + zqw.puz(new byte[] {(byte)-58,(byte)-84,(byte)-122,(byte)-117,(byte)-68,(byte)-95,(byte)-86,(byte)88,(byte)64,(byte)117,(byte)126,(byte)99,(byte)20,(byte)30,(byte)2,(byte)55,(byte)56,(byte)45,(byte)-42,(byte)-36,(byte)-52,(byte)-15,(byte)-6,(byte)-17,(byte)-112}) + licenseKey.substring(29, 35);

                        String[] permissions = Configuration.getOnpremisePremiumCustomPermissions();

                        JSONObject responseJson = new JSONObject().put(zqw.pt5(new byte[] {(byte)118,(byte)10,(byte)122,(byte)-86,(byte)-11,(byte)1,(byte)97,(byte)-82,(byte)-12}),
                                        new JSONObject().put(zqw.pQL(new byte[] {(byte)-5,(byte)4,(byte)96,(byte)11,(byte)-82,(byte)43,(byte)-49,(byte)115,(byte)-44,(byte)-104,(byte)53,(byte)-35,(byte)67,(byte)-9,(byte)-114,(byte)47,(byte)-76}), deviceTrackerId)
                                                .put(zqw.pQE(new byte[] {(byte)30,(byte)-55,(byte)-88,(byte)93,(byte)-3,(byte)-116,(byte)58,(byte)-35,(byte)104,(byte)29,(byte)-96,(byte)70,(byte)-25,(byte)-65,(byte)44,(byte)-37,(byte)109,(byte)0,(byte)-86,(byte)93}), 3)
                                                .put(zqw.pM(new byte[] {(byte)98,(byte)-127,(byte)-17,(byte)-44,(byte)-103,(byte)101,(byte)23,(byte)16,(byte)-51,(byte)-72,(byte)101,(byte)80,(byte)21,(byte)-8,(byte)-82,(byte)-97}), (86400 * 1000) + 5200)
                                                .put(zqw.pRo(new byte[] {(byte)-15,(byte)2,(byte)103,(byte)-42,(byte)42,(byte)111,(byte)-64,(byte)39}), expiry)
                                                .put(zqw.pQK(new byte[] {(byte)10,(byte)115,(byte)3,(byte)-71,(byte)55,(byte)-61,(byte)126,(byte)-13,(byte)-102,(byte)59,(byte)-44,(byte)74,(byte)-2}), permissions)
                                                .put(zqw.ptW(new byte[] {(byte)-85,(byte)-23,(byte)-103,(byte)-55,(byte)29,(byte)95,(byte)-100,(byte)-53,(byte)8,(byte)87,(byte)110,(byte)-86,(byte)-41,(byte)56,(byte)98,(byte)-77,(byte)-10,(byte)37,(byte)106,(byte)-120,(byte)-26,(byte)18,(byte)64}), 2)
                                                .put(zqw.pts(new byte[] {(byte)-101,(byte)-56,(byte)-92,(byte)-38,(byte)-3,(byte)-20,(byte)26,(byte)44,(byte)47,(byte)124,(byte)78,(byte)109,(byte)-103}), new JSONObject().put(zqw.pt7(new byte[] {(byte)-93,(byte)-30,(byte)-110,(byte)-50,(byte)-7,(byte)20,(byte)63,(byte)71,(byte)-118,(byte)-116,(byte)-53,(byte)-4,(byte)3}), zqw.ptE(new byte[] {(byte)30,(byte)65,(byte)14,(byte)121,(byte)-99,(byte)-79,(byte)-4,(byte)2,(byte)44,(byte)104,(byte)-108,(byte)-22,(byte)-51,(byte)1,(byte)44,(byte)114,(byte)-100,(byte)-66,(byte)-52,(byte)52,(byte)56,(byte)80,(byte)-115,(byte)-96,(byte)-56}))
                                                        .put(zqw.pR6(new byte[] {(byte)18,(byte)-106,(byte)-6,(byte)116,(byte)-57,(byte)78,(byte)-36,(byte)74,(byte)-91,(byte)12,(byte)-85,(byte)44}), maskedLicenseKey))
                                                .put(zqw.pQs(new byte[] {(byte)-90,(byte)-24,(byte)-102,(byte)56,(byte)-95,(byte)55,(byte)-45,(byte)95,(byte)-43,(byte)126,(byte)-35,(byte)96,(byte)9,(byte)-100,(byte)5,(byte)-66,(byte)43}), zqw.pQq(new byte[] {(byte)29,(byte)122,(byte)9,(byte)-104,(byte)3,(byte)-80,(byte)35,(byte)-54,(byte)95}))
                                                .put(zqw.pQW(new byte[] {(byte)-100,(byte)2,(byte)112,(byte)42,(byte)-17,(byte)-103,(byte)89,(byte)-19,(byte)-93,(byte)120,(byte)41,(byte)-40,(byte)96,(byte)52}), 1000))
                                .put(zqw.p9(new byte[] {(byte)-87,(byte)9,(byte)122,(byte)93,(byte)56,(byte)-28,(byte)-44,(byte)-108,(byte)126,(byte)68,(byte)4}), signature);

                        _logger.debug(zqw.pZ(new byte[] {(byte)-88,(byte)57,(byte)115,(byte)29,(byte)44,(byte)54,(byte)-83,(byte)-60,(byte)-40,(byte)-66,(byte)-63,(byte)-115,(byte)118,(byte)26,(byte)21,(byte)49,(byte)34}), deviceId, responseJson.toString());
                        response.getWriter().print(responseJson.toString());
                    }
                } catch (KxDataEncryptException e) {
                    _logger.error(zqw.ptP(new byte[] {(byte)104,(byte)42,(byte)107,(byte)-72,(byte)-8,(byte)84,(byte)-104,(byte)-2,(byte)36,(byte)104,(byte)-35,(byte)13,(byte)52,(byte)-93,(byte)23,(byte)78,(byte)-76,(byte)-20,(byte)94,(byte)-53,(byte)-6,(byte)34,(byte)-116,(byte)-113}) + body.substring(0, 1000), e);
                    throw new ServletException(zqw.pQc(new byte[] {(byte)100,(byte)-80,(byte)-15,(byte)96,(byte)34,(byte)-64,(byte)-118,(byte)46,(byte)-42,(byte)-100,(byte)39,(byte)-11,(byte)-50,(byte)49,(byte)-26,(byte)-120,(byte)89,(byte)-24,(byte)-109,(byte)64,(byte)-17,(byte)-73,(byte)75,(byte)95,(byte)-76,(byte)68,(byte)17,(byte)-89,(byte)123,(byte)21,(byte)-28,(byte)96,(byte)3,(byte)-55,(byte)120,(byte)67,(byte)-3,(byte)113,(byte)24,(byte)-50,(byte)118,(byte)52,(byte)-19,(byte)-107,(byte)45,(byte)-45,(byte)-115,(byte)55,(byte)-18,(byte)-88,(byte)56,(byte)-16,(byte)-125,(byte)73,(byte)-8,(byte)-74,(byte)93,(byte)-21}));
                }
            }
        };
    }
}
