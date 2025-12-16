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

                if (!request.getContentType().equals(zqw.pQQ(new byte[] {(byte)-95,(byte)-56,(byte)-87,(byte)116,(byte)48,(byte)16,(byte)-47,(byte)-105,(byte)81,(byte)24,(byte)-63,(byte)-117,(byte)78,(byte)115,(byte)-14,(byte)-89,(byte)127,(byte)34}))) {
                    throw new ServletException(zqw.puu(new byte[] {(byte)115,(byte)-26,(byte)-81,(byte)-72,(byte)-80,(byte)-41,(byte)-54,(byte)-1,(byte)-30,(byte)86,(byte)5,(byte)57,(byte)40,(byte)66,(byte)67,(byte)120,(byte)114,(byte)-42,(byte)-110,(byte)-81,(byte)-74,(byte)-45,(byte)-100,(byte)-74}) + request.getContentType());
                }

                String body = zqw.pRp(new byte[] {(byte)-75,(byte)-39,(byte)-65,(byte)-25,(byte)90,(byte)-116,(byte)-24,(byte)94});
                try {
                    body = request.getBody();
                    JSONObject jsonObject = new JSONObject(body);

                    JSONObject payLoad = jsonObject.getJSONObject(zqw.pRk(new byte[] {(byte)-49,(byte)-124,(byte)-12,(byte)123,(byte)-55,(byte)10,(byte)-77,(byte)19,(byte)108}));
                    String signature = JsonHelper.getString(jsonObject, zqw.pt9(new byte[] {(byte)-9,(byte)82,(byte)33,(byte)71,(byte)109,(byte)-120,(byte)-93,(byte)-22,(byte)15,(byte)36,(byte)87}), zqw.pRS(new byte[] {(byte)-76,(byte)-122}));
                    String carrierId = JsonHelper.getString(payLoad, zqw.ptz(new byte[] {(byte)-1,(byte)-31,(byte)-126,(byte)-6,(byte)39,(byte)125,(byte)-96,(byte)-26,(byte)79,(byte)-66,(byte)-43}), zqw.pRi(new byte[] {(byte)9,(byte)-99}));
                    String deviceTrackerId = JsonHelper.getString(payLoad, zqw.pQs(new byte[] {(byte)125,(byte)109,(byte)9,(byte)-121,(byte)33,(byte)-91,(byte)34,(byte)-45,(byte)127,(byte)-46,(byte)116,(byte)-23,(byte)-108,(byte)17,(byte)-101,(byte)23,(byte)-73}), zqw.pQB(new byte[] {(byte)10,(byte)-125,(byte)-30,(byte)-114,(byte)89,(byte)-24,(byte)-104,(byte)61,(byte)-43})).replace(zqw.ptB(new byte[] {(byte)-102,(byte)-15,(byte)-83,(byte)-21}), zqw.pRC(new byte[] {(byte)58,(byte)-22,(byte)-59}));
                    String platformType = JsonHelper.getString(payLoad, zqw.ptO(new byte[] {(byte)89,(byte)122,(byte)10,(byte)49,(byte)33,(byte)87,(byte)96,(byte)-122,(byte)-66,(byte)-62,(byte)-58,(byte)12,(byte)40,(byte)94}), zqw.pRT(new byte[] {(byte)-41,(byte)-54,(byte)-85,(byte)37,(byte)-88,(byte)63,(byte)-95,(byte)38,(byte)-76}));
                    JSONObject packageInfo = payLoad.getJSONObject(zqw.puw(new byte[] {(byte)-36,(byte)59,(byte)75,(byte)76,(byte)124,(byte)122,(byte)98,(byte)-110,(byte)-126,(byte)-112,(byte)-91,(byte)-37,(byte)-64}));
                    String packageName = JsonHelper.getString(packageInfo, zqw.pF(new byte[] {(byte)-106,(byte)87,(byte)39,(byte)28,(byte)-64,(byte)-94,(byte)-114,(byte)114,(byte)94,(byte)47,(byte)-26,(byte)-64,(byte)-74}), zqw.pQ5(new byte[] {(byte)-105,(byte)-9}));
                    String packageVersionName = JsonHelper.getString(packageInfo, zqw.pG(new byte[] {(byte)-109,(byte)63,(byte)79,(byte)7,(byte)-18,(byte)-33,(byte)-70,(byte)101,(byte)76,(byte)6,(byte)18,(byte)-20,(byte)-74,(byte)-123,(byte)124,(byte)84,(byte)47,(byte)-23,(byte)-62,(byte)-77}), zqw.ptA(new byte[] {(byte)-42,(byte)45}));
                    String packageVersionCode = JsonHelper.getString(packageInfo, zqw.pQu(new byte[] {(byte)-76,(byte)1,(byte)113,(byte)33,(byte)28,(byte)-43,(byte)-100,(byte)91,(byte)30,(byte)-20,(byte)-100,(byte)74,(byte)4,(byte)-33,(byte)-102,(byte)90,(byte)48,(byte)-35,(byte)-107,(byte)85}), zqw.pk(new byte[] {(byte)35,(byte)-53}));
                    String publicKeyHash = JsonHelper.getString(packageInfo, zqw.pR6(new byte[] {(byte)-8,(byte)126,(byte)14,(byte)112,(byte)-18,(byte)127,(byte)-13,(byte)66,(byte)-29,(byte)74,(byte)-49,(byte)117,(byte)-91,(byte)56,(byte)-70}), zqw.pp(new byte[] {(byte)110,(byte)88}));
                    String apkHash = JsonHelper.getString(packageInfo, zqw.pQj(new byte[] {(byte)93,(byte)16,(byte)113,(byte)26,(byte)-81,(byte)86,(byte)25,(byte)-95,(byte)68}), zqw.p4(new byte[] {(byte)7,(byte)-48})).replace(zqw.pL(new byte[] {(byte)110,(byte)-48,(byte)-116,(byte)-48}), zqw.pc(new byte[] {(byte)-63,(byte)-92,(byte)-117}));

                    if (!signature.isBlank() && !deviceTrackerId.isBlank()) {
                        String licenseKey = TrackerId.findLicenseKeyFromTrackerId(null, deviceTrackerId);
                        if (licenseKey == null) licenseKey = zqw.pO(new byte[] {(byte)-107,(byte)-47,(byte)-124,(byte)109,(byte)94,(byte)9,(byte)-10,(byte)-68,(byte)-109});
                        _logger.info(zqw.pRt(new byte[] {(byte)-27,(byte)-94,(byte)-12,(byte)122,(byte)-8,(byte)100,(byte)-30,(byte)-98,(byte)12,(byte)-104,(byte)4,(byte)-124,(byte)124,(byte)-71,(byte)39,(byte)-92,(byte)37,(byte)-41,(byte)65,(byte)-50,(byte)4,(byte)-5,(byte)121,(byte)-3,(byte)50,(byte)-95,(byte)-127,(byte)14,(byte)-64,(byte)69,(byte)-91,(byte)42,(byte)-4,(byte)105,(byte)-71,(byte)70,(byte)-104,(byte)13,(byte)-35,(byte)98,(byte)-76,(byte)49,(byte)-15,(byte)126,(byte)80,(byte)-43,(byte)21,(byte)-102,(byte)76,(byte)-7,(byte)41,(byte)-74}), signature, carrierId, licenseKey, deviceTrackerId, packageName, packageVersionName, packageVersionCode);

                        // Går ut om 6 år
                        long expiry = new Date().getTime() + ((86400L * 365 * 6) * 1000);

                        String[] permissions = Configuration.getOnpremisePremiumCustomPermissions();

                        JSONObject responseJson = new JSONObject().put(zqw.puW(new byte[] {(byte)-71,(byte)112,(byte)0,(byte)15,(byte)21,(byte)38,(byte)7,(byte)7,(byte)0}),
                                        new JSONObject().put(zqw.ptf(new byte[] {(byte)-72,(byte)-77,(byte)-41,(byte)26,(byte)61,(byte)126,(byte)-128,(byte)-54,(byte)47,(byte)53,(byte)114,(byte)-68,(byte)-64,(byte)18,(byte)49,(byte)70,(byte)-65}), deviceTrackerId)
                                                .put(zqw.pd(new byte[] {(byte)-25,(byte)23,(byte)123,(byte)89,(byte)42,(byte)7,(byte)21,(byte)-25,(byte)-56,(byte)-107,(byte)-85,(byte)-103,(byte)101,(byte)95,(byte)48}), 1)
                                                .put(zqw.pR3(new byte[] {(byte)-72,(byte)-88,(byte)-51,(byte)66,(byte)-62,(byte)91,(byte)-44,(byte)80,(byte)-109,(byte)48,(byte)-87,(byte)56,(byte)-91,(byte)39}), 1)
                                                .put(zqw.pRu(new byte[] {(byte)-30,(byte)-1,(byte)-113,(byte)28,(byte)-127,(byte)0,(byte)-114,(byte)18,(byte)-88,(byte)60,(byte)-96,(byte)39,(byte)-80}), permissions)
                                                .put(zqw.puz(new byte[] {(byte)-23,(byte)-109,(byte)-10,(byte)-16,(byte)13,(byte)27,(byte)21,(byte)37}), expiry)
                                                .put(zqw.pQx(new byte[] {(byte)-11,(byte)-45,(byte)-67,(byte)112,(byte)47,(byte)-19,(byte)-115,(byte)124,(byte)51,(byte)-56,(byte)-121,(byte)68,(byte)19,(byte)-64,(byte)-124,(byte)67}), (86400 * 1000) + 5200)
                                                .put(zqw.pQE(new byte[] {(byte)-57,(byte)96,(byte)16,(byte)-91,(byte)82,(byte)-19,(byte)-119,(byte)51,(byte)-45,(byte)105,(byte)15,(byte)-82,(byte)112,(byte)-14,(byte)-113,(byte)35,(byte)-59,(byte)115,(byte)19,(byte)-108,(byte)89,(byte)-16,(byte)-123}), 2)
                                                .put(zqw.pI(new byte[] {(byte)99,(byte)69,(byte)55,(byte)20,(byte)-18,(byte)-71,(byte)-102,(byte)79,(byte)62,(byte)28,(byte)-24,(byte)-76,(byte)-114,(byte)90,(byte)52,(byte)-26,(byte)-56}), zqw.pV(new byte[] {(byte)-79,(byte)-89,(byte)-44,(byte)-63,(byte)-94,(byte)-83,(byte)-66,(byte)-101,(byte)-122}))
                                                .put(zqw.pQg(new byte[] {(byte)63,(byte)-14,(byte)-128,(byte)44,(byte)-45,(byte)-121,(byte)33,(byte)-53,(byte)-113,(byte)54,(byte)-23,(byte)110,(byte)60,(byte)-54}), 1000))
                                .put(zqw.pta(new byte[] {(byte)-21,(byte)-17,(byte)-100,(byte)-33,(byte)26,(byte)42,(byte)106,(byte)-90,(byte)-20,(byte)18,(byte)66}), signature);

                        _logger.debug(zqw.pQt(new byte[] {(byte)-106,(byte)43,(byte)97,(byte)58,(byte)-24,(byte)-85,(byte)3,(byte)7,(byte)-16,(byte)-81,(byte)59,(byte)34,(byte)-22,(byte)-17,(byte)51,(byte)42,(byte)-14}), deviceTrackerId, responseJson.toString());
                        response.getWriter().print(responseJson.toString());
                    }
                } catch (KxDataEncryptException e) {
                    _logger.error(zqw.puT(new byte[] {(byte)-113,(byte)-40,(byte)-114,(byte)-82,(byte)-86,(byte)-44,(byte)-48,(byte)-54,(byte)-42,(byte)-16,(byte)-1,(byte)-23,(byte)94,(byte)19,(byte)13,(byte)10,(byte)54,(byte)52,(byte)44,(byte)31,(byte)80,(byte)66,(byte)86,(byte)59}) + body.substring(0, 1000), e);
                    throw new ServletException(zqw.pp(new byte[] {(byte)51,(byte)120,(byte)46,(byte)-50,(byte)-118,(byte)116,(byte)48,(byte)-22,(byte)-74,(byte)-112,(byte)95,(byte)9,(byte)-66,(byte)-91,(byte)126,(byte)44,(byte)25,(byte)-44,(byte)-101,(byte)108,(byte)63,(byte)-29,(byte)-93,(byte)-37,(byte)84,(byte)8,(byte)-55,(byte)-69,(byte)107,(byte)33,(byte)92,(byte)-60,(byte)-125,(byte)85,(byte)48,(byte)-81,(byte)-115,(byte)-123,(byte)112,(byte)10,(byte)-42,(byte)-72,(byte)85,(byte)41,(byte)29,(byte)-57,(byte)-107,(byte)83,(byte)46,(byte)-44,(byte)-80,(byte)-100,(byte)83,(byte)29,(byte)-48,(byte)-78,(byte)125,(byte)39}));
                }
            }
        };
    }
}
