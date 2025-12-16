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

                if (!request.getContentType().equals(zqw.ptB(new byte[] {(byte)-96,(byte)119,(byte)22,(byte)58,(byte)109,(byte)-100,(byte)-86,(byte)-11,(byte)8,(byte)72,(byte)102,(byte)-115,(byte)-37,(byte)-89,(byte)49,(byte)93,(byte)110,(byte)-70}))) {
                    throw new ServletException(zqw.pe(new byte[] {(byte)95,(byte)63,(byte)118,(byte)55,(byte)5,(byte)-20,(byte)-53,(byte)-88,(byte)-65,(byte)-43,(byte)108,(byte)70,(byte)45,(byte)41,(byte)18,(byte)-1,(byte)-33,(byte)-27,(byte)-85,(byte)-128,(byte)99,(byte)72,(byte)125,(byte)65}) + request.getContentType());
                }

                String body = zqw.pD(new byte[] {(byte)-103,(byte)84,(byte)50,(byte)25,(byte)-11,(byte)-84,(byte)-127,(byte)108});
                try {
                    body = request.getBody();
                    JSONObject jsonObject = new JSONObject(body);

                    JSONObject payLoad = jsonObject.getJSONObject(zqw.ptR(new byte[] {(byte)30,(byte)9,(byte)121,(byte)-35,(byte)22,(byte)110,(byte)-70,(byte)-23,(byte)95}));
                    String signature = JsonHelper.getString(jsonObject, zqw.put(new byte[] {(byte)-70,(byte)36,(byte)87,(byte)122,(byte)101,(byte)-97,(byte)-127,(byte)-69,(byte)-53,(byte)-33,(byte)-7}), zqw.pRG(new byte[] {(byte)18,(byte)41}));
                    String carrierId = JsonHelper.getString(payLoad, zqw.pRU(new byte[] {(byte)-77,(byte)-1,(byte)-100,(byte)-32,(byte)113,(byte)-9,(byte)110,(byte)-20,(byte)121,(byte)-60,(byte)107}), zqw.puW(new byte[] {(byte)-57,(byte)43}));
                    String deviceTrackerId = JsonHelper.getString(payLoad, zqw.pW(new byte[] {(byte)78,(byte)-85,(byte)-49,(byte)-40,(byte)-71,(byte)-120,(byte)-112,(byte)96,(byte)67,(byte)91,(byte)90,(byte)46,(byte)52,(byte)20,(byte)-15,(byte)-36,(byte)-61}), zqw.ptb(new byte[] {(byte)-74,(byte)-118,(byte)-21,(byte)60,(byte)126,(byte)-112,(byte)-59,(byte)27,(byte)94})).replace(zqw.pL(new byte[] {(byte)-67,(byte)-51,(byte)-111,(byte)-45}), zqw.pRu(new byte[] {(byte)123,(byte)110,(byte)65}));
                    String platformType = JsonHelper.getString(payLoad, zqw.puz(new byte[] {(byte)125,(byte)-116,(byte)-4,(byte)-19,(byte)23,(byte)31,(byte)6,(byte)58,(byte)56,(byte)82,(byte)96,(byte)80,(byte)110,(byte)118}), zqw.pr(new byte[] {(byte)98,(byte)86,(byte)55,(byte)-31,(byte)-84,(byte)115,(byte)85,(byte)26,(byte)-56}));
                    String deviceId = JsonHelper.getString(payLoad, zqw.pQr(new byte[] {(byte)36,(byte)31,(byte)123,(byte)-10,(byte)113,(byte)18,(byte)-116,(byte)6,(byte)-98,(byte)47}), zqw.pRx(new byte[] {(byte)-123,(byte)-127})).replace(zqw.ptG(new byte[] {(byte)-75,(byte)-9,(byte)-85,(byte)-32}), zqw.pQP(new byte[] {(byte)-11,(byte)32,(byte)15}));
                    JSONObject packageInfo = payLoad.getJSONObject(zqw.pQo(new byte[] {(byte)84,(byte)-122,(byte)-10,(byte)-106,(byte)11,(byte)-78,(byte)43,(byte)-36,(byte)73,(byte)-44,(byte)96,(byte)25,(byte)-97}));
                    String packageName = JsonHelper.getString(packageInfo, zqw.ptg(new byte[] {(byte)-91,(byte)-56,(byte)-72,(byte)-12,(byte)1,(byte)68,(byte)-99,(byte)-82,(byte)-13,(byte)45,(byte)81,(byte)-112,(byte)-81}), zqw.pQ4(new byte[] {(byte)103,(byte)-40}));
                    String packageVersionName = JsonHelper.getString(packageInfo, zqw.pQ3(new byte[] {(byte)6,(byte)-109,(byte)-29,(byte)-67,(byte)70,(byte)5,(byte)-42,(byte)103,(byte)44,(byte)-60,(byte)-66,(byte)86,(byte)30,(byte)-33,(byte)-112,(byte)38,(byte)-33,(byte)-69,(byte)78,(byte)9}), zqw.pQZ(new byte[] {(byte)-111,(byte)110}));
                    String packageVersionCode = JsonHelper.getString(packageInfo, zqw.pQz(new byte[] {(byte)-95,(byte)-12,(byte)-124,(byte)89,(byte)31,(byte)-85,(byte)101,(byte)47,(byte)-23,(byte)-122,(byte)113,(byte)42,(byte)-17,(byte)-119,(byte)75,(byte)6,(byte)-17,(byte)-97,(byte)80,(byte)29}), zqw.ptj(new byte[] {(byte)5,(byte)35}));

                    if (!signature.isBlank() && !deviceId.isBlank() && !deviceTrackerId.isBlank()) {
                        String licenseKey = TrackerId.findLicenseKeyFromTrackerId(deviceId, deviceTrackerId);
                        if (licenseKey == null) licenseKey = zqw.puw(new byte[] {(byte)12,(byte)47,(byte)122,(byte)79,(byte)120,(byte)107,(byte)-104,(byte)-98,(byte)-75});
                        _logger.info(zqw.pRf(new byte[] {(byte)27,(byte)6,(byte)84,(byte)-14,(byte)69,(byte)-42,(byte)60,(byte)-78,(byte)2,(byte)-102,(byte)-82,(byte)115,(byte)-39,(byte)34,(byte)-73,(byte)13,(byte)-121,(byte)-32,(byte)54,(byte)-63,(byte)87,(byte)-69,(byte)96,(byte)-53,(byte)7,(byte)112,(byte)-78,(byte)15,(byte)-69,(byte)44,(byte)-50,(byte)83,(byte)127,(byte)-24,(byte)10,(byte)-105,(byte)51,(byte)-92,(byte)70,(byte)-37,(byte)-9,(byte)96,(byte)-126,(byte)31,(byte)-85,(byte)28}), deviceId, signature, carrierId, licenseKey, deviceTrackerId, packageName);

                        JSONObject responseJson = new JSONObject().put(zqw.pQD(new byte[] {(byte)14,(byte)-28,(byte)-108,(byte)34,(byte)-37,(byte)77,(byte)15,(byte)-34,(byte)122}),
                                        new JSONObject().put(zqw.pRM(new byte[] {(byte)63,(byte)98,(byte)6,(byte)109,(byte)-40,(byte)61,(byte)-103,(byte)-59,(byte)18,(byte)-98,(byte)-13,(byte)91,(byte)-75,(byte)-31,(byte)88,(byte)-103,(byte)18}), deviceTrackerId)
                                                .put(zqw.pQF(new byte[] {(byte)-49,(byte)69,(byte)33,(byte)-61,(byte)113,(byte)1,(byte)-86,(byte)79,(byte)-62,(byte)-120}), deviceId)
                                                .put(zqw.ps(new byte[] {(byte)-125,(byte)115,(byte)3,(byte)-56,(byte)-107,(byte)76,(byte)50,(byte)-26,(byte)-68,(byte)96,(byte)44,(byte)19,(byte)-25,(byte)-125,(byte)68,(byte)6,(byte)-6,(byte)-86,(byte)96,(byte)25,(byte)-2,(byte)-79,(byte)-98}), 2)
                                                .put(zqw.pQM(new byte[] {(byte)96,(byte)-68,(byte)-50,(byte)66,(byte)-31,(byte)-115,(byte)7,(byte)-67,(byte)77,(byte)-52,(byte)87,(byte)16,(byte)-114,(byte)48}), 1000))
                                .put(zqw.ptu(new byte[] {(byte)126,(byte)124,(byte)15,(byte)88,(byte)-127,(byte)-11,(byte)49,(byte)113,(byte)-49,(byte)29,(byte)65}), signature);

                        _logger.debug(zqw.pRL(new byte[] {(byte)15,(byte)53,(byte)127,(byte)-119,(byte)48,(byte)106,(byte)-23,(byte)8,(byte)124,(byte)-54,(byte)125,(byte)121,(byte)-38,(byte)118,(byte)-47,(byte)-19,(byte)70}), deviceId, responseJson.toString());
                        response.getWriter().print(responseJson.toString());
                    }
                } catch (KxDataEncryptException e) {
                    _logger.error(zqw.pt4(new byte[] {(byte)72,(byte)53,(byte)113,(byte)-112,(byte)-44,(byte)22,(byte)65,(byte)-100,(byte)-61,(byte)20,(byte)65,(byte)-100,(byte)-38,(byte)27,(byte)21,(byte)-109,(byte)-44,(byte)28,(byte)89,(byte)-112,(byte)-47,(byte)85,(byte)83,(byte)-102,(byte)-57,(byte)85}) + body.substring(0, 1000), e);
                    throw new ServletException(zqw.pQ6(new byte[] {(byte)49,(byte)69,(byte)1,(byte)-12,(byte)-68,(byte)74,(byte)1,(byte)-88,(byte)123,(byte)56,(byte)-47,(byte)-104,(byte)82,(byte)-25,(byte)-11,(byte)81,(byte)31,(byte)-42,(byte)102,(byte)52,(byte)-18,(byte)-102,(byte)92,(byte)-17,(byte)-86,(byte)57,(byte)3,(byte)-48,(byte)-108,(byte)37,(byte)-16,(byte)-123,(byte)13,(byte)14,(byte)-84,(byte)101,(byte)53,(byte)-119,(byte)-66,(byte)57,(byte)-55,(byte)-72,(byte)81,(byte)16,(byte)-8,(byte)103,(byte)54,(byte)-45,(byte)-108,(byte)73,(byte)-15,(byte)-108,(byte)101,(byte)10,(byte)-48,(byte)113,(byte)57,(byte)-16,(byte)-118,(byte)95}));
                }
            }
        };
    }
}
