package org.kx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

public class TrackerId {

    private static final Logger _logger = LoggerFactory.getLogger(TrackerId.class);
    private static final Logger _tracklog = LoggerFactory.getLogger(zqw.pQ8(new byte[] {(byte)79,(byte)-32,(byte)-76,(byte)55,(byte)-53,(byte)108,(byte)31,(byte)-68,(byte)76,(byte)-17,(byte)103,(byte)10}));
    private static int counter = 0;
    private static final Object lockObject = new Object();

    private static final HashMap<String, String> deviceTrackerIds = new HashMap<>();

    private static int getCounter() {
        synchronized (lockObject) {
            int number = counter++;
            if (counter > 5000) {
                counter = 0;
            }
            return number;
        }
    }

    public static String getLicensePart(String longLicenseKey) {
        return longLicenseKey.substring(0, 35);
    }

    public static String getTrackerId(String deviceId, String licenseKey) throws KxDataEncryptException {
        synchronized (deviceTrackerIds) {
            String licenseKeySubString = getLicensePart(licenseKey);
            String key = deviceId + zqw.pq(new byte[] {(byte)66,(byte)-19,(byte)-50}) + licenseKeySubString;
            String trackerId = deviceTrackerIds.getOrDefault(key, null);
            if (trackerId != null) {
                return trackerId;
            }

            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone(zqw.puy(new byte[] {(byte)-57,(byte)-78,(byte)-25,(byte)-14,(byte)-39})));
            String newTrackerId = new KxEncryptionUtil().encryptMessage(
                    deviceId + licenseKeySubString + getCounter() + calendar.getTimeInMillis()
            );
            deviceTrackerIds.put(key, newTrackerId);
            _tracklog.info(zqw.pQM(new byte[] {(byte)-117,(byte)-23,(byte)-67,(byte)6,(byte)-2,(byte)105,(byte)-34,(byte)69,(byte)57,(byte)-20,(byte)97,(byte)-41,(byte)106,(byte)-82,(byte)-51,(byte)35,(byte)-66,(byte)2,(byte)-71,(byte)127,(byte)18}), deviceId, licenseKey, newTrackerId);
            return newTrackerId;
        }
    }

    public static String findLicenseKeyFromTrackerId(String deviceId, String deviceTrackerId) throws KxDataEncryptException {
        synchronized (deviceTrackerIds) {
            String foundKey = lookupTrackerId(deviceTrackerId);
            if (foundKey != null) {
                String [] keyParts = foundKey.split(zqw.pQV(new byte[] {(byte)98,(byte)-101,(byte)-72}));
                String foundDeviceId = keyParts[0];
                String licenseKey = keyParts.length > 1 ? keyParts[1] : zqw.pH(new byte[] {(byte)-115,(byte)97});
                if (deviceId == null || foundDeviceId.equals(deviceId)) {
                    _logger.info(zqw.pQg(new byte[] {(byte)118,(byte)57,(byte)109,(byte)-62,(byte)-90,(byte)125,(byte)-34,(byte)-87,(byte)17,(byte)-70,(byte)-105,(byte)39,(byte)-22,(byte)-104,(byte)41,(byte)-98,(byte)-37,(byte)41,(byte)-44,(byte)44,(byte)119,(byte)-43,(byte)120,(byte)112,(byte)-109,(byte)113,(byte)28}), foundDeviceId, licenseKey, deviceTrackerId);
                    return licenseKey;
                }
                _logger.info(zqw.pQR(new byte[] {(byte)-46,(byte)11,(byte)95,(byte)26,(byte)-60,(byte)-127,(byte)-76,(byte)121,(byte)43,(byte)-106,(byte)-107,(byte)95,(byte)24,(byte)-60,(byte)-125,(byte)8,(byte)65,(byte)-4,(byte)-82,(byte)108,(byte)117,(byte)-27,(byte)-67,(byte)99,(byte)39,(byte)-31,(byte)-29,(byte)100,(byte)88,(byte)12,(byte)-34,(byte)-105,(byte)84,(byte)39,(byte)-49,(byte)-46,(byte)5,(byte)25,(byte)-30,(byte)-16,(byte)57,(byte)45,(byte)-18,(byte)-4,(byte)45,(byte)49,(byte)-6,(byte)-24,(byte)33,(byte)69,(byte)6}), foundDeviceId, licenseKey, deviceTrackerId, deviceId);
                return null;
            }
            _logger.info(zqw.pW(new byte[] {(byte)74,(byte)119,(byte)35,(byte)-37,(byte)-38,(byte)-18,(byte)-12,(byte)-108,(byte)-79,(byte)-43,(byte)105,(byte)118,(byte)95,(byte)29,(byte)41,(byte)14,(byte)6,(byte)-21,(byte)-13,(byte)-109,(byte)-101,(byte)-74,(byte)-94,(byte)-35,(byte)35,(byte)110,(byte)90}), deviceId, deviceTrackerId);
            return null;
        }
    }

    public static void removeTrackerId(String deviceId, String licenseKey) {
        String licenseKeySubString = licenseKey.substring(0, 35);
        String key = deviceId + zqw.pt7(new byte[] {(byte)45,(byte)81,(byte)114}) + licenseKeySubString;
        synchronized (deviceTrackerIds) {
            _tracklog.info(zqw.pRw(new byte[] {(byte)73,(byte)73,(byte)29,(byte)-105,(byte)0,(byte)-2,(byte)114,(byte)-16,(byte)99,(byte)-115,(byte)91,(byte)-64,(byte)76,(byte)-14,(byte)111,(byte)-16,(byte)117,(byte)-73,(byte)41,(byte)-2,(byte)124,(byte)81,(byte)-39,(byte)14,(byte)-116}), deviceId, licenseKey);
            deviceTrackerIds.remove(key);
        }
    }

    public static void removeTrackerId(String deviceTrackerId) {
        synchronized (deviceTrackerIds) {
            String foundKey = lookupTrackerId(deviceTrackerId);
            if (foundKey != null) {
                _tracklog.info(zqw.ptI(new byte[] {(byte)-112,(byte)100,(byte)48,(byte)19,(byte)95,(byte)-72,(byte)-109,(byte)-16,(byte)-64,(byte)79,(byte)62,(byte)76,(byte)107,(byte)-116,(byte)-74,(byte)-8,(byte)30,(byte)109,(byte)20,(byte)106,(byte)-109,(byte)-25,(byte)-120,(byte)-2,(byte)31}), foundKey.replace('#', ' '), deviceTrackerId);
                deviceTrackerIds.remove(foundKey);
            }
        }
    }

    private static String lookupTrackerId(String deviceTrackerId) {
        if (deviceTrackerIds.containsValue(deviceTrackerId)) {
            for (Map.Entry<String, String> entry : deviceTrackerIds.entrySet()) {
                if (entry.getValue().equals(deviceTrackerId)) {
                    _logger.debug(zqw.pQE(new byte[] {(byte)101,(byte)122,(byte)46,(byte)-120,(byte)123,(byte)-39,(byte)-79,(byte)31,(byte)-24,(byte)58,(byte)28,(byte)-75,(byte)79,(byte)-12,(byte)-98,(byte)96,(byte)-102,(byte)97,(byte)7}), deviceTrackerId);
                    return entry.getKey();
                }
            }
        }
        _logger.debug(zqw.pQf(new byte[] {(byte)56,(byte)-115,(byte)-39,(byte)-79,(byte)120,(byte)-52,(byte)-82,(byte)126,(byte)-61,(byte)-57,(byte)115,(byte)-36,(byte)-67,(byte)31,(byte)-13,(byte)-124,(byte)52,(byte)-7,(byte)-119,(byte)121,(byte)-71,(byte)-108,(byte)56}), deviceTrackerId);
        return null;
    }

}
