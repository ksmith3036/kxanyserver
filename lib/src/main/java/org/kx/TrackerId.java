package org.kx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

public class TrackerId {

    private static final Logger _logger = LoggerFactory.getLogger(TrackerId.class);
    private static final Logger _tracklog = LoggerFactory.getLogger("TrackerLog");
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
            String key = deviceId + "#" + licenseKeySubString;
            String trackerId = deviceTrackerIds.getOrDefault(key, null);
            if (trackerId != null) {
                return trackerId;
            }

            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            String newTrackerId = new KxEncryptionUtil().encryptMessage(
                    deviceId + licenseKeySubString + getCounter() + calendar.getTimeInMillis()
            );
            deviceTrackerIds.put(key, newTrackerId);
            _tracklog.info("TRACKER: {}, {}, {}", deviceId, licenseKey, newTrackerId);
            return newTrackerId;
        }
    }

    public static String findLicenseKeyFromTrackerId(String deviceId, String deviceTrackerId) throws KxDataEncryptException {
        synchronized (deviceTrackerIds) {
            String foundKey = lookupTrackerId(deviceTrackerId);
            if (foundKey != null) {
                String [] keyParts = foundKey.split("#");
                String foundDeviceId = keyParts[0];
                String licenseKey = keyParts.length > 1 ? keyParts[1] : "";
                if (deviceId == null || foundDeviceId.equals(deviceId)) {
                    _logger.info("TRACKER found: {}, {}, {}", foundDeviceId, licenseKey, deviceTrackerId);
                    return licenseKey;
                }
                _logger.info("TRACKER found, but wrong deviceId: {}, {}, {}, {}", foundDeviceId, licenseKey, deviceTrackerId, deviceId);
                return null;
            }
            _logger.info("TRACKER not found: {}, {}", deviceId, deviceTrackerId);
            return null;
        }
    }

    public static void removeTrackerId(String deviceId, String licenseKey) {
        String licenseKeySubString = licenseKey.substring(0, 35);
        String key = deviceId + "#" + licenseKeySubString;
        synchronized (deviceTrackerIds) {
            _tracklog.info("TRACKER removed: {}, {}", deviceId, licenseKey);
            deviceTrackerIds.remove(key);
        }
    }

    public static void removeTrackerId(String deviceTrackerId) {
        synchronized (deviceTrackerIds) {
            String foundKey = lookupTrackerId(deviceTrackerId);
            if (foundKey != null) {
                _tracklog.info("TRACKER removed: {}, {}", foundKey.replace('#', ' '), deviceTrackerId);
                deviceTrackerIds.remove(foundKey);
            }
        }
    }

    private static String lookupTrackerId(String deviceTrackerId) {
        if (deviceTrackerIds.containsValue(deviceTrackerId)) {
            for (Map.Entry<String, String> entry : deviceTrackerIds.entrySet()) {
                if (entry.getValue().equals(deviceTrackerId)) {
                    _logger.debug("TRACKER found: {}", deviceTrackerId);
                    return entry.getKey();
                }
            }
        }
        _logger.debug("TRACKER NOT found: {}", deviceTrackerId);
        return null;
    }

}
