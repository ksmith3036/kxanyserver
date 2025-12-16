package org.kx;

// Fixed

import org.json.JSONObject;

public class JsonHelper {
    static String getString(JSONObject json, String key, String defaultValue) {
        if (json.has(key)) {
            String str = json.optString(key, defaultValue);
            if (str != null)
                return str;
        }
        return defaultValue;
    }

    static int getInt(JSONObject json, String key, int defaultValue) {
        return json.optInt(key, defaultValue);
    }
}
