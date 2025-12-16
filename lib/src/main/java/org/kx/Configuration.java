package org.kx;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;


public class Configuration {

    private static final Logger _logger = LoggerFactory.getLogger(Configuration.class);
    private static final Properties properties = init();
    private static final boolean isWindows = System.getProperty("os.name").toLowerCase().contains("windows");

    private static Properties init() {
        Properties defaultProps = new Properties();
        /*
        TODO Remove
        defaultProps.setProperty("key2", "57637f5b1b340bf8503b6694cf8c59c8");
        defaultProps.setProperty("key3", "cb6b18952bf388b5d1730a113e4dcccd");
        defaultProps.setProperty("key1", "992c39ff861f0c980b5f841c561e027b");
        defaultProps.setProperty("keyWindows", "8ff16785c687934083d3e45af192d04ee8f06245e7d7dcf2e870f5e03a43f8dedce97c157e4c359ca563c34dc4ab2ce06e1fc51eb853a99bdd49458e7a09707c");
        */

        defaultProps.setProperty("KlmKey", "oCOsq2djfaKzrCkirP0tiQ==");
        defaultProps.setProperty("KnoxPolicy", "{\"elm\":{\"validate\":\"off\",\"apilog\":\"off\",\"deniallog\":\"off\",\"amslog\":\"off\",\"timalog\":\"off\"},\"klm\":{\"validateTrackKey\":\"on\",\"enrollDevice\":\"on\",\"uninstallLicense\":\"on\", \"enrollContainer\":\"on\",\"uninstallContainer\":\"on\",\"notifyTrackKey\":\"on\"},\"spd\":\"off\",\"kad\":\"\"}");
        defaultProps.setProperty("KnoxServerLookupResponse", "{\"service\":\"klms\",\"endpoint\":[{\"protocol\":\"https\",\"url\":\"!SERVERNAME!\",\"port\":\"!PORTNUMBER!\"},{\"protocol\":\"https\",\"url\":\"!SERVERNAME!\",\"port\":\"!PORTNUMBER!\"}]}");

        Properties props = new Properties(defaultProps);
        try (InputStream is = Configuration.class.getResourceAsStream("/kx.properties")) {
            props.load(is);
            for (String propName : props.stringPropertyNames()) {
                _logger.debug("Property {} = {}", propName, props.getProperty(propName));
            }
        } catch (IOException | NullPointerException ex) {
            _logger.error("Error loading WEB-INF/classes/kx.properties", ex);
        }
        return props;
    }

    public static String getParameter(String parameterName) {
        return properties.getProperty(parameterName);
    }

    // TODO Remove
    public static String getKey1() {
        return properties.getProperty("key1");
    }

    // TODO Remove
    public static String getKey2() {
        return properties.getProperty("key2");
    }

    // TODO Remove
    public static String getKey3() {
        return properties.getProperty("key3");
    }

    // TODO Remove
    public static String getKeyWindows() {
        return properties.getProperty("keyWindows");
    }

    public static boolean isLinuxEnvironment() {
        return !isWindows;
    }

    public static boolean isWindowsEnvironment() {
        return isWindows;
    }

    // 1	F6EA2CEDFA8880383B4560265A6FEC55F512C248D1DEBBDB8950AA0E49608B54	N2bhzqaFIoQw9TFK4OLd21QzaJ6i+NJGMxpWvleN4t6Lp4bN/bX8M8Qp0G1QW4UuyAnRdeCRwnjUjaDu0dvbj90FHLG4PMRVKwRucCX4B1bUgDAs8+epEQYoWQ/ZIsPen4nI3dQUKag1WihwyYKzJ9ijud/iPEGtkt0ae2gXBADM3F56mJLlr6a6JKgy9xWg44WXfyenCalgld4G7cVhckPptlZSrq2MkhUTiF8TLYNJ6PY/FciRm6YqXwGlNl9PTFKScxW26EK4U8boysGXQH642yQTjnc7DdDjPoSItUQxLqsuLmtjnwZTTpEP3TF+MvF/yFL2SgzPxI/xquP6dpIa+kyTIH7Qoe65XvHkXLmKdvy0R/HVPu7IpbBa6dNBODEmO/CvC5wGJY6YwQr4LIpFpxHaiB5eOiEM2hCCAH0ei4ocqdu6KPT+Pi69Qg8AsCvXKFYbDYxCI8UobTWcyimLd0CwSPvFSfx82fJNwj6GkQg1q4ZJE4z1Gl2L/3+jcQ0qU1dpyZsKSNb+9fyXJjWTyatGTTIYozz9GF/cPIwy4pJLaPBhYrPZL7KZN1nNkik0fivmPbi9AuaxKhuBFT0zoeEJXQDeD/MQgGPGTdOR9ZWrI4oW3CWnq4ms0qqY9BHu1LS4zqijooZ92KJE32IbDO52WZ5yrFgVNWKbFCXQHTjdzT/zmGlVe8/K00q3wpcavWDtZRrG22eP1I+qJ0ySSlfETrC/pn55yj42SCewq14JmcmVwvJMbojznOxBCyv01cFSxcJVIvoWDu0EJHUcxUAMxLvQM2ZSFRFHXt9EipObXHFS9G7k8nmsEGXXuTTYfhDTyVZflz4V7a68/JvgYupliqMIAoEfqbq0ybxo52S8F1XGrAIBF2V6qsEyMDcy6U+Xf7+PELZ0ZHvMNrbKD1H4hnXKgtrF3F/pQEFnOP6DIyxWB5wZPasP06tQVJJ76mCF7TUyLb6N1WX0kKlEgyH8AvddH4CBnF/ruX02NNotlM3r7ZyjD4zk+dLPy1u475ZspTCkizkFs4mg7eBqRuyuoS0rEJRnM2WNrz4d9wZK/OtDLsHU4Rg3mQlu4+LdkQidnrO2l+p0804LnkCSlEiKr/19xkX1XbZVyw8CVUGRWCl022ef/LQVaFk5vzGqHYNPKxqBPFJVpNYH03W4Gg/Rq9PKWGoakHY0xv49ztKL9hznUuPpdFqZ5bruiDEbSrSYFLCI7AH7uK4+NOKqd8f8UVeXazmDf4InSVHWTYZ8fvXUQinM4UAZ4AB+vitxgcRqoMve1XUHyvAx3hziqrKlrRcZLW0q1DhhxgqfGsXmsz+gxoBkH1Q+HSe6XATgelV1LoTUhvWaO4R7WcxTgQF2+cHISQVBAmRLgWvq1VrEjEgKi9ij8QDuRRVyZeU0mCj+dz4L2Kq5OcjEv6jkakONKfRI/zdRrXu2EwGdbP6SkNYsoy9FlZ5Z+xEQ1C00oa/hgKiIWMPdbNDMbuO0O1jk/+JZOKyv/QkKmlE5DBbIjbHf4IcRlJCDuuXO34rhlTnz07OWGP+KtSF6aKR9luqiXn5gHr02UNWtgBw04VMu9sZ3pcZGoS+NmOsu	klm-onprem	2022-07-20 07:28:06.6700000
    public static Set<KxKeyStore> getKeyStore() {
        Set<KxKeyStore> keys = new HashSet<>();
        keys.add(new KxKeyStore("F6EA2CEDFA8880383B4560265A6FEC55F512C248D1DEBBDB8950AA0E49608B54", "N2bhzqaFIoQw9TFK4OLd21QzaJ6i+NJGMxpWvleN4t6Lp4bN/bX8M8Qp0G1QW4UuyAnRdeCRwnjUjaDu0dvbj90FHLG4PMRVKwRucCX4B1bUgDAs8+epEQYoWQ/ZIsPen4nI3dQUKag1WihwyYKzJ9ijud/iPEGtkt0ae2gXBADM3F56mJLlr6a6JKgy9xWg44WXfyenCalgld4G7cVhckPptlZSrq2MkhUTiF8TLYNJ6PY/FciRm6YqXwGlNl9PTFKScxW26EK4U8boysGXQH642yQTjnc7DdDjPoSItUQxLqsuLmtjnwZTTpEP3TF+MvF/yFL2SgzPxI/xquP6dpIa+kyTIH7Qoe65XvHkXLmKdvy0R/HVPu7IpbBa6dNBODEmO/CvC5wGJY6YwQr4LIpFpxHaiB5eOiEM2hCCAH0ei4ocqdu6KPT+Pi69Qg8AsCvXKFYbDYxCI8UobTWcyimLd0CwSPvFSfx82fJNwj6GkQg1q4ZJE4z1Gl2L/3+jcQ0qU1dpyZsKSNb+9fyXJjWTyatGTTIYozz9GF/cPIwy4pJLaPBhYrPZL7KZN1nNkik0fivmPbi9AuaxKhuBFT0zoeEJXQDeD/MQgGPGTdOR9ZWrI4oW3CWnq4ms0qqY9BHu1LS4zqijooZ92KJE32IbDO52WZ5yrFgVNWKbFCXQHTjdzT/zmGlVe8/K00q3wpcavWDtZRrG22eP1I+qJ0ySSlfETrC/pn55yj42SCewq14JmcmVwvJMbojznOxBCyv01cFSxcJVIvoWDu0EJHUcxUAMxLvQM2ZSFRFHXt9EipObXHFS9G7k8nmsEGXXuTTYfhDTyVZflz4V7a68/JvgYupliqMIAoEfqbq0ybxo52S8F1XGrAIBF2V6qsEyMDcy6U+Xf7+PELZ0ZHvMNrbKD1H4hnXKgtrF3F/pQEFnOP6DIyxWB5wZPasP06tQVJJ76mCF7TUyLb6N1WX0kKlEgyH8AvddH4CBnF/ruX02NNotlM3r7ZyjD4zk+dLPy1u475ZspTCkizkFs4mg7eBqRuyuoS0rEJRnM2WNrz4d9wZK/OtDLsHU4Rg3mQlu4+LdkQidnrO2l+p0804LnkCSlEiKr/19xkX1XbZVyw8CVUGRWCl022ef/LQVaFk5vzGqHYNPKxqBPFJVpNYH03W4Gg/Rq9PKWGoakHY0xv49ztKL9hznUuPpdFqZ5bruiDEbSrSYFLCI7AH7uK4+NOKqd8f8UVeXazmDf4InSVHWTYZ8fvXUQinM4UAZ4AB+vitxgcRqoMve1XUHyvAx3hziqrKlrRcZLW0q1DhhxgqfGsXmsz+gxoBkH1Q+HSe6XATgelV1LoTUhvWaO4R7WcxTgQF2+cHISQVBAmRLgWvq1VrEjEgKi9ij8QDuRRVyZeU0mCj+dz4L2Kq5OcjEv6jkakONKfRI/zdRrXu2EwGdbP6SkNYsoy9FlZ5Z+xEQ1C00oa/hgKiIWMPdbNDMbuO0O1jk/+JZOKyv/QkKmlE5DBbIjbHf4IcRlJCDuuXO34rhlTnz07OWGP+KtSF6aKR9luqiXn5gHr02UNWtgBw04VMu9sZ3pcZGoS+NmOsu", "klm-onprem"));
        return keys;
    }

    public static byte[] getKlmKey() {
        return Base64.decodeBase64(getParameter("KlmKey"));
    }

    public static String getKnoxPolicy() {
        return properties.getProperty("KnoxPolicy");
    }

    public static String getKnoxServerName() {
        return properties.getProperty("KnoxServer");
    }

    public static String getKnoxServerPort() {
        return properties.getProperty("KnoxServerPort");
    }

    public static String getKnoxServerLookupResponse(String serverName, int serverPortNum) {
        String template = properties.getProperty("KnoxServerLookupResponse");
        if (serverName == null) serverName = getKnoxServerName();
        String serverPort = Integer.toString(serverPortNum);
        if (serverPortNum == 80) serverPort = getKnoxServerPort();
        return template.replace("!SERVERNAME!", serverName).replace("!PORTNUMBER!", serverPort);
    }

    public static String[] getOnpremisePremiumCustomPermissions() {
        return new String[]{
                "com.samsung.android.knox.permission.KNOX_ADVANCED_APP_MGMT",
                "com.samsung.android.knox.permission.KNOX_ADVANCED_RESTRICTION",
                "com.samsung.android.knox.permission.KNOX_ADVANCED_SECURITY",
                "com.samsung.android.knox.permission.KNOX_AUDIT_LOG",
                "com.samsung.android.knox.permission.KNOX_CCM",
                "com.samsung.android.knox.permission.KNOX_CCM_KEYSTORE",
                "com.samsung.android.knox.permission.KNOX_CERTENROLL",
                "com.samsung.android.knox.permission.KNOX_CERTIFICATE",
                "com.samsung.android.knox.permission.KNOX_CERTIFICATE_ENROLLMENT",
                "com.samsung.android.knox.permission.KNOX_CONTAINER",
                "com.samsung.android.knox.permission.KNOX_CONTAINER_RCP",
                "com.samsung.android.knox.permission.KNOX_CONTAINER_VPN",
                "com.samsung.android.knox.permission.KNOX_DLP",
                "com.samsung.android.knox.permission.KNOX_DLP_MGMT",
                "com.samsung.android.knox.permission.KNOX_EBILLING",
                "com.samsung.android.knox.permission.KNOX_EBILLING_NOMDM",
                "com.samsung.android.knox.permission.KNOX_ENTERPRISE_BILLING",
                "com.samsung.android.knox.permission.KNOX_ENTERPRISE_BILLING_NOMDM",
                "com.samsung.android.knox.permission.KNOX_GENERIC_VPN",
                "com.samsung.android.knox.permission.KNOX_KEYSTORE",
                "com.samsung.android.knox.permission.KNOX_KEYSTORE_PER_APP",
                "com.samsung.android.knox.permission.KNOX_NPA",
                "com.samsung.android.knox.permission.KNOX_RESTRICTION",
                "com.samsung.android.knox.permission.KNOX_SEAMS",
                "com.samsung.android.knox.permission.KNOX_SEAMS_MGMT",
                "com.samsung.android.knox.permission.KNOX_TIMA_KEYSTORE",
                "com.samsung.android.knox.permission.KNOX_TIMA_KEYSTORE_PER_APP",
                "com.samsung.android.knox.permission.KNOX_VPN_CONTAINER",
                "com.samsung.android.knox.permission.KNOX_VPN_GENERIC",
                "android.permission.sec.MDM_AUDIT_LOG",
                "android.permission.sec.MDM_CERTIFICATE",
                "android.permission.sec.MDM_ENTERPRISE_CONTAINER",
                "android.permission.sec.MDM_SMARTCARD",
                "android.permission.sec.MDM_ENTERPRISE_SSO",
                "android.permission.sec.MDM_ENTERPRISE_ISL",
                "com.sec.enterprise.knox.KNOX_GENERIC_VPN",
                "com.sec.enterprise.knox.KNOX_CONTAINER_VPN",
                "com.sec.enterprise.knox.permission.KNOX_DEACTIVATE_LICENSE",
                "com.sec.enterprise.knox.permission.KNOX_RCP_SYNC_MGMT",
                "com.sec.enterprise.knox.permission.KNOX_SEAMS",
                "com.sec.enterprise.knox.permission.KNOX_KEYSTORE",
                "com.sec.enterprise.knox.permission.KNOX_CERTENROLL",
                "com.sec.enterprise.knox.permission.KNOX_CCM",
                "com.sec.enterprise.knox.permission.KNOX_RESTRICTION",
                "com.sec.enterprise.knox.permission.KNOX_ENTERPRISE_BILLING",
                "com.sec.enterprise.permission.KNOX_UCM_ESE",
                "com.sec.enterprise.permission.KNOX_UCM_OTHER",
                "com.sec.enterprise.permission.KNOX_DLP",
                "com.sec.enterprise.permission.KNOX_KEYSTORE_PER_APP",
                "com.sec.enterprise.knox.permission.KNOX_SEAMS_SEPOLICY",
                "com.sec.enterprise.knox.permission.KNOX_ENTERPRISE_BILLING_NOMDM",
                "com.sec.enterprise.permission.KNOX_UCM_PLUGIN",
                "com.sec.enterprise.permission.KNOX_UCM_PRIVILEGED",
                "com.samsung.android.knox.permission.KNOX_DEVICE_CONFIGURATION",
                "com.samsung.android.knox.permission.KNOX_ENHANCED_ATTESTATION",
                "com.samsung.android.knox.permission.KNOX_HDM",
                "com.samsung.android.knox.permission.KNOX_MOBILE_THREAT_DEFENSE",
                "com.samsung.android.knox.permission.KNOX_APP_SEPARATION",
                "com.samsung.android.knox.permission.KNOX_CUSTOM_DEX",
                "com.samsung.android.knox.permission.KNOX_CUSTOM_PROKIOSK",
                "com.samsung.android.knox.permission.KNOX_CUSTOM_SETTING",
                "com.samsung.android.knox.permission.KNOX_CUSTOM_SYSTEM",
                "com.sec.enterprise.knox.permission.CUSTOM_SETTING",
                "com.sec.enterprise.knox.permission.CUSTOM_SYSTEM",
                "com.sec.enterprise.knox.permission.CUSTOM_SEALEDMODE",
                "com.sec.enterprise.knox.permission.CUSTOM_PROKIOSK",
                "com.samsung.android.knox.permission.KNOX_APN",
                "com.samsung.android.knox.permission.KNOX_APP_MGMT",
                "com.samsung.android.knox.permission.KNOX_BLUETOOTH",
                "com.samsung.android.knox.permission.KNOX_BLUETOOTH_SECUREMODE",
                "com.samsung.android.knox.permission.KNOX_BROWSER_PROXY",
                "com.samsung.android.knox.permission.KNOX_BROWSER_SETTINGS",
                "com.samsung.android.knox.permission.KNOX_CERT_PROVISIONING",
                "com.samsung.android.knox.permission.KNOX_CLIPBOARD",
                "com.samsung.android.knox.permission.KNOX_DATE_TIME",
                "com.samsung.android.knox.permission.KNOX_DEX",
                "com.samsung.android.knox.permission.KNOX_DUAL_SIM",
                "com.samsung.android.knox.permission.KNOX_EMAIL",
                "com.samsung.android.knox.permission.KNOX_ENTERPRISE_DEVICE_ADMIN",
                "com.samsung.android.knox.permission.KNOX_EXCHANGE",
                "com.samsung.android.knox.permission.KNOX_FIREWALL",
                "com.samsung.android.knox.permission.KNOX_GEOFENCING",
                "com.samsung.android.knox.permission.KNOX_GLOBALPROXY",
                "com.samsung.android.knox.permission.KNOX_HW_CONTROL",
                "com.samsung.android.knox.permission.KNOX_INVENTORY",
                "com.samsung.android.knox.permission.KNOX_KIOSK_MODE",
                "com.samsung.android.knox.permission.KNOX_LDAP",
                "com.samsung.android.knox.permission.KNOX_LICENSE_LOG",
                "com.samsung.android.knox.permission.KNOX_LOCATION",
                "com.samsung.android.knox.permission.KNOX_LOCKSCREEN",
                "com.samsung.android.knox.permission.KNOX_MULTI_USER_MGMT",
                "com.samsung.android.knox.permission.KNOX_PHONE_RESTRICTION",
                "com.samsung.android.knox.permission.KNOX_REMOTE_CONTROL",
                "com.samsung.android.knox.permission.KNOX_RESTRICTION_MGMT",
                "com.samsung.android.knox.permission.KNOX_ROAMING",
                "com.samsung.android.knox.permission.KNOX_SECURITY",
                "com.samsung.android.knox.permission.KNOX_SPDCONTROL",
                "com.samsung.android.knox.permission.KNOX_VPN",
                "com.samsung.android.knox.permission.KNOX_WIFI",
                "android.permission.sec.ENTERPRISE_DEVICE_ADMIN",
                "android.permission.sec.MDM_APN",
                "android.permission.sec.MDM_APP_BACKUP",
                "android.permission.sec.MDM_APP_MGMT",
                "android.permission.sec.MDM_APP_PERMISSION_MGMT",
                "android.permission.sec.MDM_BLUETOOTH",
                "android.permission.sec.MDM_BROWSER_SETTINGS",
                "android.permission.sec.MDM_DATE_TIME",
                "android.permission.sec.MDM_EMAIL",
                "android.permission.sec.MDM_ENTERPRISE_VPN",
                "android.permission.sec.MDM_EXCHANGE",
                "android.permission.sec.MDM_FIREWALL",
                "android.permission.sec.MDM_HW_CONTROL",
                "android.permission.sec.MDM_INVENTORY",
                "android.permission.sec.MDM_KIOSK_MODE",
                "android.permission.sec.MDM_LDAP",
                "android.permission.sec.MDM_LICENSE_LOG",
                "android.permission.sec.MDM_LOCATION",
                "android.permission.sec.MDM_LOCKSCREEN",
                "android.permission.sec.MDM_PHONE_RESTRICTION",
                "android.permission.sec.MDM_RESTRICTION",
                "android.permission.sec.MDM_ROAMING",
                "android.permission.sec.MDM_SECURITY",
                "android.permission.sec.MDM_VPN",
                "android.permission.sec.MDM_WIFI",
                "android.permission.sec.MDM_GEOFENCING",
                "android.permission.sec.MDM_DUAL_SIM",
                "android.permission.sec.MDM_BLUETOOTH_SECUREMODE",
                "android.permission.sec.MDM_MULTI_USER_MGMT",
                "com.sec.enterprise.mdm.permission.BROWSER_PROXY",
                "android.permission.sec.MDM_REMOTE_CONTROL",
                "com.sec.enterprise.mdm.permission.MDM_SSO",
                "com.sec.enterprise.permission.MDM_SPDCONTROL",
                "com.sec.enterprise.knox.permission.KNOX_ATTESTATION",
                "com.samsung.android.knox.permission.KNOX_ATTESTATION",
                "com.samsung.android.knox.permission.KNOX_REMOTE_ATTESTATION",
                "com.sec.enterprise.permission.KNOX_SDP",
                "com.samsung.android.knox.permission.KNOX_SDP",
                "com.samsung.android.knox.permission.KNOX_SENSITIVE_DATA_PROTECTION",
                "com.samsung.android.knox.permission.KNOX_NDA_DEVICE_SETTINGS",
                "com.samsung.android.knox.permission.KNOX_NDA_PERIPHERAL",
                "com.samsung.android.knox.permission.KNOX_NDA_DATA_ANALYTICS",
                "com.samsung.android.knox.permission.KNOX_NDA_AI"
        };
    }

}
