/*
 * hunter_hooks.js - Runtime security monitoring hooks for AndroidINONE Hunter module.
 * Monitors: Crypto operations, SQL queries, HTTP requests, SSL pinning, SharedPreferences access.
 * Usage: frida -U -f <package> -l hunter_hooks.js --no-pause
 */

Java.perform(function () {
    var findings = [];

    function log(tag, severity, msg) {
        var entry = "[" + tag + "] [" + severity + "] " + msg;
        console.log(entry);
        send({ type: "hunter_finding", tag: tag, severity: severity, message: msg });
    }

    // ── CRYPTO MONITOR ──
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function (input) {
            var mode = this.getOpMode ? "unknown" : "unknown";
            try { mode = this.opmode.value === 1 ? "ENCRYPT" : "DECRYPT"; } catch (e) {}
            var algo = this.getAlgorithm();
            log("CRYPTO", "INFO", mode + " " + algo + " input_len=" + (input ? input.length : 0));
            if (algo && algo.indexOf("ECB") !== -1) {
                log("CRYPTO", "HIGH", "Weak cipher mode ECB detected: " + algo);
            }
            if (algo && algo.indexOf("DES") !== -1) {
                log("CRYPTO", "HIGH", "Weak cipher DES detected: " + algo);
            }
            return this.doFinal(input);
        };
    } catch (e) {}

    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            log("CRYPTO", "MEDIUM", "SecretKeySpec created: algo=" + algo + " key_len=" + (key ? key.length : 0));
            if (key && key.length < 16) {
                log("CRYPTO", "HIGH", "Short encryption key (" + key.length + " bytes) for " + algo);
            }
            return this.$init(key, algo);
        };
    } catch (e) {}

    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function (algo) {
            if (algo === "MD5" || algo === "SHA1" || algo === "SHA-1") {
                log("CRYPTO", "MEDIUM", "Weak hash algorithm: " + algo);
            }
            return this.getInstance(algo);
        };
    } catch (e) {}

    // ── SQL MONITOR ──
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

        SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (sql, args) {
            log("SQL", "INFO", "rawQuery: " + sql);
            if (sql && (sql.indexOf("password") !== -1 || sql.indexOf("token") !== -1 || sql.indexOf("secret") !== -1)) {
                log("SQL", "HIGH", "Sensitive data in SQL query: " + sql.substring(0, 200));
            }
            return this.rawQuery(sql, args);
        };

        SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {
            log("SQL", "INFO", "execSQL: " + sql);
            return this.execSQL(sql);
        };
    } catch (e) {}

    // ── HTTP INTERCEPT ──
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var url = this.toString();
            log("HTTP", "INFO", "URL.openConnection: " + url);
            if (url.indexOf("http://") === 0) {
                log("HTTP", "HIGH", "Cleartext HTTP request: " + url);
            }
            return this.openConnection();
        };
    } catch (e) {}

    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Interceptor = Java.use("okhttp3.Interceptor");

        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
        if (RealCall) {
            RealCall.execute.implementation = function () {
                try {
                    var req = this.request();
                    var url = req.url().toString();
                    var method = req.method();
                    log("HTTP", "INFO", method + " " + url);
                    if (url.indexOf("http://") === 0) {
                        log("HTTP", "HIGH", "Cleartext OkHttp request: " + url);
                    }
                } catch (e) {}
                return this.execute();
            };
        }
    } catch (e) {}

    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.setRequestProperty.implementation = function (key, value) {
            if (key && (key.toLowerCase() === "authorization" || key.toLowerCase() === "cookie")) {
                log("HTTP", "MEDIUM", "Sensitive header: " + key + "=" + value.substring(0, 50));
            }
            return this.setRequestProperty(key, value);
        };
    } catch (e) {}

    // ── SHARED PREFERENCES MONITOR ──
    try {
        var SharedPreferencesEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        SharedPreferencesEditor.putString.implementation = function (key, value) {
            var sensitiveKeys = ["password", "token", "secret", "key", "session", "jwt", "auth", "cookie", "pin", "credential"];
            var keyLower = key ? key.toLowerCase() : "";
            for (var i = 0; i < sensitiveKeys.length; i++) {
                if (keyLower.indexOf(sensitiveKeys[i]) !== -1) {
                    log("STORAGE", "HIGH", "Sensitive SharedPref write: " + key + "=" + (value ? value.substring(0, 50) : "null"));
                    break;
                }
            }
            return this.putString(key, value);
        };
    } catch (e) {}

    // ── FILE I/O MONITOR ──
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function (path) {
            if (path && (path.indexOf("/sdcard") !== -1 || path.indexOf("external") !== -1)) {
                log("STORAGE", "MEDIUM", "Writing to external storage: " + path);
            }
            return this.$init(path);
        };
    } catch (e) {}

    // ── WEBVIEW MONITOR ──
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            log("WEBVIEW", "INFO", "WebView.loadUrl: " + url);
            if (url && url.indexOf("javascript:") === 0) {
                log("WEBVIEW", "HIGH", "JavaScript injection in WebView: " + url.substring(0, 100));
            }
            return this.loadUrl(url);
        };

        var WebSettings = Java.use("android.webkit.WebSettings");
        WebSettings.setJavaScriptEnabled.implementation = function (enabled) {
            if (enabled) {
                log("WEBVIEW", "MEDIUM", "JavaScript enabled in WebView");
            }
            return this.setJavaScriptEnabled(enabled);
        };
    } catch (e) {}

    console.log("[HUNTER] All hooks installed. Monitoring crypto, SQL, HTTP, storage, WebView...");
});
