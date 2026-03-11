Java.perform(function () {

    var WebView = Java.use("android.webkit.WebView");

    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {

        console.log("[WebView.loadUrl] " + url);

        return this.loadUrl(url);
    };

});
