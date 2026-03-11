Java.perform(function() {
    console.log("[*] Hooking GetTopSpammersListRequestV2...");
    
    try {
        var RequestV2 = Java.use("com.truecaller.contactlists.api.topspammers.p1911v1.GetTopSpammersListRequestV2");
        var ResponseV2 = Java.use("com.truecaller.contactlists.api.topspammers.p1911v1.GetTopSpammersListResponseV2");
        
        // Hook newBuilder
        RequestV2.newBuilder.overload().implementation = function() {
            console.log("\n[*] GetTopSpammersListRequestV2.newBuilder() called");
            console.log("[*] Stack trace:");
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            
            return this.newBuilder();
        };
        
        // Hook parseFrom để bắt response
        ResponseV2.parseFrom.overload('[B').implementation = function(bytes) {
            console.log("\n[*] GetTopSpammersListResponseV2.parseFrom() called");
            var result = this.parseFrom(bytes);
            
            if (result.hasContactList()) {
                var contactList = result.getContactList();
                console.log("[+] Response received:");
                console.log("    URL: " + contactList.getUrl());
                console.log("    ETag: " + contactList.getEtag());
            }
            
            return result;
        };
        
        console.log("[+] Hooks installed successfully");
        
    } catch(e) {
        console.log("[-] Error: " + e);
    }
});