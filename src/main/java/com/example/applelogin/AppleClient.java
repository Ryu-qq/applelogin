package com.example.applelogin;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Map;

@FeignClient(name = "appleClient", url = "https://appleid.apple.com/auth")
public interface AppleClient {

    @GetMapping(value = "/keys")
    ApplePublicKeyResponse getAppleAuthPublicKey();

    @PostMapping(value="/token")
    String getTokenResponse(@RequestBody Map<String, String> tokenRequest);


}
