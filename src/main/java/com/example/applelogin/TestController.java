package com.example.applelogin;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

@Controller
@RequiredArgsConstructor
@RequestMapping("api/v1/apple")
public class TestController {

    private final AppleJwtUtils appleJwtUtils;
    private final AppleService appleService;


    @PostMapping(value = "/appleLoginCallBack")
    public String snsApplelogin(@RequestBody MultiValueMap<String, Object> data) throws ParseException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, JsonProcessingException, JOSEException {
        //전달 받은 data에서 token 값 저장
        String id_token = data.get("id_token").toString();
        String code = data.get("code").toString();
        String client_secret =appleService.getAppleClientSecret(id_token);

        appleService.requestCodeValidations(client_secret, code, null);

        return "hello";

    }
}
