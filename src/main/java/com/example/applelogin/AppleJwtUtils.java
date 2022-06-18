package com.example.applelogin;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.*;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Component;


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;


@Component
@RequiredArgsConstructor
public class AppleJwtUtils {

    private final AppleClient appleClient;
    private final AppConfig appConfig;

    public Claims getClaimsBy(String identityToken) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, JsonProcessingException, ParseException, JOSEException, InvalidKeyException {

        //애플에서 가져온 정보
        ApplePublicKeyResponse response = appleClient.getAppleAuthPublicKey();

        String headerOfIdentityToken = StringReplace(identityToken.substring(0, identityToken.indexOf("."))).trim();

        Map<String, String> header = new ObjectMapper().readValue(new String(Base64.getDecoder().decode(headerOfIdentityToken), "UTF-8"), Map.class);


        //public key 구성요소를 조회한 뒤 JWT의 서명을 검증한 후 Claim을 응답
        ApplePublicKeyResponse.Key key = response.getMatchedKeyBy(header.get("kid"), header.get("alg"))
                .orElseThrow(() -> new NullPointerException("Failed get public key from apple's id server."));


        byte[] nBytes = Base64.getUrlDecoder().decode(key.getN());
        byte[] eBytes = Base64.getUrlDecoder().decode(key.getE());

        BigInteger n = new BigInteger(1, nBytes);
        BigInteger e = new BigInteger(1, eBytes);



        // public Key 생성
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
        KeyFactory keyFactory = KeyFactory.getInstance(key.getKty());
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);



        return Jwts.parser().setSigningKey(publicKey.getEncoded()).parseClaimsJws(identityToken).getBody();

    }







    //특수문자 제거용
    public String StringReplace(String str){
        String match = "[^\uAC00-\uD7A30-9a-zA-Z]";
        str = str.replaceAll(match, " ");
        return str;
    }







}
