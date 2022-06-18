package com.example.applelogin;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@Getter
class AppConfig {

    @Value("${Apple.key-path}")
    private String keyPath;

    @Value("${Apple.key-teamId}")
    private String keyTeamId;

    @Value("${Apple.aud}")
    private String aud;

    @Value("${Apple.iss}")
    private String iss;

    @Value("${Apple.websiteUrl}")
    private String websiteUrl;

    @Value("${Apple.publicKeyUrl}")
    private String publicKeyUrl;

    @Value("${Apple.authTokenUrl}")
    private String authTokenUrl;


}


