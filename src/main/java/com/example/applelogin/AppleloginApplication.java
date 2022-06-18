package com.example.applelogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@EnableFeignClients
@SpringBootApplication
public class AppleloginApplication {

	public static void main(String[] args) {
		SpringApplication.run(AppleloginApplication.class, args);
	}

}
