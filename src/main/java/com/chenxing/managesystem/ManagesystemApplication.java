package com.chenxing.managesystem;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.feign.EnableFeignClients;

@EnableDiscoveryClient
@EnableFeignClients
@SpringBootApplication
public class ManagesystemApplication {

	public static void main(String[] args) {
		SpringApplication.run(ManagesystemApplication.class, args);
	}
}
