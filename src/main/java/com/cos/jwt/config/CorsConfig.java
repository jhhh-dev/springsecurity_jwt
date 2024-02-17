package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {
	
	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);// 내서버가 응답을 할 때 json을 자바스크립트에서 처리할 수 있게 할지를 설정하는 것 - false면 자스에서 처리 못함
		config.addAllowedOrigin("*");// 모든 ip에 응답을 허용하겠다
		config.addAllowedHeader("*");// 모든 header에 응답을 허용
		config.addAllowedMethod("*");// 모든 post, get, delete, put, patch요청을 허용
		
		source.registerCorsConfiguration("/api/**", config); // /api/** 요청이 오면 무조건 이 필터로 오게된다
		
		return new CorsFilter(source);
	}
	
}
