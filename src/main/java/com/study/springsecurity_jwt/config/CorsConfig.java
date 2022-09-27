package com.study.springsecurity_jwt.config;

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
        config.setAllowCredentials(true); // 내 서버가 응답할 때, json을 자바스크립트에서 처리할 수 있게 할지
        config.addAllowedOrigin("*"); // 모든 ip에 응답 혀용
        config.addAllowedMethod("*"); // 모든 header에 응답 허용
        source.registerCorsConfiguration("/api/**", config); // 모든 method에 응답 허용
        return new CorsFilter(source);
    }
}
