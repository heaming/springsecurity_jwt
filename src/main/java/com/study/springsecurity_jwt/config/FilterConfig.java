package com.study.springsecurity_jwt.config;


import com.study.springsecurity_jwt.filter.CustomFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<CustomFilter> filter() {
        FilterRegistrationBean<CustomFilter> bean = new FilterRegistrationBean<>(new CustomFilter());
        bean.addUrlPatterns("/*");
        bean.setOrder(0); // 낮은 번호가 우선순위
        return bean;
    }
}
