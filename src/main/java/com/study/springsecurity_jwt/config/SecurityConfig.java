package com.study.springsecurity_jwt.config;

import com.study.springsecurity_jwt.config.jwt.JwtAuthenticationFilter;
import com.study.springsecurity_jwt.config.jwt.JwtAuthorizationFilter;
import com.study.springsecurity_jwt.filter.CustomFilter;
import com.study.springsecurity_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter CORS_CONFIG;
    private final UserRepository userRepository;

    protected void configure(HttpSecurity http) throws Exception {

        http.addFilterBefore(new CustomFilter(), BasicAuthenticationFilter.class); // securityconfig filter 최우선
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session 사용X
                .and()
                .addFilter(CORS_CONFIG) // @CrossOrigin(인증x) -> filter 인증
                .formLogin().disable()
                .httpBasic().disable() // httpBasic -> id,pw 이용 인증 // bearer -> (jwt) token(유효시간) 이용
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') || hasRole('ROLE_MANAGER') || hasAnyRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') || hasAnyRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }
}
