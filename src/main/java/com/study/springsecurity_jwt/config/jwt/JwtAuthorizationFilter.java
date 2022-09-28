package com.study.springsecurity_jwt.config.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.study.springsecurity_jwt.config.auth.PrincipalDetails;
import com.study.springsecurity_jwt.model.User;
import com.study.springsecurity_jwt.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// security.BasicAuthenticationFilter
// : 권한이나 인증이 필요한 주소를 요청했을 때, 이 필터를 사용함
// 권한, 인증이 필요하지 않으면 이 필터를 타지 않음
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final Logger LOGGER = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        LOGGER.info("doFilterInternal() : 인증, 권한이 필요한 주소 요청");

        String jwtHeader = request.getHeader("Authorization");
        LOGGER.info("jwtHeader = {}", jwtHeader);

        // header 있는지 확인
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return; // 다음으로 진행 안됨
        }

        // JWT token 검증으로 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();

        // claim 정상상
       if(username != null) {
           User userEntity = userRepository.findByUsername(username);

           PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

           // jwt token 서명을 통해서 서명이 정상이면 Authentication 만들기
           Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

           // 강제로 security session에 접근해 authentication 저장
           SecurityContextHolder.getContext().setAuthentication(authentication);

           chain.doFilter(request, response);
       }
    }
}
