package com.study.springsecurity_jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.springsecurity_jwt.config.auth.PrincipalDetails;
import com.study.springsecurity_jwt.model.User;
import lombok.RequiredArgsConstructor;

import lombok.extern.java.Log;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// /login 요청 -> UsernamePasswordAuthenticationFilter 등장
// securityConfig formlogin.disabled -> filter X -> 다시 securityconfig에 filter 등록
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    // 1. username, password 받기
    // 2. attemptAuthentication() -> login 시도 -> PrincipalDetailsService.loadUserByUsername() 실행
    // 3. PrincipalDetails를 session 담음 (권한 관리를 위해서) = return authentication
    // 4. attemptAuthentication() 정상적 실행 -> super.successfulAuthentication() JWT token 만들어서 response

    // login 요청 시, 실행
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        LOGGER.info("AuthenticationManager: ON -> /login");

        try {
            // 1.
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 2. 로그인 진행
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); // pd.getUser().getUsername() -> login 됨

            return authentication; // authentication session에 저장 -> return을 하는 이유는 sercurity에게 권한 관리를 넘기기 위해

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername()+" Token")
                .withExpiresAt(new Date(System.currentTimeMillis()+60*1000*10))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        LOGGER.info("jwtToken 인증 완료 : {}",jwtToken);
        response.addHeader("Authorization", "Bearer "+jwtToken);
    }

}
