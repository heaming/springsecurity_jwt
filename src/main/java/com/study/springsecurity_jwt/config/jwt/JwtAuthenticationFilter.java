package com.study.springsecurity_jwt.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.springsecurity_jwt.config.auth.PrincipalDetails;
import com.study.springsecurity_jwt.model.User;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// /login 요청 -> UsernamePasswordAuthenticationFilter 등장
// securityConfig formlogin.disabled -> filter X -> 다시 securityconfig에 filter 등록
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    private final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    // login 요청 시, 실행
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 1. username, password 받기
        // 2. attemptAuthentication() -> login 시도 -> PrincipalDetailsService.loadUserByUsername() 실행
        // 3. PrincipalDetails를 session 담음 (권한 관리를 위해서)
        // 4. JWT token 만들어서 응답
        LOGGER.info("AuthenticationManager: ON -> /login");

        try {
            // 1.
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 2,3 authentication ->  PrincipalDetails를 session에 담음
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            PrincipalDetails pd = (PrincipalDetails) authentication.getPrincipal(); // pd.getUser().getUsername()

            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


}
