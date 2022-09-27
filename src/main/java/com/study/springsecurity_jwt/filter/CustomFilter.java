package com.study.springsecurity_jwt.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomFilter implements Filter {

    private final Logger LOGGER = LoggerFactory.getLogger(CustomFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if(req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            LOGGER.info("CustomFilter.doFilter() : headerAuth = {}", headerAuth);

            if(headerAuth.equals("cos")) {
                chain.doFilter(req,res);
            } else {
                LOGGER.info("non auth");
            }
        }

        chain.doFilter(req, res); // 필수! 꼭 req, res 넘겨줘야함
    }
}
