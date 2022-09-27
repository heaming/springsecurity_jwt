package com.study.springsecurity_jwt.controller;

import com.study.springsecurity_jwt.model.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestApiController {

    @GetMapping("home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryPassWordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userReposity.save(user);
        return "회원가입완료";
    }
}
