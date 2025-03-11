package tech.robd.toolbox.trivialauth.client.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login() {
        return "login"; // This resolves to src/main/resources/templates/login.html
    }
}
