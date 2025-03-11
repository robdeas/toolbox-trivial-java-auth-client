package tech.robd.toolbox.trivialauth.client.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

   @GetMapping("/api/greeting")
   public String getGreeting() {
      return "Hello from our secured REST endpoint!";
   }
}
