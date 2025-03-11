package tech.robd.toolbox.trivialauth.client.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

   @GetMapping("/dashboard")
   public String dashboard(Model model) {
      model.addAttribute("message", "Welcome to the dashboard!");
      return "dashboard"; // returns dashboard.html
   }
}
