package com.example.infrastructure.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class ExampleController {

  @GetMapping("/")
  @ResponseBody
  public String index(){
    return "no authentication needed";
  }

  @GetMapping("/restricted")
  @ResponseBody
  public String restricted(){
    return "only logged in users can see this";
  }
}
