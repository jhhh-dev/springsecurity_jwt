package com.cos.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

//@CrossOrigin //security 인증이 필요없는 요청에만 적용됨, 그래서 corsconfig만들어서 설정해야함
//@RequiredArgsConstructor //이걸로 생성자 만들든가 아니면 @Autowired로 주입하든가
@RestController
public class RestApiController {
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	@Autowired
	private UserRepository userRepository;
	
	@GetMapping("home")
	public String home() {
		return "home";
	}
	
	@PostMapping("token")
	public String token() {
		return "token";
	}
	
	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입완료OKOK";
	}
	
	//user manager admin 접근가능
	@GetMapping("/api/v1/user")
	public String user(Authentication authentication) {
		//세션에 넣은 authentication를 잘 들고 오나 확인해봄
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication : " + principalDetails.getUsername());
		return "user";
	}
	
	//manager admin 접근가능
	@GetMapping("/api/v1/manager")
	public String manager() {
		return "manager";
	}
	
	//admin 접근가능
	@GetMapping("/api/v1/admin")
	public String admin() {
		return "admin";
	}
}
