package com.cos.jwt.config.jwt;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// /login 요청해서 username, password 전송하면 포스트로
// UsernamePasswordAuthenticationFilter가 동작함.
// 폼로그인 사용안함 설정해놔서 작동을 안하는데 사용하게 컨피그에 다시 등록을 해준다

@RequiredArgsConstructor //생성자
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	
	private final AuthenticationManager authenticationManager;
	
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수임
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		//1. username, password 받아서
		
		//2. 정상인지 로그인 시도를 해봄
		//authenticationManager로 로그인 시도하면 -> PrincipalDetailsService가 호출 loadUserByUsername함수 실행
		
		//3. PrincipalDetails를 세션에 담고 - 권한관리 때문에 담아주어야함, 권한 안하면 안담아도 됨
		
		//4. JWT 토큰을 만들어서 응답을 해줌
		
		return super.attemptAuthentication(request, response);
	}
	
}
