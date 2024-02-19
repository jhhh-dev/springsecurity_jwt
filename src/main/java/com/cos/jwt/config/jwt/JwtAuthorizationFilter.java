package com.cos.jwt.config.jwt;

import java.io.IOException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//시큐리티가 filter가지고 있는데 그 필터 중에 BasicAuthenticationFilter 라는 것이 있음
//권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음
//만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탄다
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
	
	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
	//인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 됨.
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//super.doFilterInternal(request, response, chain); doFilter는 하나만 적어야함 응답 2번하면 오류남
		//http://localhost:8080/api/v1/user/121 이렇게 요청하면 권한이 필요한 주소이기 때문에..
		System.out.println("인증이나 권한이 필요한 주소요청이 됨");
		
		//헤더에 Authorization를 넣어서 보내는데 출력해봄 - 우리는 헤더에 JWT 토큰을 넘겨봄
		String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
		System.out.println(jwtHeader);
		
		//header에서 받은 JWT토큰을 검증해서 정상적이 사용자인지 확인
		//1. header 가 있는지 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) { //헤더가 Bearer인지 확인
			chain.doFilter(request, response);
			return;
		}
		
		//2. JWT 토큰을 검증해서 정상적인 사용자인 확인
		//Authorization의 토큰 부분만 가져오기
//		String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
		String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
		//서명이 정상적인 확인해서 정상이면 username을 가져오기
		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();
		//서명이 제대로 됐으면
		if(username != null) {
			System.out.println("username 정상");
			
			//JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다
			User userEntity = userRepository.findByUsername(username);
			
			System.out.println("userEntity : " + userEntity.getUsername());
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			//Authentication 객체를 강제로 만들기
			Authentication authentication = 
					new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities()); //pw는 지금 우리가 로그인할게 아니라 가짜로 Authentication객제를 만들거니까 null로 둔다
			
			System.out.println(authentication+"ddd");
			
			//강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			//다 했으니 이제 체인을 탄다
			chain.doFilter(request, response);
		}
	}


}
