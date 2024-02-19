package com.cos.jwt.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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
		try {
//			System.out.println(request.getInputStream().toString()); //여기에 id와 pw가 담겨있다
			
//			BufferedReader br = request.getReader(); //읽어서
//			String input = null;
//			while ((input = br.readLine()) != null) {
//				System.out.println(input); //출력해보기 -> form방식 username=user&password=1234 
//			}
			
			//json방식으로 받아서 파싱해보자
			ObjectMapper om = new ObjectMapper(); //json 파싱가능함
			User user = om.readValue(request.getInputStream(), User.class); //User에 담기
			System.out.println(user); //User(id=0, username=user, password=1234, roles=null)
			
			//토큰 만들기 - 이 토큰으로 로그인 시도 해보기
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			//PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
			//loadUserByUsername는 유저네임만 받아서 실행함 - pw는 내부에서 알아서 처리해줌
			//즉, ===> authenticationToken 토큰을 authenticationManager에 던지면 인증을 해줌 -> 인증이 되면 authentication을 받음
			//authentication여기에 로그인한 정보가 담겨있음
			// => 이거는 디비에 있는 username과 pw가 일치한다는 뜻
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			
			// authentication.getPrincipal이 출력이 되면 로그인이 되었다는 뜻
			//정보 꺼내보기
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println(principalDetails.getUser().getUsername());
			System.out.println("OKOKOKOK=======================================================");
			
			//그러면 authentication를 리턴 
			//리턴하면 authentication 객체가 session영역에 저장됨
			//리턴의 이유는 권한 관리를 security가 대신 해주기 때문데 편하려고 하는 것
			//굳이 JWT토큰을 사용하면서 셔센을 만들 이유가 없음. 근데 단지 권한 처리때문에 session에 넣어줌
			return authentication;
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		//토큰 로그인 순서=============
		//1. username, password 받아서
		//2. 정상인지 로그인 시도를 해봄
		//authenticationManager로 로그인 시도하면 -> PrincipalDetailsService가 호출 loadUserByUsername함수 실행
		//3. PrincipalDetails를 세션에 담고 - 권한관리 때문에 담아주어야함, 권한 안하면 안담아도 됨
		//4. JWT 토큰을 만들어서 응답을 해줌
		System.out.println("NONONONO=======================================================");
		return null;
	}
	
	
	//attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
	//JWT토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면 됨
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻");
		//토큰 만들기
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal(); //이 정보로 토큰을 만든다
		
		//JWT 라이브러리로 만든다
		//RSA방식은 아니고 Hash암호방식임 - 이 방식을 더 많이 씀
		String jwtToken = JWT.create()
				.withSubject("cos토큰") //큰 의미없음
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME)) //토큰이 언제까지 유효할지 - 탈취문제 등을 고려하여 //1000이 1초 10분으로 설정함
				//토큰 만료시간은 짧게, 만료되면 다시 만들어야함
				.withClaim("id", principalDetails.getUser().getId()) // 이거는 내가 넣고싶은 것 넣으면 됨 - 키 밸류값
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET)); //시크릿 서버만 아는 고유한 값
		
		//사용자에 응답할 response 헤더
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken); //"Bearer " 한칸띄움
		
		//그러면 헤더에 이렇게 들어옴
		//Authorization Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJjb3PthqDtgbAiLCJpZCI6MSwiZXhwIjoxNzA4MzIyNDQ2LCJ1c2VybmFtZSI6InVzZXIifQ.wvoPADMPuVKwryOFk9kJP4YIR9X6sSbBpr8WbUjmr3bB-O3ZngO7cQhAI1jvauZm6CzS8I2Rm-InR3n9jyw3gw
		//이제 이 토큰이 있으면 로그인이 되었다는 의미임
		//요청할 때마다 JWT 토큰을 가지고 요청
		//서버는 JWT 토큰이 유요한지를 판단 - 필터로 판단함
		//여기서 전자서명을 통해서 개인정보에 접근이 가능하게 구현을 해본다
		
	}
	
}
