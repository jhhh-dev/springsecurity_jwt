package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		//req.setCharacterEncoding("UTF-8");
		
		//임시 토큰 만들어서 넣어보기
		//토큰 : cos -> 라는 토큰이 넘어오면 인증되게 하고, 아니면 진입을 못하게
		//즉, 우리는 토큰 : cos 이걸 만들어줘야함. id, pw정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답을 해준다.
		//요청할 때마다 header에 Authorization에 value값으로 토큰을 가지고 옴
		//그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면 됨 - RSA, HS256
		if(req.getMethod().equals("POST")) {
			System.out.println("POST 요청됨");
			String headerAuth = req.getHeader("Authorization");
			System.out.println(headerAuth); //아무것도 안 넣었을 때 null - postman으로 header에 Authorization값 넣어서 전송하면 출력됨
			
			if(headerAuth!=null && headerAuth.equals("cos")) {
				chain.doFilter(req, res);
			}else {
				PrintWriter out = res.getWriter();
				out.println("인증안됨");
			}
		}
		
		//System.out.println("필터33");
		//chain.doFilter(request, response); //여기 필터에 걸려도 끝나지 말고 넘겨주라는 뜻임
	}

}
