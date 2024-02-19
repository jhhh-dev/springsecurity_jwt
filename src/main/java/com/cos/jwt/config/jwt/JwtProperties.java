package com.cos.jwt.config.jwt;

public interface JwtProperties {
	//하드코딩 하지말고 이렇게 만들어서 관리해야함 이렇게
//	String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
//	String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
	
	String SECRET = "cos"; // 우리 서버만 알고 있는 비밀값
	int EXPIRATION_TIME = 60000*30; // 10분
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";

}
