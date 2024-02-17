package com.cos.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import com.cos.jwt.filter.MyFilter3;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	
	@Autowired
	private final CorsFilter corsFilter;

	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		//jwt를 위해서 다르게 설정한것
		//1. 내 서버는 STATELESS 서버
		//2. cros 정책에서 벗어남
		//3. 폼 로그인 안 쓸거임
		
		//필터걸기
		//BasicAuthenticationFilter가 시작하기 전에 MyFilter1가 걸린다 -> 이렇게 걸면됨 -> 필터 실행 순서를 알아야함
		http.addFilterBefore(new MyFilter2(), BasicAuthenticationFilter.class); // 두번째 -> 그 다음에 이제 filterconfig
		//그런데 여기다 걸 필요는 없고 따로 필터컨피그 만들어서 걸어도 됨 ->filterconfig보다 시큐리티 필터가 먼저 실행된다
		//시큐리티 필터보다 먼저 실행하게 만들기 위해서는 이렇게 따로 설정한다
		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // 제일 먼저 실행됨
		
		//deprecated 제거
		http.csrf(c->c.disable())
			.sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			// STATELESS 방식은 세션을 사용하지 않겠다
			.addFilter(corsFilter) //cors 정책에서 벗어날 수 있음
			//@CrossOrigin(인증x상황에서), 시큐리티 필터에 등록(인증o일때도 가능하게)
			//.and()
			.formLogin(f->f.disable())
			.httpBasic(h->h.disable()) //기본적인 http로그인 방식, 세션만드는 방식을 사용하지 않음 -> bearer 방식을 사용하겠다.
			//.addFilter(new JwtAuthenticationFilter(authenticationManager)); // 여기서 전달해야 할 파라메타 AuthenticationManager이걸 줘야함 AuthenticationManager를 통해서 로그인을 진행함
			.apply(new MyCustomDsl());
			
		http.authorizeHttpRequests( r -> r
			.requestMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
			.requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
			.requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
			.anyRequest().permitAll());
		
		
		return http.build();
	}
	
	//authenticationManager 사용하기 위해서 - 일단 이렇게 넣어둔다
	public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http.addFilter(new JwtAuthenticationFilter(authenticationManager));

        }
    }
	
}
