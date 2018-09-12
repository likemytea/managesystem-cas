package com.chenxing.managesystem.interceptor;

/**
 * 自定义拦截器：认证用户
 * 
 * */
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.chenxing.managesystem.service.CustomUserService;

@Component
public class MyAuthenticationProvider implements AuthenticationProvider {
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	@Autowired
	private CustomUserService userService;

	/**
	 * 自定义验证方式
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		String password = (String) authentication.getCredentials();
		UserDetails user = (UserDetails) userService.loadUserByUsername(username);
		if (user == null) {
			throw new BadCredentialsException("Username not found.");
		}
		log.info("用户传入的密码:" + username + ":" + password + "数据库内的密码:" + user.getUsername() + ":" + user.getPassword());
		// 加密过程在这里体现
		if (!password.equals(user.getPassword())) {
			throw new BadCredentialsException("Wrong password.");
		}

		Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
		return new UsernamePasswordAuthenticationToken(user, password, authorities);
	}

	@Override
	public boolean supports(Class<?> arg0) {
		return true;
	}

}
