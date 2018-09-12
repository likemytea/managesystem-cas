package com.chenxing.managesystem.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import com.chenxing.managesystem.interceptor.MyAuthenticationProvider;
import com.chenxing.managesystem.service.CustomUserService;

/**
 * 初始化类：权限认证
 * <p>
 * Created by liuxing on 18/1/18.
 */

@Configuration
@EnableWebSecurity
public class MyAuthenticationConfig {

	@Autowired
	CustomUserService customUserService;// 自定义 user Details Service

	@Autowired
	private MyAuthenticationProvider provider;// 自定义的权限验证拦截器

	// 将验证过程交给 springsecurity自带的认证拦截器工具
	// @Override 或者 用@Autowired 。(如果是override，需要继承WebSecurityConfigurerAdapter接口)
	// protected void configure(AuthenticationManagerBuilder auth) throws Exception
	// {
	// auth.userDetailsService(customUserService); // user Details Service验证
	// }

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		// 将验证过程交给自定义验证工具
		auth.authenticationProvider(provider).userDetailsService(customUserService);

	}

}
