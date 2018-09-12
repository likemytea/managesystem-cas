package com.chenxing.managesystem.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import com.chenxing.managesystem.interceptor.MyAccessDecisionManager;
import com.chenxing.managesystem.interceptor.MyAuthenticationAccessDeniedHandler;
import com.chenxing.managesystem.interceptor.MyFilterSecurityInterceptor;


/**
 * 启动初始化访问路径
 * 
 * @author huayu
 *
 */
@Configuration
@EnableWebSecurity
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

	/**
	 * 调用MyInvocationSecurityMetadataSource的getAttributes(Object
	 * object)这个方法获取fi对应的所有权限
	 * 
	 */
	@Autowired
	private FilterInvocationSecurityMetadataSource securityMetadataSource;
	/**
	 * 调用MyAccessDecisionManager的decide方法来校验用户的权限是否足够
	 */
	@Autowired
	private MyAccessDecisionManager myAccessDecisionManager;

	@Autowired
	MyAuthenticationAccessDeniedHandler authenticationAccessDeniedHandler;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/css/**", "/h5/**").permitAll().anyRequest().authenticated() // 任何请求,登录后可以访问
				.and().formLogin().loginPage("/login").defaultSuccessUrl("/").failureUrl("/login?error").permitAll() // 登录页面用户任意访问
				.and().headers().frameOptions().disable() // 系统页面menu内超链了html，springsecurity认为这是嵌套iframe，为潜在风险，所以把它关掉
				.and().logout().permitAll().and().csrf().disable().exceptionHandling()// 注销行为任意访问
				.accessDeniedHandler(authenticationAccessDeniedHandler);
		// spring容器托管的GenericFilterBean的bean，都会自动加入到servlet的filter
		// chain，所以MyFilterSecurityInterceptor就不要托管给spring了，
		// 因为加上下面的代码就相当于加上两次，会导致重复过滤请求path。
		MyFilterSecurityInterceptor myFilterSecurityInterceptor = new MyFilterSecurityInterceptor(
				securityMetadataSource, myAccessDecisionManager);
		http.addFilterBefore(myFilterSecurityInterceptor, FilterSecurityInterceptor.class);
	}
}