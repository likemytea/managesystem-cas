package com.chenxing.managesystem.service;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.chenxing.managesystem.dao.PermissionDao;
import com.chenxing.managesystem.dao.UserDao;
import com.chenxing.managesystem.domain.Permission;
import com.chenxing.managesystem.domain.SysUser;

@Component
public class CasUserDetailService implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

	private final Logger log = LoggerFactory.getLogger(this.getClass());

	@Resource
	private UserDao userDao;
	@Autowired
	PermissionDao permissionDao;
	@Override
	public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
		log.info("校验成功的登录名为: " + token.getName());
		// 此处涉及到数据库操作然后读取权限集合，读者可自行实现
		SysUser user = userDao.findByUserName(token.getName());
		if (user != null && user.getId() != null) {
			List<Permission> permissions = permissionDao.findByPermissionByUserId(user.getId());
			List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
			for (Permission permission : permissions) {
				if (permission != null && permission.getName() != null) {

					GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(permission.getName());
					grantedAuthorities.add(grantedAuthority);
				}
			}
			return new User(user.getUsername(), user.getPassword(), grantedAuthorities);
		} else {
			throw new UsernameNotFoundException("admin: " + token.getName() + " do not exist!");
		}
	}

}
