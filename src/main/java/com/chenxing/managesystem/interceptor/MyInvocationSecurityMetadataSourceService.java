package com.chenxing.managesystem.interceptor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Service;

import com.chenxing.managesystem.dao.PermissionDao;
import com.chenxing.managesystem.domain.Permission;

/**
 * Created by liuxing on 17/1/19.
 */
@Service
public class MyInvocationSecurityMetadataSourceService implements FilterInvocationSecurityMetadataSource {
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	@Autowired
	private PermissionDao permissionDao;

	private HashMap<String, Collection<ConfigAttribute>> map = null;

	/**
	 * 加载资源，初始化资源变量
	 */
	public void loadResourceDefine() {
		map = new HashMap<>();
		Collection<ConfigAttribute> array;
		ConfigAttribute cfg;
		List<Permission> permissions = permissionDao.findAll();
		for (Permission permission : permissions) {
			array = new ArrayList<>();
			cfg = new SecurityConfig(permission.getName());
			array.add(cfg);
			map.put(permission.getUrl(), array);
		}

	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
		System.out.println("检查拜访者权限...");
		if (map == null)
			loadResourceDefine();
		HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
		AntPathRequestMatcher matcher;
		String resUrl;
		for (Iterator<String> iter = map.keySet().iterator(); iter.hasNext();) {
			resUrl = iter.next();
			matcher = new AntPathRequestMatcher(resUrl);
			if (matcher.matches(request)) {
				return map.get(resUrl);
			}
		}
		pringAuthority(map);
		return null;
	}

	private void pringAuthority(HashMap<String, Collection<ConfigAttribute>> map) {
		Set<String> set = map.keySet();
		for (String s : set) {
			log.info(s + "," + map.get(s));
		}
	}
	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		return null;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}
}
