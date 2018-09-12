package com.chenxing.managesystem.controller;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.alibaba.fastjson.JSON;
import com.chenxing.common.vo.PageResult;
import com.chenxing.managesystem.domain.SysUser;
import com.chenxing.managesystem.service.CustomUserService;

/**
 * 系统功能类：主要用来管理系统权限，角色，系统的使用者如管理员等等
 * <p>
 * Created by liuxing on 17/1/18.
 */
@RestController
public class SystemController {
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	@Autowired
	private CustomUserService customUserService;

	@ResponseBody
	@RequestMapping(value = "/system/user/list", method = RequestMethod.GET, produces = "application/json;charset=UTF-8")
	public String getUserList(@RequestParam int currentpage, @RequestParam int pagesize, HttpServletResponse response) {
		UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		log.info("security holder-username：" + userDetails.getUsername());
		PageResult<SysUser> list = customUserService.findUserList(currentpage, pagesize);
		log.info("user数组"+JSON.toJSONString(list));
		return JSON.toJSONString(list);

	}

}
