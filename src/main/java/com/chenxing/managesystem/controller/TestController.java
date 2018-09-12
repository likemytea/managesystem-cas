/**
 * 
 */
package com.chenxing.managesystem.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.chenxing.common.result.BaseResult;
import com.chenxing.managesystem.outeriface.Servicehi;
import com.chenxing.managesystem.service.TestService;

/**
 * @author liuxing
 */
@RestController
@RequestMapping(value = "/user", method = RequestMethod.GET)
public class TestController {
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	@Autowired
	TestService tervice;
	@Autowired
	Servicehi servicehi;

	@RequestMapping(value = "/sayHitoUser", method = RequestMethod.GET)
	public String sayHi(@RequestParam String id, @RequestParam String name) {
		log.info(name);
		long start = System.currentTimeMillis();
		String res = null;
		try {
			String resaa = tervice.updateName(id, name);
			res = "ver:1  " + "name：" + resaa;
		} catch (Exception e) {
			e.printStackTrace();
		}

		long end = System.currentTimeMillis();
		log.info("消耗时长 " + (start - end) + "毫秒");

		return res;

	}

	@RequestMapping(value = "/sayHi01", method = RequestMethod.GET)
	public BaseResult<String> sayHiLiuxing(@RequestParam String id, @RequestParam String name,
			@RequestParam int currentpage, @RequestParam int pagesize) {
		BaseResult<String> result = new BaseResult<>();
		log.info(name);
		long start = System.currentTimeMillis();
		String res = null;
		try {
			res = servicehi.sayHiFromClient(name);
			res += "feign版本2.8";
		} catch (Exception e) {
			e.printStackTrace();
		}

		long end = System.currentTimeMillis();
		log.info("消耗时长 " + (start - end) + "毫秒");
		result.setData(res);
		return result;

	}

}
