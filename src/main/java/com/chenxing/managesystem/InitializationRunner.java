package com.chenxing.managesystem;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import com.chenxing.managesystem.service.CustomUserService;

/**
 * Description: 系统初始化
 * 
 * @author liuxing
 * @date 2018年7月25日
 * @version 1.0
 */
@Component
public class InitializationRunner implements ApplicationRunner {
	@Autowired
	private CustomUserService customUserService;
	private final Logger log = LoggerFactory.getLogger(this.getClass());

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.boot.ApplicationRunner#run(org.springframework.boot.
	 * ApplicationArguments)
	 */
	@Override
	public void run(ApplicationArguments args) throws Exception {
		log.info("initialization start ...");
		todo();
	}

	/**
	 * task1
	 */
	private void todo() {
	}
}