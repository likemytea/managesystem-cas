package com.chenxing.managesystem.config;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.alibaba.druid.pool.DruidDataSource;
import com.chenxing.common.jdbc.MyJdbcTemplate;

@Configuration
public class DBConfig {
	private final Logger log = LoggerFactory.getLogger(this.getClass());

	/** 数据源1 start */
	@Bean(name = "dataSourcep3", destroyMethod = "close", initMethod = "init")
	@ConfigurationProperties("spring.datasource.p3")
	public com.alibaba.druid.pool.DruidDataSource getDataSourcep1() {

		log.info("initializing data source p3....！");
		DruidDataSource druidDataSource = new DruidDataSource();
		return druidDataSource;
	}

	@Bean(name = "myJdbcTemplatep3")
	public MyJdbcTemplate getJdbcTemplatePrimary1(@Qualifier("dataSourcep3") DataSource dataSource) {
		return new MyJdbcTemplate(dataSource);
	}
}