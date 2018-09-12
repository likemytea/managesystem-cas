package com.chenxing.managesystem.dao;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/**
 * liuxing
 * 
 * */
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class Test01Dao {
	@Autowired
	private JdbcTemplate jdbcTemplate;

	public String getNameById(String id) {
		String rsql = "select name from  test_01 where id=?";
		List<String> ms = jdbcTemplate.query(rsql, new RowMapper<String>() {
			@Override
			public String mapRow(ResultSet rs, int rowNum) throws SQLException {
				String url = rs.getString(1);
				return url;
			}
		}, id);

		return ms.size() > 0 ? ms.get(0) : "";
	}

}
