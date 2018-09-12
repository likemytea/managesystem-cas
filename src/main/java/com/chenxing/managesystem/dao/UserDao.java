package com.chenxing.managesystem.dao;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import com.chenxing.common.jdbc.MyJdbcTemplate;
import com.chenxing.common.pagination.PaginationResult;
import com.chenxing.common.pagination.SortType;
import com.chenxing.common.vo.PageResult;
import com.chenxing.managesystem.domain.SysRole;
import com.chenxing.managesystem.domain.SysUser;

/**
 * Description:
 * 
 * @author liuxing
 * @date 2018年5月14日
 * @version 1.0
 */
@Repository
public class UserDao {

	@Autowired
	@Qualifier("myJdbcTemplatep3")
	private MyJdbcTemplate jdbcTemplate;

	public SysUser findByUserName(String username) {

		String rsql = "SELECT u.sys_user_id,u.username,u.password,r.name from sys_user u "
				+ "left join sys_role_user sru on u.sys_user_id= sru.sys_user_id "
				+ "LEFT JOIN sys_role r on sru.sys_role_id=r.id where username= ?";

		List<Map<String, String>> ms = jdbcTemplate.query(rsql, new RowMapper<Map<String, String>>() {
			@Override
			public Map<String, String> mapRow(ResultSet rs, int rowNum) throws SQLException {
				Map<String, String> p = new HashMap<String, String>();
				p.put("userid", String.valueOf(rs.getInt(1)));
				p.put("username", rs.getString(2));
				p.put("password", rs.getString(3));
				p.put("rolename", rs.getString(4));
				return p;
			}
		}, username);
		return map2Obj(ms);
	}

	public PageResult<SysUser> findUser(int currentpage, int pagesize) {

		String rsql = "SELECT u.sys_user_id,u.username,u.password from sys_user u";
		PaginationResult<Map<String, String>> res = jdbcTemplate.queryForPage(rsql, currentpage, pagesize,
				"sys_user_id",
				SortType.DESC,
				new RowMapper<Map<String, String>>() {
			@Override
			public Map<String, String> mapRow(ResultSet rs, int rowNum) throws SQLException {
				Map<String, String> p = new HashMap<String, String>();
				p.put("userid", String.valueOf(rs.getInt(1)));
				p.put("username", rs.getString(2));
				p.put("password", rs.getString(3));
				return p;
			}
		});
		List<SysUser> lst = map2Obj2(res.getData());
		PageResult<SysUser> pr = new PageResult<SysUser>();
		pr.setArray(lst);
		pr.setTotalCount(res.getTotalCount());
		pr.setTotalPage(res.getTotalPage());
		return pr;
	}

	private List<SysUser> map2Obj2(List<Map<String, String>> ms) {
		List<SysUser> list = new ArrayList<SysUser>();
		SysUser user = null;
		for (Map<String, String> map : ms) {
			user = new SysUser();
			user.setId(Integer.parseInt(map.get("userid")));
			user.setUsername(map.get("username"));
			user.setPassword(map.get("password"));
			list.add(user);
		}
		return list;
	}

	private SysUser map2Obj(List<Map<String, String>> ms) {
		SysUser p = new SysUser();
		SysRole sysRole = null;
		List<SysRole> roles = new ArrayList<SysRole>();
		for (Map<String, String> map : ms) {
			sysRole = new SysRole();
			p.setId(Integer.parseInt(map.get("userid")));
			p.setUsername(map.get("username"));
			p.setPassword(map.get("password"));
			sysRole.setName(map.get("rolename"));
			roles.add(sysRole);
		}
		p.setRoles(roles);
		return p;
	}
}