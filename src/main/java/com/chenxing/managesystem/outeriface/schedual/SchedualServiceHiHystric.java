/**
 * 
 */
package com.chenxing.managesystem.outeriface.schedual;

import org.springframework.stereotype.Component;

import com.chenxing.managesystem.outeriface.Servicehi;

/**
 * @author HXDF
 *
 */
@Component
public class SchedualServiceHiHystric implements Servicehi {

	@Override
	public String sayHiFromClient(String name) {
		return "网络异常或被调用服务重启过程中...： " + name;
	}

}
