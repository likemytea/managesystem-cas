/**
 * 
 */
package com.chenxing.managesystem.outeriface;

import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.chenxing.managesystem.outeriface.schedual.SchedualServiceHiHystric;

/**
 * @author liuxing
 *
 */
@FeignClient(value = "eurekaclient111", fallback = SchedualServiceHiHystric.class)
public interface Servicehi {
	@RequestMapping(value = "/hi", method = RequestMethod.GET)
	String sayHiFromClient(@RequestParam(value = "name") String name);
}
