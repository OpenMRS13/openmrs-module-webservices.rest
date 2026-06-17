/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.webservices.rest.web.controller;

import javax.servlet.http.HttpServletRequest;

import org.openmrs.module.webservices.rest.web.RestAuditLog;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller("webservices.rest.SwaggerDocController")
@RequestMapping("/module/webservices/rest/apiDocs")
public class SwaggerDocController {
	
	@RequestMapping(method = RequestMethod.GET)
	public void get() {
	}

	@RequestMapping(value = "/debug", method = RequestMethod.GET)
	@org.springframework.web.bind.annotation.ResponseBody
	public String debug(@org.springframework.web.bind.annotation.RequestParam("tag") String tag, HttpServletRequest request) {
		// Audit (NEN 7510 8.15/8.16): log access to this unauthenticated debug endpoint at WARN with the
		// source IP. Only the LENGTH of 'tag' is logged, never its value (avoids log injection / XSS payload echo).
		RestAuditLog.sensitiveAccess("apidocs-debug", "tagLength=" + (tag == null ? 0 : tag.length()),
		    request.getRemoteAddr());
		return "<h1>Debugging Tag: " + tag + "</h1>";
	}
	
}
