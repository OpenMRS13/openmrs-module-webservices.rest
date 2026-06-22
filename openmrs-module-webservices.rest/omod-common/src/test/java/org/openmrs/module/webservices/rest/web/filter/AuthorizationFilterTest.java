/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.webservices.rest.web.filter;

import java.util.Base64;

import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;
import org.openmrs.GlobalProperty;
import org.openmrs.api.context.Context;
import org.openmrs.module.webservices.rest.web.RestConstants;
import org.openmrs.web.test.BaseModuleWebContextSensitiveTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Tests for {@link AuthorizationFilter}, focused on the security-audit behaviour added for
 * NEN 7510:2024-2 control 8.15 (IP denial and failed-authentication events). The filter delegates to
 * {@link org.openmrs.module.webservices.rest.web.RestAuditLog}; these tests drive the request paths that
 * produce those audit events. They are context-sensitive because the IP allow-list check reads a global
 * property through the OpenMRS {@code Context}.
 */
public class AuthorizationFilterTest extends BaseModuleWebContextSensitiveTest {

	private MockHttpServletResponse runFilter(MockHttpServletRequest req) throws Exception {
		MockHttpServletResponse resp = new MockHttpServletResponse();
		new AuthorizationFilter().doFilter(req, resp, new MockFilterChain());
		return resp;
	}

	@Test
	public void doFilter_shouldDenyAndAuditWhenIpIsNotAllowed() throws Exception {
		Context.getAdministrationService().saveGlobalProperty(
		    new GlobalProperty(RestConstants.ALLOWED_IPS_GLOBAL_PROPERTY_NAME, "1.2.3.4"));
		MockHttpServletRequest req = new MockHttpServletRequest();
		req.setRemoteAddr("9.9.9.9");

		MockHttpServletResponse resp = runFilter(req);

		Assert.assertEquals(HttpServletResponse.SC_FORBIDDEN, resp.getStatus());
	}

	@Test
	public void doFilter_shouldAuditFailedAuthForBlankCredentials() throws Exception {
		// Enter the unauthenticated branch so the Basic-auth parsing (and its audit) is exercised.
		Context.logout();
		MockHttpServletRequest req = new MockHttpServletRequest();
		req.setRemoteAddr("127.0.0.1");
		req.addHeader("Authorization", "Basic ");

		MockHttpServletResponse resp = runFilter(req);

		Assert.assertEquals(HttpServletResponse.SC_BAD_REQUEST, resp.getStatus());
	}

	@Test
	public void doFilter_shouldAuditFailedAuthForCredentialsWithoutColon() throws Exception {
		Context.logout();
		String encoded = Base64.getEncoder().encodeToString("nocolon".getBytes("UTF-8"));
		MockHttpServletRequest req = new MockHttpServletRequest();
		req.setRemoteAddr("127.0.0.1");
		req.addHeader("Authorization", "Basic " + encoded);

		MockHttpServletResponse resp = runFilter(req);

		Assert.assertEquals(HttpServletResponse.SC_BAD_REQUEST, resp.getStatus());
	}

	@Test
	public void doFilter_shouldAuditFailedAuthForInvalidCredentialsAndContinueChain() throws Exception {
		Context.logout();
		String encoded = Base64.getEncoder().encodeToString("baduser:badpass".getBytes("UTF-8"));
		MockHttpServletRequest req = new MockHttpServletRequest();
		req.setRemoteAddr("127.0.0.1");
		req.addHeader("Authorization", "Basic " + encoded);

		MockHttpServletResponse resp = runFilter(req);

		// The filter never blocks on a failed authentication; it audits the failure and lets the chain
		// continue (the API enforces authorization downstream).
		Assert.assertNotEquals(HttpServletResponse.SC_BAD_REQUEST, resp.getStatus());
		Assert.assertFalse(Context.isAuthenticated());
	}
}
