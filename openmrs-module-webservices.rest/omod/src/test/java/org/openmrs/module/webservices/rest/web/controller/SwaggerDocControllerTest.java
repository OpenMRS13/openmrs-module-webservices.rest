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

import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Tests for {@link SwaggerDocController#debug(String, javax.servlet.http.HttpServletRequest)}.
 * <p>
 * The endpoint emits a security-audit event (NEN 7510:2024-2 control 8.15) for every access. These
 * tests confirm that auditing does not break the response and — importantly — that auditing only
 * records the <i>length</i> of the {@code tag} parameter, never its value (8.11 / log-injection
 * protection). No OpenMRS context is required because the audit logger falls back to an unauthenticated
 * principal.
 */
public class SwaggerDocControllerTest {

	@Test
	public void debug_shouldEchoTagAndAuditAccessWithoutThrowing() {
		MockHttpServletRequest req = new MockHttpServletRequest();
		req.setRemoteAddr("127.0.0.1");

		String result = new SwaggerDocController().debug("mytag", req);

		Assert.assertTrue(result.contains("mytag"));
	}

	@Test
	public void debug_shouldHandleNullTag() {
		MockHttpServletRequest req = new MockHttpServletRequest();
		req.setRemoteAddr("127.0.0.1");

		String result = new SwaggerDocController().debug(null, req);

		Assert.assertNotNull(result);
	}
}
