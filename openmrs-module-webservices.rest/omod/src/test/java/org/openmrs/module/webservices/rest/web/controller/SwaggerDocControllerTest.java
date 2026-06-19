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

public class SwaggerDocControllerTest {

	private final SwaggerDocController controller = new SwaggerDocController();

	@Test
	public void debug_shouldReturnEscapedHtmlToPreventXss() {
		String input = "<script>alert('xss')</script>";
		String result = controller.debug(input);
		Assert.assertNotNull(result);
		Assert.assertEquals("<h1>Debugging Tag: &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;</h1>", result);
		Assert.assertFalse(result.contains("<script>"));
	}
}
