package org.openmrs.module.webservices.rest.web.controller;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.openmrs.api.context.Context;
import org.openmrs.web.test.BaseModuleWebContextSensitiveTest;

public class SwaggerDocControllerTest extends BaseModuleWebContextSensitiveTest {

	private SwaggerDocController controller;

	@Before
	public void before() {
		controller = Context.getRegisteredComponents(SwaggerDocController.class).iterator().next();
	}

	@Test
	public void debug_shouldReturnEscapedHtmlToPreventXss() {
		String input = "<script>alert('xss')</script>";
		String result = controller.debug(input);
		Assert.assertNotNull(result);
		// Check that the result is escaped and does not contain raw tag
		Assert.assertTrue(result.contains("&lt;script&gt;alert('xss')&lt;/script&gt;"));
		Assert.assertFalse(result.contains("<script>"));
	}
}
