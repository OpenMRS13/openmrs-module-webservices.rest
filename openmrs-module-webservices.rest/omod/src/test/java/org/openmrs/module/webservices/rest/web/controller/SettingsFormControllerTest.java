package org.openmrs.module.webservices.rest.web.controller;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.openmrs.api.APIException;
import org.openmrs.api.context.Context;
import org.openmrs.web.test.BaseModuleWebContextSensitiveTest;

public class SettingsFormControllerTest extends BaseModuleWebContextSensitiveTest {

	private SettingsFormController controller;

	@Before
	public void before() {
		controller = Context.getRegisteredComponents(SettingsFormController.class).iterator().next();
	}

	@Test
	public void searchProperties_shouldSucceedForAuthenticatedUserWithPrivilege() throws Exception {
		Assert.assertTrue(Context.isAuthenticated());
		// The default test environment runs as daemon/superuser who has "Manage Global Properties"
		String result = controller.searchProperties("webservices.rest");
		Assert.assertNotNull(result);
		Assert.assertTrue(result.startsWith("["));
		Assert.assertTrue(result.endsWith("]"));
		Assert.assertTrue(result.contains("webservices.rest.maxResultsDefault"));
	}

	@Test(expected = APIException.class)
	public void searchProperties_shouldFailForUnauthenticatedUser() throws Exception {
		Assert.assertTrue(Context.isAuthenticated());
		Context.logout();
		Assert.assertFalse(Context.isAuthenticated());
		controller.searchProperties("webservices.rest");
	}
}
