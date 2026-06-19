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

import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.openmrs.GlobalProperty;
import org.openmrs.api.APIException;
import org.openmrs.api.AdministrationService;

public class SettingsFormControllerTest {

	private SettingsFormController newControllerWithProperties(List<GlobalProperty> properties) {
		AdministrationService administrationService = Mockito.mock(AdministrationService.class);
		Mockito.when(administrationService.getGlobalPropertiesByPrefix("webservices.rest")).thenReturn(properties);

		return new SettingsFormController() {
			@Override
			protected void requireManageGlobalPropertiesPrivilege() {
				// authenticated test path only needs the controller logic
			}

			@Override
			protected AdministrationService getAdministrationService() {
				return administrationService;
			}
		};
	}

	@Test
	public void searchProperties_shouldSucceedForAuthenticatedUserWithPrivilege() throws Exception {
		SettingsFormController controller = newControllerWithProperties(Collections.singletonList(new GlobalProperty(
			"webservices.rest.maxResultsDefault", "50")));
		String result = controller.searchProperties("webservices.rest");
		Assert.assertNotNull(result);
		Assert.assertTrue(result.startsWith("["));
		Assert.assertTrue(result.endsWith("]"));
		Assert.assertTrue(result.contains("webservices.rest.maxResultsDefault"));
	}

	@Test(expected = APIException.class)
	public void searchProperties_shouldFailForUnauthenticatedUser() throws Exception {
		SettingsFormController controller = new SettingsFormController() {
			@Override
			protected void requireManageGlobalPropertiesPrivilege() {
				throw new APIException();
			}

			@Override
			protected AdministrationService getAdministrationService() {
				return Mockito.mock(AdministrationService.class);
			}
		};
		controller.searchProperties("webservices.rest");
	}
}
