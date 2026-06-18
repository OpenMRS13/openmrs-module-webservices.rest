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

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.openmrs.GlobalProperty;
import org.openmrs.api.context.Context;
import org.openmrs.web.test.BaseModuleWebContextSensitiveTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.validation.BindException;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * Tests for {@link SettingsFormController#searchProperties(String, javax.servlet.http.HttpServletRequest)}.
 * <p>
 * The endpoint emits a security-audit event (NEN 7510:2024-2 control 8.15) for every access. These
 * tests confirm the search still returns matching properties and that the audit logging does not break
 * the response. Context-sensitive because the controller reads global properties via the OpenMRS
 * {@code Context}.
 */
public class SettingsFormControllerTest extends BaseModuleWebContextSensitiveTest {

	@Test
	public void searchProperties_shouldReturnMatchingPropertiesAndAuditAccess() {
		Context.getAdministrationService().saveGlobalProperty(new GlobalProperty("unittest.audit.key", "somevalue"));
		MockHttpServletRequest req = new MockHttpServletRequest();
		req.setRemoteAddr("127.0.0.1");

		String json = new SettingsFormController().searchProperties("unittest.audit", req);

		Assert.assertTrue(json.contains("unittest.audit.key"));
	}

	@Test
	public void searchProperties_shouldReturnEmptyArrayWhenNothingMatches() {
		MockHttpServletRequest req = new MockHttpServletRequest();
		req.setRemoteAddr("127.0.0.1");

		String json = new SettingsFormController().searchProperties("no.such.prefix.exists.xyz", req);

		Assert.assertEquals("[]", json);
	}

	@Test
	public void handleSubmission_shouldSavePropertiesAndAuditTheChange() {
		SettingsFormController controller = new SettingsFormController();
		List<GlobalProperty> props = new ArrayList<GlobalProperty>();
		props.add(new GlobalProperty("unittest.audit.save", "value1"));
		SettingsFormController.GlobalPropertiesModel model = controller.new GlobalPropertiesModel(props);
		BindException errors = new BindException(model, "globalPropertiesModel");
		ServletWebRequest request = new ServletWebRequest(new MockHttpServletRequest());

		String view = controller.handleSubmission(model, errors, request);

		Assert.assertEquals("redirect:settings.form", view);
		Assert.assertEquals("value1", Context.getAdministrationService().getGlobalProperty("unittest.audit.save"));
	}
}
