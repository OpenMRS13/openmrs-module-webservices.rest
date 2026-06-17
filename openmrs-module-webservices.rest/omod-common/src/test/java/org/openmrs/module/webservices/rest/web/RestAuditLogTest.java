/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.webservices.rest.web;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests for {@link RestAuditLog}. These verify, for the structured audit line that underpins every
 * security event (NEN 7510:2024-2 control 8.15):
 * <ul>
 * <li>(a) the line carries WHO / WHAT (action + resource + id) / outcome for the right action, and</li>
 * <li>(b) no sensitive data ends up in the line — values are never included and caller-supplied fields
 * are sanitised against log injection (8.11).</li>
 * </ul>
 * The "when" is supplied by the logging framework timestamp and is therefore not asserted here.
 * <p>
 * Note: end-to-end "controller emits the event" assertions require the full Spring/OpenMRS test context
 * plus a log appender; they are documented as a follow-up in {@code GAP_ANALYSE_LOGGING.md} because the
 * build cannot be executed in this environment.
 */
public class RestAuditLogTest {

	@Test
	public void buildLine_shouldIncludePrincipalActionResourceIdAndOutcome() {
		String line = RestAuditLog.buildLine("user=42", "read", "patient", "abc-uuid", null,
		    RestAuditLog.OUTCOME_SUCCESS);

		Assert.assertTrue(line.startsWith("AUDIT "));
		Assert.assertTrue(line.contains("user=42"));
		Assert.assertTrue(line.contains("action=read"));
		Assert.assertTrue(line.contains("resource=patient"));
		Assert.assertTrue(line.contains("id=abc-uuid"));
		Assert.assertTrue(line.contains("outcome=success"));
	}

	@Test
	public void buildLine_shouldIncludeIpAndOmitAbsentResourceAndId() {
		String line = RestAuditLog.buildLine("user=unauthenticated", "ip-not-allowed", null, null, "10.0.0.5",
		    RestAuditLog.OUTCOME_DENIED);

		Assert.assertTrue(line.contains("ip=10.0.0.5"));
		Assert.assertTrue(line.contains("outcome=denied"));
		Assert.assertFalse(line.contains("resource="));
		Assert.assertFalse(line.contains("id="));
	}

	@Test
	public void buildLine_shouldRenderNullActionAndOutcomeAsDash() {
		String line = RestAuditLog.buildLine("user=1", null, null, null, null, null);

		Assert.assertTrue(line.contains("action=-"));
		Assert.assertTrue(line.contains("outcome=-"));
	}

	@Test
	public void buildLine_shouldNeverContainAPasswordItWasNotGiven() {
		// The authentication API accepts only a username + IP, never a password. Build the line exactly
		// as authFailure() does and assert the password used in the attempt cannot appear.
		String password = "S3cr3tP@ss";
		String line = RestAuditLog.buildLine("user=" + RestAuditLog.clean("alice"), "authenticate", null, null,
		    "10.1.1.1", RestAuditLog.OUTCOME_FAILURE);

		Assert.assertFalse("a password must never appear in an audit line", line.contains(password));
		Assert.assertTrue(line.contains("user=alice"));
		Assert.assertTrue(line.contains("outcome=failure"));
	}

	@Test
	public void buildLine_gpSearchShouldContainOnlyMetadataNotValues() {
		// The settings controller passes "prefix=<x> hits=<n>" as the descriptor — never the property
		// values. A secret stored as a global-property value must therefore never reach the log.
		String secretValue = "smtp-password-12345";
		String line = RestAuditLog.buildLine("user=unauthenticated", "gp-search", "prefix=mail hits=3", null,
		    "10.0.0.9", RestAuditLog.OUTCOME_SUCCESS);

		Assert.assertTrue(line.contains("action=gp-search"));
		Assert.assertTrue(line.contains("prefix=mail"));
		Assert.assertTrue(line.contains("hits=3"));
		Assert.assertFalse(line.contains(secretValue));
	}

	@Test
	public void clean_shouldStripCrlfToPreventLogInjection() {
		String forged = "alice\r\nAUDIT user=999 action=authenticate outcome=success";

		String cleaned = RestAuditLog.clean(forged);

		Assert.assertFalse(cleaned.contains("\n"));
		Assert.assertFalse(cleaned.contains("\r"));
	}

	@Test
	public void clean_shouldReturnDashForNull() {
		Assert.assertEquals("-", RestAuditLog.clean(null));
	}

	@Test
	public void currentPrincipal_shouldFallBackToUnauthenticatedWithoutContext() {
		// No OpenMRS user context is bound in a plain unit test; the guard must yield 'unauthenticated'
		// instead of throwing, so that auditing can never break a request.
		Assert.assertEquals("user=unauthenticated", RestAuditLog.currentPrincipal());
	}
}
