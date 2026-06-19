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

import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Centralised, structured security audit logging for the REST web services module
 * (NEN 7510:2024-2 control 8.15 "Logging" / 8.16 "Monitoring of activities").
 * <p>
 * Every audit record captures <b>who</b> (the acting principal), <b>what</b> (an action plus the
 * affected resource type and identifier), <b>when</b> (provided by the logging framework timestamp)
 * and the <b>outcome</b> (success / failure / denied). Records are emitted through a dedicated logger
 * named {@link #AUDIT_LOGGER_NAME} so that a deployment can route them to a separate, append-only or
 * otherwise integrity-protected appender/SIEM (see residual point on log immutability/retention,
 * which is a deployment concern outside the scope of this module).
 * <p>
 * <b>Sensitive data is never accepted here as a value.</b> Callers must pass identifiers and metadata
 * only — never PHI content, passwords, tokens, API keys or global-property values. All
 * caller-supplied fields are additionally sanitised (control characters stripped) to prevent log
 * injection / forging.
 */
public class RestAuditLog {

	/** Dedicated logger name so audit events can be routed/retained separately from technical logs. */
	public static final String AUDIT_LOGGER_NAME = "org.openmrs.module.webservices.rest.audit";

	public static final String OUTCOME_SUCCESS = "success";

	public static final String OUTCOME_FAILURE = "failure";

	public static final String OUTCOME_DENIED = "denied";

	private static final Logger auditLog = LoggerFactory.getLogger(AUDIT_LOGGER_NAME);

	private RestAuditLog() {
	}

	/**
	 * Logs a successful authentication. The username is the login identifier of the subject being
	 * authenticated (needed for brute-force detection); no password is ever passed in.
	 */
	public static void authSuccess(String username, String ip) {
		auditLog.info(buildLine("user=" + clean(username), "authenticate", null, null, ip, OUTCOME_SUCCESS));
	}

	/**
	 * Logs a failed authentication attempt at WARN so it is available for monitoring/alerting.
	 */
	public static void authFailure(String username, String ip) {
		auditLog.warn(buildLine("user=" + clean(username), "authenticate", null, null, ip, OUTCOME_FAILURE));
	}

	/**
	 * Logs a request that was denied before reaching application logic (e.g. IP not allow-listed).
	 */
	public static void accessDenied(String action, String ip) {
		auditLog.warn(buildLine(currentPrincipal(), action, null, null, ip, OUTCOME_DENIED));
	}

	/**
	 * Logs a read/inspection of a resource (e.g. PHI retrieval, list, search) by the current user.
	 * Only the resource type and identifier are logged, never the content.
	 */
	public static void read(String resourceType, String resourceId) {
		auditLog.info(buildLine(currentPrincipal(), "read", resourceType, resourceId, null, OUTCOME_SUCCESS));
	}

	/**
	 * Logs a state-changing action (create/update/delete/admin/config) by the current user at INFO.
	 */
	public static void write(String action, String resourceType, String resourceId) {
		auditLog.info(buildLine(currentPrincipal(), action, resourceType, resourceId, null, OUTCOME_SUCCESS));
	}

	/**
	 * Logs a particularly sensitive or irreversible action (e.g. purge, changing another user's
	 * password) at WARN so it stands out in monitoring.
	 */
	public static void sensitive(String action, String resourceType, String resourceId) {
		auditLog.warn(buildLine(currentPrincipal(), action, resourceType, resourceId, null, OUTCOME_SUCCESS));
	}

	/**
	 * Logs access to a sensitive endpoint where the caller may be unauthenticated and the source IP is
	 * relevant (e.g. the diagnostics/debug/global-property-search endpoints). The {@code detail} is a
	 * non-sensitive descriptor (e.g. a search prefix or a result count) — never a secret value.
	 */
	public static void sensitiveAccess(String action, String detail, String ip) {
		auditLog.warn(buildLine(currentPrincipal(), action, detail, null, ip, OUTCOME_SUCCESS));
	}

	/**
	 * Resolves the current authenticated principal as {@code user=<id>}, or {@code user=unauthenticated}
	 * if there is no authenticated user. The numeric user id is used rather than the username to limit
	 * personal data in the log while keeping the action attributable.
	 */
	static String currentPrincipal() {
		try {
			User user = Context.getAuthenticatedUser();
			if (user != null && user.getUserId() != null) {
				return "user=" + user.getUserId();
			}
		}
		catch (Exception ex) {
			// auditing must never break the request; fall through to unauthenticated
		}
		return "user=unauthenticated";
	}

	/**
	 * Builds the single, structured audit line. Package-private so it can be unit-tested directly
	 * (deterministic, no logging backend required).
	 */
	static String buildLine(String principal, String action, String resourceType, String resourceId, String ip,
	        String outcome) {
		StringBuilder sb = new StringBuilder("AUDIT ");
		sb.append(principal);
		sb.append(" action=").append(clean(action));
		if (resourceType != null) {
			sb.append(" resource=").append(clean(resourceType));
		}
		if (resourceId != null) {
			sb.append(" id=").append(clean(resourceId));
		}
		if (ip != null) {
			sb.append(" ip=").append(clean(ip));
		}
		sb.append(" outcome=").append(clean(outcome));
		return sb.toString();
	}

	/**
	 * Strips CR/LF and other control characters from caller-supplied fields to prevent log
	 * injection/forging, and replaces a null with a dash so the field is always present.
	 */
	static String clean(String value) {
		if (value == null) {
			return "-";
		}
		return value.replaceAll("[\\p{Cntrl}]", "_");
	}
}
