/**
 * Microsoft Graph security API types, v1.0.
 *
 * MMS 2026 Midway Edition - "Empowering SOC Teams".
 *
 * Hand-written from the Microsoft Learn reference, October 2026, rather than
 * generated, so the enums carry the comments that matter at 2am.
 *
 *   https://learn.microsoft.com/graph/api/resources/security-incident
 *   https://learn.microsoft.com/graph/api/resources/security-alert
 *   https://learn.microsoft.com/graph/api/security-security-runhuntingquery
 *
 * These match ../data/*.json exactly, so code written against the mock server
 * compiles and runs unchanged against graph.microsoft.com.
 */

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/** Shared by incidents and alerts. */
export type AlertSeverity =
  | 'unknown'
  | 'informational'
  | 'low'
  | 'medium'
  | 'high'
  | 'unknownFutureValue';

/**
 * Incident status. Note there is no 'new' here - a fresh incident is 'active'.
 * 'awaitingAction' only comes back if you send the request header
 * `Prefer: include-unknown-enum-members`.
 */
export type IncidentStatus =
  | 'active'
  | 'resolved'
  | 'inProgress'
  | 'redirected'
  | 'awaitingAction'
  | 'unknownFutureValue';

/** Alert status. Different set from IncidentStatus - no 'active', no 'redirected'. */
export type AlertStatus =
  | 'unknown'
  | 'new'
  | 'inProgress'
  | 'resolved'
  | 'unknownFutureValue';

/** Shared by incidents and alerts. */
export type AlertClassification =
  | 'unknown'
  | 'falsePositive'
  | 'truePositive'
  | 'informationalExpectedActivity'
  | 'unknownFutureValue';

/**
 * Determination for an INCIDENT.
 *
 * This is not the same set as the alert version. Incidents have
 * 'compromisedUser', 'clean' and 'insufficientData'; alerts do not. Sending an
 * alert-only value here is a 400. Keep the two types apart - that is why this
 * file does not share one union between them.
 */
export type IncidentDetermination =
  | 'unknown'
  | 'apt'
  | 'malware'
  | 'securityPersonnel'
  | 'securityTesting'
  | 'unwantedSoftware'
  | 'other'
  | 'multiStagedAttack'
  | 'compromisedUser'
  | 'phishing'
  | 'maliciousUserActivity'
  | 'clean'
  | 'insufficientData'
  | 'confirmedActivity'
  | 'lineOfBusinessApplication'
  | 'unknownFutureValue';

/**
 * Determination for an ALERT.
 *
 * Alert-only values: 'compromisedAccount', 'notMalicious',
 * 'notEnoughDataToValidate'. See the warning on IncidentDetermination.
 */
export type AlertDetermination =
  | 'unknown'
  | 'apt'
  | 'malware'
  | 'securityPersonnel'
  | 'securityTesting'
  | 'unwantedSoftware'
  | 'other'
  | 'multiStagedAttack'
  | 'compromisedAccount'
  | 'phishing'
  | 'maliciousUserActivity'
  | 'notMalicious'
  | 'notEnoughDataToValidate'
  | 'confirmedActivity'
  | 'lineOfBusinessApplication'
  | 'unknownFutureValue';

/**
 * Which product raised the alert. `microsoftSentinel` is the one to filter on
 * when you want Sentinel analytics-rule alerts specifically:
 *
 *   GET /security/alerts_v2?$filter=serviceSource eq 'microsoftSentinel'
 */
export type ServiceSource =
  | 'unknown'
  | 'microsoftDefenderForEndpoint'
  | 'microsoftDefenderForIdentity'
  | 'microsoftDefenderForCloudApps'
  | 'microsoftDefenderForOffice365'
  | 'microsoft365Defender'
  | 'azureAdIdentityProtection'
  | 'microsoftAppGovernance'
  | 'dataLossPrevention'
  | 'microsoftDefenderForCloud'
  | 'microsoftSentinel'
  | 'microsoftThreatIntelligence'
  | 'microsoftSecurityForAI'
  | 'unknownFutureValue';

export type InvestigationState =
  | 'unknown'
  | 'terminated'
  | 'successfullyRemediated'
  | 'benign'
  | 'failed'
  | 'partiallyRemediated'
  | 'running'
  | 'pendingApproval'
  | 'pendingResource'
  | 'queued'
  | 'innerFailure'
  | 'preexistingAlert'
  | 'unsupportedOs'
  | 'unsupportedAlertType'
  | 'suppressedAlert'
  | 'partiallyInvestigated'
  | 'terminatedByUser'
  | 'terminatedBySystem'
  | 'unknownFutureValue';

export type EvidenceVerdict =
  | 'unknown'
  | 'suspicious'
  | 'malicious'
  | 'noThreatsFound'
  | 'unknownFutureValue';

export type EvidenceRemediationStatus =
  | 'none'
  | 'remediated'
  | 'prevented'
  | 'blocked'
  | 'notFound'
  | 'active'
  | 'pendingApproval'
  | 'declined'
  | 'notRemediated'
  | 'running'
  | 'unknownFutureValue';

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

export interface UserAccount {
  accountName?: string | null;
  domainName?: string | null;
  userPrincipalName?: string | null;
  userSid?: string | null;
  azureAdUserId?: string | null;
  displayName?: string | null;
}

export interface FileDetails {
  fileName?: string | null;
  filePath?: string | null;
  fileSize?: number | null;
  sha1?: string | null;
  sha256?: string | null;
  issuer?: string | null;
  signer?: string | null;
}

/** Fields every evidence subtype carries. */
export interface AlertEvidenceBase {
  '@odata.type': string;
  createdDateTime?: string | null;
  verdict?: EvidenceVerdict | null;
  remediationStatus?: EvidenceRemediationStatus | null;
  remediationStatusDetails?: string | null;
  roles?: string[];
  detailedRoles?: string[];
  tags?: string[];
}

export interface UserEvidence extends AlertEvidenceBase {
  '@odata.type': '#microsoft.graph.security.userEvidence';
  userAccount?: UserAccount;
}

export interface IpEvidence extends AlertEvidenceBase {
  '@odata.type': '#microsoft.graph.security.ipEvidence';
  ipAddress?: string | null;
  countryLetterCode?: string | null;
}

export interface DeviceEvidence extends AlertEvidenceBase {
  '@odata.type': '#microsoft.graph.security.deviceEvidence';
  deviceDnsName?: string | null;
  osPlatform?: string | null;
  osBuild?: number | null;
  healthStatus?: string | null;
  riskScore?: string | null;
  mdeDeviceId?: string | null;
}

export interface FileEvidence extends AlertEvidenceBase {
  '@odata.type': '#microsoft.graph.security.fileEvidence';
  fileDetails?: FileDetails;
}

export interface OAuthApplicationEvidence extends AlertEvidenceBase {
  '@odata.type': '#microsoft.graph.security.oauthApplicationEvidence';
  appId?: string | null;
  displayName?: string | null;
  objectId?: string | null;
  publisher?: string | null;
}

export interface CloudApplicationEvidence extends AlertEvidenceBase {
  '@odata.type': '#microsoft.graph.security.cloudApplicationEvidence';
  appId?: number | null;
  displayName?: string | null;
  instanceName?: string | null;
  instanceId?: number | null;
  saasAppId?: number | null;
}

export interface MailboxEvidence extends AlertEvidenceBase {
  '@odata.type': '#microsoft.graph.security.mailboxEvidence';
  primaryAddress?: string | null;
  displayName?: string | null;
  userAccount?: UserAccount;
}

/**
 * Graph returns many more evidence subtypes than these. The trailing member
 * keeps `switch` statements honest: narrow on '@odata.type' and handle the
 * default case rather than assuming the union is closed.
 */
export type AlertEvidence =
  | UserEvidence
  | IpEvidence
  | DeviceEvidence
  | FileEvidence
  | OAuthApplicationEvidence
  | CloudApplicationEvidence
  | MailboxEvidence
  | AlertEvidenceBase;

// ---------------------------------------------------------------------------
// Alert and incident
// ---------------------------------------------------------------------------

export interface AlertComment {
  comment?: string | null;
  createdByDisplayName?: string | null;
  createdDateTime?: string | null;
}

/** GET /security/alerts_v2 */
export interface SecurityAlert {
  '@odata.type'?: '#microsoft.graph.security.alert';
  id: string;
  tenantId?: string | null;
  providerAlertId?: string | null;
  incidentId?: string | null;
  title?: string | null;
  description?: string | null;
  severity: AlertSeverity;
  status: AlertStatus;
  classification?: AlertClassification | null;
  determination?: AlertDetermination | null;
  serviceSource?: ServiceSource | null;
  detectionSource?: string | null;
  detectorId?: string | null;
  productName?: string | null;
  /** @deprecated Graph marks this deprecated. Use `categories`. */
  category?: string | null;
  categories?: string[];
  mitreTechniques?: string[];
  actorDisplayName?: string | null;
  threatDisplayName?: string | null;
  threatFamilyName?: string | null;
  assignedTo?: string | null;
  alertWebUrl?: string | null;
  incidentWebUrl?: string | null;
  createdDateTime?: string | null;
  firstActivityDateTime?: string | null;
  lastActivityDateTime?: string | null;
  lastUpdateDateTime?: string | null;
  resolvedDateTime?: string | null;
  investigationState?: InvestigationState | null;
  recommendedActions?: string | null;
  systemTags?: string[];
  comments?: AlertComment[];
  /** Free-form, product-specific. Untrusted text - see the note on SecurityIncident. */
  additionalData?: Record<string, unknown>;
  customDetails?: Record<string, unknown>;
  evidence?: AlertEvidence[];
}

/**
 * GET /security/incidents
 *
 * `alerts` is only present when you ask for it with `$expand=alerts`. That is
 * why it is optional here: if you forget the $expand, this type makes you
 * handle `undefined` rather than throwing at runtime.
 *
 * SECURITY NOTE. `displayName`, `description`, `summary`, `comments`,
 * `customTags` and everything under `additionalData` are attacker-influenced.
 * They are populated from telemetry, from mail subjects, from file names, from
 * whatever a user typed. Treat every one of them as untrusted data when you
 * build a prompt. Fixture incident 48176 carries a live example.
 */
export interface SecurityIncident {
  '@odata.type'?: '#microsoft.graph.security.incident';
  id: string;
  tenantId?: string | null;
  displayName?: string | null;
  description?: string | null;
  incidentWebUrl?: string | null;
  redirectIncidentId?: string | null;
  severity: AlertSeverity;
  status: IncidentStatus;
  classification?: AlertClassification | null;
  determination?: IncidentDetermination | null;
  assignedTo?: string | null;
  createdDateTime?: string | null;
  lastUpdateDateTime?: string | null;
  lastModifiedBy?: string | null;
  resolvingComment?: string | null;
  summary?: string | null;
  /** 0-100, or null. */
  priorityScore?: number | null;
  customTags?: string[];
  systemTags?: string[];
  comments?: AlertComment[];
  /** Present only with `$expand=alerts`. */
  alerts?: SecurityAlert[];
}

// ---------------------------------------------------------------------------
// Advanced hunting
// ---------------------------------------------------------------------------

/**
 * POST /security/runHuntingQuery body.
 *
 * The property names are CASE-SENSITIVE and inconsistent: `Query` and
 * `Timespan` are capitalised, `workspaceId` is not. That is Graph's spelling,
 * not a typo here.
 */
export interface HuntingQueryRequest {
  /** KQL. Required. */
  Query: string;
  /** ISO 8601 duration or interval. Defaults to 30 days. e.g. 'P7D'. */
  Timespan?: string;
  /**
   * Target a specific Log Analytics workspace.
   *
   * Careful: if the workspace is not found or not accessible, Graph silently
   * falls back to the caller's primary workspace rather than failing. Always
   * assert on something in the result rather than trusting that you queried
   * the workspace you named.
   */
  workspaceId?: string;
}

export interface HuntingColumn {
  name: string;
  type: string;
}

export interface HuntingQueryResults {
  '@odata.context'?: string;
  schema: HuntingColumn[];
  /** Row objects keyed by column name. Casing can differ from `schema` - map by position if it matters. */
  results: Array<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Collections and errors
// ---------------------------------------------------------------------------

export interface GraphCollection<T> {
  '@odata.context'?: string;
  '@odata.count'?: number;
  '@odata.nextLink'?: string;
  value: T[];
}

export interface GraphErrorBody {
  error: {
    code: string;
    message: string;
    innerError?: Record<string, unknown>;
  };
}
