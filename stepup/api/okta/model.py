# from __future__ import annotations
#
# from datetime import datetime
# from enum import Enum
# from typing import Any, Dict, List, Optional, Set
#
# from aenum import MultiValueEnum
# from pydantic import BaseModel, Field, SecretStr, RootModel
#
#
# class Model(RootModel):
#     pass
#
#
# class AccessPolicy(RootModel):
#     pass
#
#
# class AccessPolicyConstraint(BaseModel):
#     methods: Optional[List[str]] = None
#     reauthenticateIn: Optional[str] = None
#     types: Optional[List[str]] = None
#
#
# class AccessPolicyRuleCustomCondition(BaseModel):
#     condition: Optional[str] = None
#
#
# class AcsEndpoint(BaseModel):
#     index: Optional[int] = None
#     url: Optional[str] = None
#
#
# class ActivateFactorRequest(BaseModel):
#     attestation: Optional[str] = None
#     clientData: Optional[str] = None
#     passCode: Optional[str] = None
#     registrationData: Optional[str] = None
#     stateToken: Optional[str] = None
#
#
# class AllowedForEnum(Enum):
#     recovery = "recovery"
#     sso = "sso"
#     any = "any"
#     none = "none"
#
#
# class Type(Enum):
#     APP_TYPE = "APP_TYPE"
#     APP = "APP"
#
#
# class AppAndInstanceConditionEvaluatorAppOrInstance(BaseModel):
#     id: Optional[str] = None
#     name: Optional[str] = None
#     type: Optional[Type] = None
#
#
# class AppAndInstancePolicyRuleCondition(BaseModel):
#     exclude: Optional[
#         List[AppAndInstanceConditionEvaluatorAppOrInstance]
#     ] = None
#     include: Optional[
#         List[AppAndInstanceConditionEvaluatorAppOrInstance]
#     ] = None
#
#
# class AppInstancePolicyRuleCondition(BaseModel):
#     exclude: Optional[List[str]] = None
#     include: Optional[List[str]] = None
#
#
# class AppLink(BaseModel):
#     appAssignmentId: Optional[str] = None
#     appInstanceId: Optional[str] = None
#     appName: Optional[str] = None
#     credentialsSetup: Optional[bool] = None
#     hidden: Optional[bool] = None
#     id: Optional[str] = None
#     label: Optional[str] = None
#     linkUrl: Optional[str] = None
#     logoUrl: Optional[str] = None
#     sortOrder: Optional[int] = None
#
#
# class AppUserPasswordCredential(BaseModel):
#     value: Optional[SecretStr] = None
#
#
# class Status(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#     DELETED = "DELETED"
#
#
# class ApplicationAccessibility(BaseModel):
#     errorRedirectUrl: Optional[str] = None
#     loginRedirectUrl: Optional[str] = None
#     selfService: Optional[bool] = None
#
#
# class ApplicationCredentialsScheme(Enum):
#     SHARED_USERNAME_AND_PASSWORD = "SHARED_USERNAME_AND_PASSWORD"
#     EXTERNAL_PASSWORD_SYNC = "EXTERNAL_PASSWORD_SYNC"
#     EDIT_USERNAME_AND_PASSWORD = "EDIT_USERNAME_AND_PASSWORD"
#     EDIT_PASSWORD_ONLY = "EDIT_PASSWORD_ONLY"
#     ADMIN_SETS_CREDENTIALS = "ADMIN_SETS_CREDENTIALS"
#
#
# class ApplicationCredentialsSigningUse(Enum):
#     sig = "sig"
#
#
# class ApplicationCredentialsUsernameTemplate(BaseModel):
#     pushStatus: Optional[str] = None
#     suffix: Optional[str] = None
#     template: Optional[str] = None
#     type: Optional[str] = None
#
#
# class ApplicationGroupAssignment(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     priority: Optional[int] = None
#     profile: Optional[Dict[str, Dict[str, Any]]] = None
#
#
# class ApplicationLicensing(BaseModel):
#     seatCount: Optional[int] = None
#
#
# class ApplicationSettingsApplication(RootModel):
#     pass
#
#
# class ApplicationSettingsNotes(BaseModel):
#     admin: Optional[str] = None
#     enduser: Optional[str] = None
#
#
# class ApplicationSettingsNotificationsVpnNetwork(BaseModel):
#     connection: Optional[str] = None
#     exclude: Optional[List[str]] = None
#     include: Optional[List[str]] = None
#
#
# class ApplicationSignOnMode(Enum):
#     BOOKMARK = "BOOKMARK"
#     BASIC_AUTH = "BASIC_AUTH"
#     BROWSER_PLUGIN = "BROWSER_PLUGIN"
#     SECURE_PASSWORD_STORE = "SECURE_PASSWORD_STORE"
#     AUTO_LOGIN = "AUTO_LOGIN"
#     WS_FEDERATION = "WS_FEDERATION"
#     SAML_2_0 = "SAML_2_0"
#     OPENID_CONNECT = "OPENID_CONNECT"
#     SAML_1_1 = "SAML_1_1"
#
#
# class ApplicationVisibilityHide(BaseModel):
#     iOS: Optional[bool] = None
#     web: Optional[bool] = None
#
#
# class AuthenticationProviderType(Enum):
#     ACTIVE_DIRECTORY = "ACTIVE_DIRECTORY"
#     FEDERATION = "FEDERATION"
#     LDAP = "LDAP"
#     OKTA = "OKTA"
#     SOCIAL = "SOCIAL"
#     IMPORT = "IMPORT"
#
#
# class AuthenticatorProviderConfigurationUserNamePlate(BaseModel):
#     template: Optional[str] = None
#
#
# class AuthenticatorStatus(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#
#
# class AuthenticatorType(Enum):
#     app = "app"
#     password = "password"
#     security_question = "security_question"
#     phone = "phone"
#     email = "email"
#     security_key = "security_key"
#     federated = "federated"
#
#
# class IssuerMode(Enum):
#     ORG_URL = "ORG_URL"
#     CUSTOM_URL = "CUSTOM_URL"
#     DYNAMIC = "DYNAMIC"
#
#
# class Status1(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#
#
# class AuthorizationServerCredentialsRotationMode(Enum):
#     AUTO = "AUTO"
#     MANUAL = "MANUAL"
#
#
# class AuthorizationServerCredentialsUse(Enum):
#     sig = "sig"
#
#
# class Type1(Enum):
#     RESOURCE_ACCESS = "RESOURCE_ACCESS"
#
#
# class AutoLoginApplicationSettingsSignOn(BaseModel):
#     loginUrl: Optional[str] = None
#     redirectUrl: Optional[str] = None
#
#
# class BasicApplicationSettingsApplication(BaseModel):
#     authURL: Optional[str] = None
#     url: Optional[str] = None
#
#
# class BookmarkApplicationSettingsApplication(BaseModel):
#     requestIntegration: Optional[bool] = None
#     url: Optional[str] = None
#
#
# class Brand(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     agreeToCustomPrivacyPolicy: Optional[bool] = None
#     customPrivacyPolicyUrl: Optional[str] = None
#     id: Optional[str] = None
#     removePoweredByOkta: Optional[bool] = None
#
#
# class CatalogApplicationStatus(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#
#
# class ChangeEnum(Enum):
#     KEEP_EXISTING = "KEEP_EXISTING"
#     CHANGE = "CHANGE"
#
#
# class ClientPolicyCondition(BaseModel):
#     include: Optional[List[str]] = None
#
#
# class ClientSecret(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     client_secret: Optional[str] = None
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     secret_hash: Optional[str] = None
#     status: Optional[Status1] = None
#
#
# class ClientSecretMetadata(BaseModel):
#     client_secret: Optional[str] = None
#
#
# class ContextPolicyRuleCondition(BaseModel):
#     expression: Optional[str] = None
#
#
# class CreateSessionRequest(BaseModel):
#     sessionToken: Optional[str] = None
#
#
# class Csr(BaseModel):
#     created: Optional[datetime] = None
#     csr: Optional[str] = None
#     id: Optional[str] = None
#     kty: Optional[str] = None
#
#
# class CsrMetadataSubject(BaseModel):
#     commonName: Optional[str] = None
#     countryName: Optional[str] = None
#     localityName: Optional[str] = None
#     organizationName: Optional[str] = None
#     organizationalUnitName: Optional[str] = None
#     stateOrProvinceName: Optional[str] = None
#
#
# class CsrMetadataSubjectAltNames(BaseModel):
#     dnsNames: Optional[List[str]] = None
#
#
# class DNSRecordType(Enum):
#     TXT = "TXT"
#     CNAME = "CNAME"
#
#
# class DeviceAccessPolicyRuleCondition(BaseModel):
#     managed: Optional[bool] = None
#     registered: Optional[bool] = None
#
#
# class TrustLevel(Enum):
#     ANY = "ANY"
#     TRUSTED = "TRUSTED"
#
#
# class SupportedMDMFramework(Enum):
#     AFW = "AFW"
#     SAFE = "SAFE"
#     NATIVE = "NATIVE"
#
#
# class Type2(Enum):
#     IOS = "IOS"
#     ANDROID = "ANDROID"
#     OSX = "OSX"
#     WINDOWS = "WINDOWS"
#
#
# class DevicePolicyRuleConditionPlatform(BaseModel):
#     supportedMDMFrameworks: Optional[List[SupportedMDMFramework]] = None
#     types: Optional[List[Type2]] = None
#
#
# class DomainCertificateMetadata(BaseModel):
#     expiration: Optional[str] = None
#     fingerprint: Optional[str] = None
#     subject: Optional[str] = None
#
#
# class DomainCertificateSourceType(Enum):
#     MANUAL = "MANUAL"
#     OKTA_MANAGED = "OKTA_MANAGED"
#
#
# class DomainCertificateType(Enum):
#     PEM = "PEM"
#
#
# class DomainValidationStatus(Enum):
#     NOT_STARTED = "NOT_STARTED"
#     IN_PROGRESS = "IN_PROGRESS"
#     VERIFIED = "VERIFIED"
#     FAILED_TO_VERIFY = "FAILED_TO_VERIFY"
#     DOMAIN_TAKEN = "DOMAIN_TAKEN"
#     COMPLETED = "COMPLETED"
#
#
# class Duration(BaseModel):
#     number: Optional[int] = None
#     unit: Optional[str] = None
#
#
# class EmailTemplate(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     name: Optional[str] = None
#
#
# class EmailTemplateContent(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     body: Optional[str] = None
#     fromAddress: Optional[str] = None
#     fromName: Optional[str] = None
#     subject: Optional[str] = None
#
#
# class EmailTemplateCustomization(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     body: Optional[str] = None
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     isDefault: Optional[bool] = None
#     language: Optional[str] = Field(
#         None, description="unique under each email template"
#     )
#     lastUpdated: Optional[datetime] = None
#     subject: Optional[str] = None
#
#
# class EmailTemplateCustomizationRequest(BaseModel):
#     body: Optional[str] = None
#     isDefault: Optional[bool] = None
#     language: Optional[str] = Field(
#         None, description="unique under each email template"
#     )
#     subject: Optional[str] = None
#
#
# class EmailTemplateTestRequest(BaseModel):
#     customizationId: Optional[str] = None
#
#
# class EmailTemplateTouchPointVariant(Enum):
#     OKTA_DEFAULT = "OKTA_DEFAULT"
#     FULL_THEME = "FULL_THEME"
#
#
# class EmailUserFactorProfile(BaseModel):
#     email: Optional[str] = None
#
#
# class EnabledStatus(Enum):
#     ENABLED = "ENABLED"
#     DISABLED = "DISABLED"
#
#
# class EndUserDashboardTouchPointVariant(Enum):
#     OKTA_DEFAULT = "OKTA_DEFAULT"
#     WHITE_LOGO_BACKGROUND = "WHITE_LOGO_BACKGROUND"
#     FULL_THEME = "FULL_THEME"
#     LOGO_ON_FULL_WHITE_BACKGROUND = "LOGO_ON_FULL_WHITE_BACKGROUND"
#
#
# class ErrorPageTouchPointVariant(Enum):
#     OKTA_DEFAULT = "OKTA_DEFAULT"
#     BACKGROUND_SECONDARY_COLOR = "BACKGROUND_SECONDARY_COLOR"
#     BACKGROUND_IMAGE = "BACKGROUND_IMAGE"
#
#
# class VerificationStatus(Enum):
#     UNVERIFIED = "UNVERIFIED"
#     VERIFIED = "VERIFIED"
#
#
# class Type3(Enum):
#     HTTP = "HTTP"
#
#
# class EventHookChannelConfigAuthSchemeType(Enum):
#     HEADER = "HEADER"
#
#
# class EventHookChannelConfigHeader(BaseModel):
#     key: Optional[str] = None
#     value: Optional[str] = None
#
#
# class Type4(Enum):
#     EVENT_TYPE = "EVENT_TYPE"
#     FLOW_EVENT = "FLOW_EVENT"
#
#
# class EventSubscriptions(BaseModel):
#     items: Optional[List[str]] = None
#     type: Optional[Type4] = None
#
#
# class FactorProvider(Enum):
#     OKTA = "OKTA"
#     RSA = "RSA"
#     FIDO = "FIDO"
#     GOOGLE = "GOOGLE"
#     SYMANTEC = "SYMANTEC"
#     DUO = "DUO"
#     YUBICO = "YUBICO"
#     CUSTOM = "CUSTOM"
#     APPLE = "APPLE"
#
#
# class FactorResultType(Enum):
#     SUCCESS = "SUCCESS"
#     CHALLENGE = "CHALLENGE"
#     WAITING = "WAITING"
#     FAILED = "FAILED"
#     REJECTED = "REJECTED"
#     TIMEOUT = "TIMEOUT"
#     TIME_WINDOW_EXCEEDED = "TIME_WINDOW_EXCEEDED"
#     PASSCODE_REPLAYED = "PASSCODE_REPLAYED"
#     ERROR = "ERROR"
#     CANCELLED = "CANCELLED"
#
#
# class FactorStatus(Enum):
#     PENDING_ACTIVATION = "PENDING_ACTIVATION"
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#     NOT_SETUP = "NOT_SETUP"
#     ENROLLED = "ENROLLED"
#     DISABLED = "DISABLED"
#     EXPIRED = "EXPIRED"
#
#
# class FactorType(str, MultiValueEnum):
#     """
#     An enumeration class for FactorType.
#     """
#
#     CALL = "call", "CALL"
#     EMAIL = "email", "EMAIL"
#     HOTP = "hotp", "HOTP"
#     PUSH = "push", "PUSH"
#     QUESTION = "question", "QUESTION"
#     SMS = "sms", "SMS"
#     TOKEN_HARDWARE = "token:hardware", "TOKEN:HARDWARE"
#     TOKEN_HOTP = "token:hotp", "TOKEN:HOTP"
#     TOKEN_SOFTWARE_TOTP = "token:software:totp", "TOKEN:SOFTWARE:TOTP"
#     TOKEN = "token", "TOKEN"
#     U_2_F = "u2f", "U2F"
#     WEB = "web", "WEB"
#     WEBAUTHN = "webauthn", "WEBAUTHN"
#     SIGNED_NONCE = "signed_nonce", "SIGNED_NONCE"
#
#
# class FeatureStageState(Enum):
#     OPEN = "OPEN"
#     CLOSED = "CLOSED"
#
#
# class FeatureStageValue(Enum):
#     EA = "EA"
#     BETA = "BETA"
#
#
# class FeatureType(Enum):
#     self_service = "self-service"
#
#
# class FipsEnum(Enum):
#     REQUIRED = "REQUIRED"
#     OPTIONAL = "OPTIONAL"
#
#
# class ForgotPasswordResponse(BaseModel):
#     resetPasswordUrl: Optional[str] = None
#
#
# class GrantTypePolicyRuleCondition(BaseModel):
#     include: Optional[List[str]] = None
#
#
# class GroupCondition(BaseModel):
#     exclude: Optional[List[str]] = None
#     include: Optional[List[str]] = None
#
#
# class GroupPolicyRuleCondition(BaseModel):
#     exclude: Optional[List[str]] = None
#     include: Optional[List[str]] = None
#
#
# class GroupProfile(BaseModel):
#     description: Optional[str] = None
#     name: Optional[str] = None
#
#
# class GroupRuleExpression(BaseModel):
#     type: Optional[str] = None
#     value: Optional[str] = None
#
#
# class GroupRuleGroupAssignment(BaseModel):
#     groupIds: Optional[List[str]] = None
#
#
# class GroupRuleGroupCondition(BaseModel):
#     exclude: Optional[List[str]] = None
#     include: Optional[List[str]] = None
#
#
# class GroupRuleStatus(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#     INVALID = "INVALID"
#
#
# class GroupRuleUserCondition(BaseModel):
#     exclude: Optional[List[str]] = None
#     include: Optional[List[str]] = None
#
#
# class GroupType(Enum):
#     OKTA_GROUP = "OKTA_GROUP"
#     APP_GROUP = "APP_GROUP"
#     BUILT_IN = "BUILT_IN"
#
#
# class HardwareUserFactorProfile(BaseModel):
#     credentialId: Optional[str] = None
#
#
# class Type5(Enum):
#     SAML2 = "SAML2"
#     GOOGLE = "GOOGLE"
#     FACEBOOK = "FACEBOOK"
#     LINKEDIN = "LINKEDIN"
#     MICROSOFT = "MICROSOFT"
#     OIDC = "OIDC"
#     OKTA = "OKTA"
#     IWA = "IWA"
#     AgentlessDSSO = "AgentlessDSSO"
#     X509 = "X509"
#
#
# class IdentityProviderApplicationUser(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[str] = None
#     externalId: Optional[str] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[str] = None
#     profile: Optional[Dict[str, Dict[str, Any]]] = None
#
#
# class IdentityProviderCredentialsClient(BaseModel):
#     client_id: Optional[str] = None
#     client_secret: Optional[str] = None
#
#
# class IdentityProviderCredentialsSigning(BaseModel):
#     kid: Optional[str] = None
#     privateKey: Optional[str] = None
#     teamId: Optional[str] = None
#
#
# class Revocation(Enum):
#     CRL = "CRL"
#     DELTA_CRL = "DELTA_CRL"
#     OCSP = "OCSP"
#
#
# class IdentityProviderCredentialsTrust(BaseModel):
#     audience: Optional[str] = None
#     issuer: Optional[str] = None
#     kid: Optional[str] = None
#     revocation: Optional[Revocation] = None
#     revocationCacheLifetime: Optional[int] = None
#
#
# class Provider(Enum):
#     ANY = "ANY"
#     OKTA = "OKTA"
#     SPECIFIC_IDP = "SPECIFIC_IDP"
#
#
# class IdentityProviderPolicyRuleCondition(BaseModel):
#     idpIds: Optional[List[str]] = None
#     provider: Optional[Provider] = None
#
#
# class IdpPolicyRuleActionProvider(BaseModel):
#     id: Optional[str] = None
#     type: Optional[str] = None
#
#
# class IframeEmbedScopeAllowedApps(Enum):
#     OKTA_ENDUSER = "OKTA_ENDUSER"
#
#
# class ImageUploadResponse(BaseModel):
#     url: Optional[str] = None
#
#
# class InactivityPolicyRuleCondition(BaseModel):
#     number: Optional[int] = None
#     unit: Optional[str] = None
#
#
# class Type6(Enum):
#     HTTP = "HTTP"
#
#
# class InlineHookChannelConfigAuthScheme(BaseModel):
#     key: Optional[str] = None
#     type: Optional[str] = None
#     value: Optional[str] = None
#
#
# class InlineHookChannelConfigHeaders(BaseModel):
#     key: Optional[str] = None
#     value: Optional[str] = None
#
#
# class InlineHookPayload(BaseModel):
#     pass
#
#
# class InlineHookResponseCommandValue(BaseModel):
#     op: Optional[str] = None
#     path: Optional[str] = None
#     value: Optional[str] = None
#
#
# class InlineHookResponseCommands(BaseModel):
#     type: Optional[str] = None
#     value: Optional[List[InlineHookResponseCommandValue]] = None
#
#
# class InlineHookStatus(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#
#
# class InlineHookType(Enum):
#     com_okta_oauth2_tokens_transform = "com.okta.oauth2.tokens.transform"
#     com_okta_import_transform = "com.okta.import.transform"
#     com_okta_saml_tokens_transform = "com.okta.saml.tokens.transform"
#     com_okta_user_pre_registration = "com.okta.user.pre-registration"
#     com_okta_user_credential_password_import = (
#         "com.okta.user.credential.password.import"
#     )
#
#
# class JsonWebKey(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     alg: Optional[str] = None
#     created: Optional[datetime] = None
#     e: Optional[str] = None
#     expiresAt: Optional[datetime] = None
#     key_ops: Optional[List[str]] = None
#     kid: Optional[str] = None
#     kty: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     n: Optional[str] = None
#     status: Optional[str] = None
#     use: Optional[str] = None
#     x5c: Optional[List[str]] = None
#     x5t: Optional[str] = None
#     x5t_S256: Optional[str] = Field(None, alias="x5t#S256")
#     x5u: Optional[str] = None
#
#
# class Use(Enum):
#     sig = "sig"
#
#
# class JwkUse(BaseModel):
#     use: Optional[Use] = None
#
#
# class KnowledgeConstraint(RootModel):
#     pass
#
#
# class LifecycleCreateSettingObject(BaseModel):
#     status: Optional[EnabledStatus] = None
#
#
# class LifecycleDeactivateSettingObject(BaseModel):
#     status: Optional[EnabledStatus] = None
#
#
# class LifecycleExpirationPolicyRuleCondition(BaseModel):
#     lifecycleStatus: Optional[str] = None
#     number: Optional[int] = None
#     unit: Optional[str] = None
#
#
# class LinkedObjectDetailsType(Enum):
#     USER = "USER"
#
#
# class LogActor(BaseModel):
#     alternateId: Optional[str] = None
#     detail: Optional[Dict[str, Dict[str, Any]]] = None
#     displayName: Optional[str] = None
#     id: Optional[str] = None
#     type: Optional[str] = None
#
#
# class LogAuthenticationProvider(Enum):
#     OKTA_AUTHENTICATION_PROVIDER = "OKTA_AUTHENTICATION_PROVIDER"
#     ACTIVE_DIRECTORY = "ACTIVE_DIRECTORY"
#     LDAP = "LDAP"
#     FEDERATION = "FEDERATION"
#     SOCIAL = "SOCIAL"
#     FACTOR_PROVIDER = "FACTOR_PROVIDER"
#
#
# class LogCredentialProvider(Enum):
#     OKTA_AUTHENTICATION_PROVIDER = "OKTA_AUTHENTICATION_PROVIDER"
#     OKTA_CREDENTIAL_PROVIDER = "OKTA_CREDENTIAL_PROVIDER"
#     RSA = "RSA"
#     SYMANTEC = "SYMANTEC"
#     GOOGLE = "GOOGLE"
#     DUO = "DUO"
#     YUBIKEY = "YUBIKEY"
#     APPLE = "APPLE"
#
#
# class LogCredentialType(Enum):
#     OTP = "OTP"
#     SMS = "SMS"
#     PASSWORD = "PASSWORD"
#     ASSERTION = "ASSERTION"
#     IWA = "IWA"
#     EMAIL = "EMAIL"
#     OAUTH2 = "OAUTH2"
#     JWT = "JWT"
#
#
# class LogDebugContext(BaseModel):
#     debugData: Optional[Dict[str, Dict[str, Any]]] = None
#
#
# class LogGeolocation(BaseModel):
#     lat: Optional[float] = None
#     lon: Optional[float] = None
#
#
# class LogIssuer(BaseModel):
#     id: Optional[str] = None
#     type: Optional[str] = None
#
#
# class LogOutcome(BaseModel):
#     reason: Optional[str] = None
#     result: Optional[str] = None
#
#
# class LogSecurityContext(BaseModel):
#     asNumber: Optional[int] = None
#     asOrg: Optional[str] = None
#     domain: Optional[str] = None
#     isProxy: Optional[bool] = None
#     isp: Optional[str] = None
#
#
# class LogSeverity(Enum):
#     DEBUG = "DEBUG"
#     INFO = "INFO"
#     WARN = "WARN"
#     ERROR = "ERROR"
#
#
# class LogTarget(BaseModel):
#     alternateId: Optional[str] = None
#     detailEntry: Optional[Dict[str, Dict[str, Any]]] = None
#     displayName: Optional[str] = None
#     id: Optional[str] = None
#     type: Optional[str] = None
#
#
# class LogTransaction(BaseModel):
#     detail: Optional[Dict[str, Dict[str, Any]]] = None
#     id: Optional[str] = None
#     type: Optional[str] = None
#
#
# class LogUserAgent(BaseModel):
#     browser: Optional[str] = None
#     os: Optional[str] = None
#     rawUserAgent: Optional[str] = None
#
#
# class Enrollment(Enum):
#     OMM = "OMM"
#     ANY_OR_NONE = "ANY_OR_NONE"
#
#
# class MDMEnrollmentPolicyRuleCondition(BaseModel):
#     blockNonSafeAndroid: Optional[bool] = None
#     enrollment: Optional[Enrollment] = None
#
#
# class Constraints(BaseModel):
#     aaguidGroups: Optional[List[str]] = None
#
#
# class MultifactorEnrollmentPolicyAuthenticatorStatus(Enum):
#     NOT_ALLOWED = "NOT_ALLOWED"
#     OPTIONAL = "OPTIONAL"
#     REQUIRED = "REQUIRED"
#
#
# class MultifactorEnrollmentPolicyAuthenticatorType(Enum):
#     custom_app = "custom_app"
#     custom_otp = "custom_otp"
#     duo = "duo"
#     external_idp = "external_idp"
#     google_otp = "google_otp"
#     okta_email = "okta_email"
#     okta_password = "okta_password"
#     okta_verify = "okta_verify"
#     onprem_mfa = "onprem_mfa"
#     phone_number = "phone_number"
#     rsa_token = "rsa_token"
#     security_question = "security_question"
#     symantec_vip = "symantec_vip"
#     webauthn = "webauthn"
#     yubikey_token = "yubikey_token"
#
#
# class MultifactorEnrollmentPolicySettingsType(Enum):
#     AUTHENTICATORS = "AUTHENTICATORS"
#
#
# class NetworkZoneAddressType(Enum):
#     CIDR = "CIDR"
#     RANGE = "RANGE"
#
#
# class NetworkZoneLocation(BaseModel):
#     country: Optional[str] = None
#     region: Optional[str] = None
#
#
# class NetworkZoneStatus(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#
#
# class NetworkZoneType(Enum):
#     IP = "IP"
#     DYNAMIC = "DYNAMIC"
#
#
# class NetworkZoneUsage(Enum):
#     POLICY = "POLICY"
#     BLOCKLIST = "BLOCKLIST"
#
#
# class NotificationType(Enum):
#     CONNECTOR_AGENT = "CONNECTOR_AGENT"
#     USER_LOCKED_OUT = "USER_LOCKED_OUT"
#     APP_IMPORT = "APP_IMPORT"
#     LDAP_AGENT = "LDAP_AGENT"
#     AD_AGENT = "AD_AGENT"
#     OKTA_ANNOUNCEMENT = "OKTA_ANNOUNCEMENT"
#     OKTA_ISSUE = "OKTA_ISSUE"
#     OKTA_UPDATE = "OKTA_UPDATE"
#     IWA_AGENT = "IWA_AGENT"
#     USER_DEPROVISION = "USER_DEPROVISION"
#     REPORT_SUSPICIOUS_ACTIVITY = "REPORT_SUSPICIOUS_ACTIVITY"
#     RATELIMIT_NOTIFICATION = "RATELIMIT_NOTIFICATION"
#
#
# class OAuth2Actor(BaseModel):
#     id: Optional[str] = None
#     type: Optional[str] = None
#
#
# class ClaimType(Enum):
#     IDENTITY = "IDENTITY"
#     RESOURCE = "RESOURCE"
#
#
# class GroupFilterType(Enum):
#     STARTS_WITH = "STARTS_WITH"
#     EQUALS = "EQUALS"
#     CONTAINS = "CONTAINS"
#     REGEX = "REGEX"
#
#
# class ValueType(Enum):
#     EXPRESSION = "EXPRESSION"
#     GROUPS = "GROUPS"
#     SYSTEM = "SYSTEM"
#
#
# class OAuth2ClaimConditions(BaseModel):
#     scopes: Optional[List[str]] = None
#
#
# class OAuth2Client(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     client_id: Optional[str] = None
#     client_name: Optional[str] = None
#     client_uri: Optional[str] = None
#     logo_uri: Optional[str] = None
#
#
# class Status8(Enum):
#     ACTIVE = "ACTIVE"
#     REVOKED = "REVOKED"
#
#
# class OAuth2RefreshToken(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     clientId: Optional[str] = None
#     created: Optional[datetime] = None
#     createdBy: Optional[OAuth2Actor] = None
#     expiresAt: Optional[datetime] = None
#     id: Optional[str] = None
#     issuer: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     scopes: Optional[List[str]] = None
#     status: Optional[Status8] = None
#     userId: Optional[str] = None
#
#
# class Consent(Enum):
#     REQUIRED = "REQUIRED"
#     IMPLICIT = "IMPLICIT"
#     ADMIN = "ADMIN"
#
#
# class MetadataPublish(Enum):
#     ALL_CLIENTS = "ALL_CLIENTS"
#     NO_CLIENTS = "NO_CLIENTS"
#
#
# class OAuth2Scope(BaseModel):
#     consent: Optional[Consent] = None
#     default: Optional[bool] = None
#     description: Optional[str] = None
#     displayName: Optional[str] = None
#     id: Optional[str] = None
#     metadataPublish: Optional[MetadataPublish] = None
#     name: Optional[str] = None
#     system: Optional[bool] = None
#
#
# class OAuth2ScopeConsentGrantSource(Enum):
#     END_USER = "END_USER"
#     ADMIN = "ADMIN"
#
#
# class OAuth2ScopeConsentGrantStatus(Enum):
#     ACTIVE = "ACTIVE"
#     REVOKED = "REVOKED"
#
#
# class OAuth2ScopesMediationPolicyRuleCondition(BaseModel):
#     include: Optional[List[str]] = None
#
#
# class OAuth2Token(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     clientId: Optional[str] = None
#     created: Optional[datetime] = None
#     expiresAt: Optional[datetime] = None
#     id: Optional[str] = None
#     issuer: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     scopes: Optional[List[str]] = None
#     status: Optional[Status8] = None
#     userId: Optional[str] = None
#
#
# class OAuthAuthorizationPolicy(RootModel):
#     pass
#
#
# class OAuthEndpointAuthenticationMethod(Enum):
#     none = "none"
#     client_secret_post = "client_secret_post"
#     client_secret_basic = "client_secret_basic"
#     client_secret_jwt = "client_secret_jwt"
#     private_key_jwt = "private_key_jwt"
#
#
# class OAuthGrantType(Enum):
#     authorization_code = "authorization_code"
#     implicit = "implicit"
#     password = "password"
#     refresh_token = "refresh_token"
#     client_credentials = "client_credentials"
#     saml2_bearer = "saml2_bearer"
#     device_code = "device_code"
#     token_exchange = "token_exchange"
#     interaction_code = "interaction_code"
#
#
# class OAuthResponseType(Enum):
#     code = "code"
#     token = "token"
#     id_token = "id_token"
#
#
# class Access(Enum):
#     ALLOW = "ALLOW"
#     DENY = "DENY"
#
#
# class FactorPromptMode(Enum):
#     ALWAYS = "ALWAYS"
#     DEVICE = "DEVICE"
#     SESSION = "SESSION"
#
#
# class OktaSignOnPolicyRuleSignonSessionActions(BaseModel):
#     maxSessionIdleMinutes: Optional[int] = 120
#     maxSessionLifetimeMinutes: Optional[int] = 0
#     usePersistentCookie: Optional[bool] = False
#
#
# class OpenIdConnectApplicationConsentMethod(Enum):
#     REQUIRED = "REQUIRED"
#     TRUSTED = "TRUSTED"
#
#
# class OpenIdConnectApplicationIdpInitiatedLogin(BaseModel):
#     default_scope: Optional[List[str]] = None
#     mode: Optional[str] = None
#
#
# class OpenIdConnectApplicationIssuerMode(Enum):
#     CUSTOM_URL = "CUSTOM_URL"
#     ORG_URL = "ORG_URL"
#     DYNAMIC = "DYNAMIC"
#
#
# class OpenIdConnectApplicationSettingsClientKeys(BaseModel):
#     keys: Optional[List[JsonWebKey]] = None
#
#
# class OpenIdConnectApplicationType(Enum):
#     web = "web"
#     native = "native"
#     browser = "browser"
#     service = "service"
#
#
# class OpenIdConnectRefreshTokenRotationType(Enum):
#     rotate = "rotate"
#     static = "static"
#
#
# class Org2OrgApplicationSettingsApp(BaseModel):
#     acsUrl: Optional[str] = None
#     audRestriction: Optional[str] = None
#     baseUrl: Optional[str] = None
#
#
# class OrgContactType(Enum):
#     BILLING = "BILLING"
#     TECHNICAL = "TECHNICAL"
#
#
# class OrgContactTypeObj(BaseModel):
#     field_links: Optional[Any] = Field(None, alias="_links")
#     contactType: Optional[OrgContactType] = None
#
#
# class OrgContactUser(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     userId: Optional[str] = None
#
#
# class OrgOktaCommunicationSetting(BaseModel):
#     field_links: Optional[Any] = Field(None, alias="_links")
#     optOutEmailUsers: Optional[bool] = None
#
#
# class OrgOktaSupportSetting(Enum):
#     DISABLED = "DISABLED"
#     ENABLED = "ENABLED"
#
#
# class OrgOktaSupportSettingsObj(BaseModel):
#     field_links: Optional[Any] = Field(None, alias="_links")
#     expiration: Optional[datetime] = None
#     support: Optional[OrgOktaSupportSetting] = None
#
#
# class OrgPreferences(BaseModel):
#     field_links: Optional[Any] = Field(None, alias="_links")
#     showEndUserFooter: Optional[bool] = None
#
#
# class OrgSetting(BaseModel):
#     field_links: Optional[Any] = Field(None, alias="_links")
#     address1: Optional[str] = None
#     address2: Optional[str] = None
#     city: Optional[str] = None
#     companyName: Optional[str] = None
#     country: Optional[str] = None
#     created: Optional[datetime] = None
#     endUserSupportHelpURL: Optional[str] = None
#     expiresAt: Optional[datetime] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     phoneNumber: Optional[str] = None
#     postalCode: Optional[str] = None
#     state: Optional[str] = None
#     status: Optional[str] = None
#     subdomain: Optional[str] = None
#     supportPhoneNumber: Optional[str] = None
#     website: Optional[str] = None
#
#
# class PasswordCredentialHashAlgorithm(Enum):
#     BCRYPT = "BCRYPT"
#     SHA_512 = "SHA-512"
#     SHA_256 = "SHA-256"
#     SHA_1 = "SHA-1"
#     MD5 = "MD5"
#
#
# class PasswordCredentialHook(BaseModel):
#     type: Optional[str] = None
#
#
# class PasswordDictionaryCommon(BaseModel):
#     exclude: Optional[bool] = False
#
#
# class PasswordExpirationPolicyRuleCondition(BaseModel):
#     number: Optional[int] = None
#     unit: Optional[str] = None
#
#
# class Provider1(Enum):
#     ACTIVE_DIRECTORY = "ACTIVE_DIRECTORY"
#     ANY = "ANY"
#     LDAP = "LDAP"
#     OKTA = "OKTA"
#
#
# class PasswordPolicyAuthenticationProviderCondition(BaseModel):
#     include: Optional[List[str]] = None
#     provider: Optional[Provider1] = None
#
#
# class PasswordPolicyDelegationSettingsOptions(BaseModel):
#     skipUnlock: Optional[bool] = None
#
#
# class PasswordPolicyPasswordSettingsAge(BaseModel):
#     expireWarnDays: Optional[int] = 0
#     historyCount: Optional[int] = 0
#     maxAgeDays: Optional[int] = 0
#     minAgeMinutes: Optional[int] = 0
#
#
# class PasswordPolicyPasswordSettingsLockout(BaseModel):
#     autoUnlockMinutes: Optional[int] = None
#     maxAttempts: Optional[int] = None
#     showLockoutFailures: Optional[bool] = None
#     userLockoutNotificationChannels: Optional[List[str]] = None
#
#
# class Status10(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#
#
# class PasswordPolicyRecoveryEmailRecoveryToken(BaseModel):
#     tokenLifetimeMinutes: Optional[int] = 10080
#
#
# class PasswordPolicyRecoveryFactorSettings(BaseModel):
#     status: Optional[Status10] = "INACTIVE"
#
#
# class PasswordPolicyRecoveryQuestionComplexity(BaseModel):
#     minLength: Optional[int] = None
#
#
# class PasswordPolicyRecoveryQuestionProperties(BaseModel):
#     complexity: Optional[PasswordPolicyRecoveryQuestionComplexity] = None
#
#
# class PasswordPolicyRuleAction(BaseModel):
#     access: Optional[Access] = None
#
#
# class PasswordPolicyRuleActions(BaseModel):
#     passwordChange: Optional[PasswordPolicyRuleAction] = None
#     selfServicePasswordReset: Optional[PasswordPolicyRuleAction] = None
#     selfServiceUnlock: Optional[PasswordPolicyRuleAction] = None
#
#
# class Type7(Enum):
#     DESKTOP = "DESKTOP"
#     MOBILE = "MOBILE"
#     OTHER = "OTHER"
#     ANY = "ANY"
#
#
# class Type8(Enum):
#     ANDROID = "ANDROID"
#     IOS = "IOS"
#     WINDOWS = "WINDOWS"
#     OSX = "OSX"
#     OTHER = "OTHER"
#     ANY = "ANY"
#
#
# class MatchType(Enum):
#     EXPRESSION = "EXPRESSION"
#     SEMVER = "SEMVER"
#
#
# class PlatformConditionEvaluatorPlatformOperatingSystemVersion(BaseModel):
#     matchType: Optional[MatchType] = None
#     value: Optional[str] = None
#
#
# class Action(Enum):
#     AUTO = "AUTO"
#     DISABLED = "DISABLED"
#
#
# class PolicyAccountLinkFilterGroups(BaseModel):
#     include: Optional[List[str]] = None
#
#
# class Connection(Enum):
#     ANYWHERE = "ANYWHERE"
#     ZONE = "ZONE"
#
#
# class PolicyNetworkCondition(BaseModel):
#     connection: Optional[Connection] = None
#     exclude: Optional[List[str]] = None
#     include: Optional[List[str]] = None
#
#
# class Type9(Enum):
#     SIGN_ON = "SIGN_ON"
#     PASSWORD = "PASSWORD"
#
#
# class PolicyRuleActionsEnrollSelf(Enum):
#     CHALLENGE = "CHALLENGE"
#     LOGIN = "LOGIN"
#     NEVER = "NEVER"
#
#
# class AuthType(Enum):
#     ANY = "ANY"
#     RADIUS = "RADIUS"
#
#
# class PolicyRuleAuthContextCondition(BaseModel):
#     authType: Optional[AuthType] = None
#
#
# class PolicySubjectMatchType(Enum):
#     USERNAME = "USERNAME"
#     EMAIL = "EMAIL"
#     USERNAME_OR_EMAIL = "USERNAME_OR_EMAIL"
#     CUSTOM_ATTRIBUTE = "CUSTOM_ATTRIBUTE"
#
#
# class PolicyType(Enum):
#     OAUTH_AUTHORIZATION_POLICY = "OAUTH_AUTHORIZATION_POLICY"
#     OKTA_SIGN_ON = "OKTA_SIGN_ON"
#     PASSWORD = "PASSWORD"
#     IDP_DISCOVERY = "IDP_DISCOVERY"
#     PROFILE_ENROLLMENT = "PROFILE_ENROLLMENT"
#     ACCESS_POLICY = "ACCESS_POLICY"
#     MFA_ENROLL = "MFA_ENROLL"
#
#
# class PolicyUserNameTemplate(BaseModel):
#     template: Optional[str] = None
#
#
# class PossessionConstraint(BaseModel):
#     deviceBound: Optional[str] = None
#     hardwareProtection: Optional[str] = None
#     phishingResistant: Optional[str] = None
#     userPresence: Optional[str] = None
#
#
# class PreRegistrationInlineHook(BaseModel):
#     inlineHookId: Optional[str] = None
#
#
# class ProfileEnrollmentPolicy(RootModel):
#     pass
#
#
# class ProfileEnrollmentPolicyRuleActivationRequirement(BaseModel):
#     emailVerification: Optional[bool] = None
#
#
# class ProfileEnrollmentPolicyRuleProfileAttribute(BaseModel):
#     label: Optional[str] = None
#     name: Optional[str] = None
#     required: Optional[bool] = None
#
#
# class ProfileMappingPropertyPushStatus(BaseModel):
#     pass
#
#
# class ProfileMappingSource(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     id: Optional[str] = None
#     name: Optional[str] = None
#     type: Optional[str] = None
#
#
# class ProfileSettingObject(BaseModel):
#     status: Optional[EnabledStatus] = None
#
#
# class Type10(Enum):
#     SAML2 = "SAML2"
#     OIDC = "OIDC"
#     OAUTH2 = "OAUTH2"
#     MTLS = "MTLS"
#
#
# class Scope(Enum):
#     RESPONSE = "RESPONSE"
#     TOKEN = "TOKEN"
#     ANY = "ANY"
#     REQUEST = "REQUEST"
#     NONE = "NONE"
#
#
# class ProtocolAlgorithmTypeSignature(BaseModel):
#     algorithm: Optional[str] = None
#     scope: Optional[Scope] = None
#
#
# class Binding(Enum):
#     HTTP_POST = "HTTP-POST"
#     HTTP_REDIRECT = "HTTP-REDIRECT"
#
#
# class Type11(Enum):
#     INSTANCE = "INSTANCE"
#     ORG = "ORG"
#
#
# class ProtocolEndpoint(BaseModel):
#     binding: Optional[Binding] = None
#     destination: Optional[str] = None
#     type: Optional[Type11] = None
#     url: Optional[str] = None
#
#
# class ProtocolEndpoints(BaseModel):
#     acs: Optional[ProtocolEndpoint] = None
#     authorization: Optional[ProtocolEndpoint] = None
#     jwks: Optional[ProtocolEndpoint] = None
#     metadata: Optional[ProtocolEndpoint] = None
#     slo: Optional[ProtocolEndpoint] = None
#     sso: Optional[ProtocolEndpoint] = None
#     token: Optional[ProtocolEndpoint] = None
#     userInfo: Optional[ProtocolEndpoint] = None
#
#
# class ProtocolRelayStateFormat(Enum):
#     OPAQUE = "OPAQUE"
#     FROM_URL = "FROM_URL"
#
#
# class ProtocolSettings(BaseModel):
#     nameFormat: Optional[str] = None
#
#
# class Action1(Enum):
#     AUTO = "AUTO"
#     CALLOUT = "CALLOUT"
#     DISABLED = "DISABLED"
#
#
# class ProvisioningConnectionAuthScheme(Enum):
#     TOKEN = "TOKEN"
#     UNKNOWN = "UNKNOWN"
#
#
# class ProvisioningConnectionProfile(BaseModel):
#     authScheme: Optional[ProvisioningConnectionAuthScheme] = None
#     token: Optional[str] = None
#
#
# class ProvisioningConnectionRequest(BaseModel):
#     profile: Optional[ProvisioningConnectionProfile] = None
#
#
# class ProvisioningConnectionStatus(Enum):
#     DISABLED = "DISABLED"
#     ENABLED = "ENABLED"
#     UNKNOWN = "UNKNOWN"
#
#
# class Action2(Enum):
#     NONE = "NONE"
#     REACTIVATE = "REACTIVATE"
#
#
# class ProvisioningDeprovisionedCondition(BaseModel):
#     action: Optional[Action2] = None
#
#
# class Action3(Enum):
#     NONE = "NONE"
#     APPEND = "APPEND"
#     SYNC = "SYNC"
#     ASSIGN = "ASSIGN"
#
#
# class ProvisioningGroups(BaseModel):
#     action: Optional[Action3] = None
#     assignments: Optional[List[str]] = None
#     filter: Optional[List[str]] = None
#     sourceAttributeName: Optional[str] = None
#
#
# class Action4(Enum):
#     NONE = "NONE"
#     UNSUSPEND = "UNSUSPEND"
#
#
# class ProvisioningSuspendedCondition(BaseModel):
#     action: Optional[Action4] = None
#
#
# class PushUserFactorProfile(BaseModel):
#     credentialId: Optional[str] = None
#     deviceToken: Optional[str] = None
#     deviceType: Optional[str] = None
#     name: Optional[str] = None
#     platform: Optional[str] = None
#     version: Optional[str] = None
#
#
# class RecoveryQuestionCredential(BaseModel):
#     answer: Optional[str] = None
#     question: Optional[str] = None
#
#
# class RequiredEnum(Enum):
#     ALWAYS = "ALWAYS"
#     HIGH_RISK_ONLY = "HIGH_RISK_ONLY"
#     NEVER = "NEVER"
#
#
# class ResetPasswordToken(BaseModel):
#     resetPasswordUrl: Optional[str] = None
#
#
# class ResponseLinks(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#
#
# class RiskPolicyRuleCondition(BaseModel):
#     behaviors: Optional[Set[str]] = Field(None)
#
#
# class RiskScorePolicyRuleCondition(BaseModel):
#     level: Optional[str] = None
#
#
# class RoleAssignmentType(Enum):
#     GROUP = "GROUP"
#     USER = "USER"
#
#
# class RoleStatus(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#
#
# class RoleType(Enum):
#     SUPER_ADMIN = "SUPER_ADMIN"
#     ORG_ADMIN = "ORG_ADMIN"
#     APP_ADMIN = "APP_ADMIN"
#     USER_ADMIN = "USER_ADMIN"
#     HELP_DESK_ADMIN = "HELP_DESK_ADMIN"
#     READ_ONLY_ADMIN = "READ_ONLY_ADMIN"
#     MOBILE_ADMIN = "MOBILE_ADMIN"
#     API_ACCESS_MANAGEMENT_ADMIN = "API_ACCESS_MANAGEMENT_ADMIN"
#     REPORT_ADMIN = "REPORT_ADMIN"
#     GROUP_MEMBERSHIP_ADMIN = "GROUP_MEMBERSHIP_ADMIN"
#     CUSTOM = "CUSTOM"
#
#
# class SamlAttributeStatement(BaseModel):
#     filterType: Optional[str] = None
#     filterValue: Optional[str] = None
#     name: Optional[str] = None
#     namespace: Optional[str] = None
#     type: Optional[str] = None
#     values: Optional[List[str]] = None
#
#
# class Status15(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#     PENDING = "PENDING"
#     DELETED = "DELETED"
#     EXPIRED_PASSWORD = "EXPIRED_PASSWORD"
#     ACTIVATING = "ACTIVATING"
#     SUSPENDED = "SUSPENDED"
#     DELETING = "DELETING"
#
#
# class ScheduledUserLifecycleAction(BaseModel):
#     status: Optional[Status15] = None
#
#
# class ScopeType(Enum):
#     CORS = "CORS"
#     REDIRECT = "REDIRECT"
#     IFRAME_EMBED = "IFRAME_EMBED"
#
#
# class SecurePasswordStoreApplicationSettingsApplication(BaseModel):
#     optionalField1: Optional[str] = None
#     optionalField1Value: Optional[str] = None
#     optionalField2: Optional[str] = None
#     optionalField2Value: Optional[str] = None
#     optionalField3: Optional[str] = None
#     optionalField3Value: Optional[str] = None
#     passwordField: Optional[str] = None
#     url: Optional[str] = None
#     usernameField: Optional[str] = None
#
#
# class SecurityQuestion(BaseModel):
#     answer: Optional[str] = None
#     question: Optional[str] = None
#     questionText: Optional[str] = None
#
#
# class SecurityQuestionUserFactorProfile(BaseModel):
#     answer: Optional[str] = None
#     question: Optional[str] = None
#     questionText: Optional[str] = None
#
#
# class SeedEnum(Enum):
#     OKTA = "OKTA"
#     RANDOM = "RANDOM"
#
#
# class SessionAuthenticationMethod(Enum):
#     pwd = "pwd"
#     swk = "swk"
#     hwk = "hwk"
#     otp = "otp"
#     sms = "sms"
#     tel = "tel"
#     geo = "geo"
#     fpt = "fpt"
#     kba = "kba"
#     mfa = "mfa"
#     mca = "mca"
#     sc = "sc"
#
#
# class SessionIdentityProviderType(Enum):
#     ACTIVE_DIRECTORY = "ACTIVE_DIRECTORY"
#     LDAP = "LDAP"
#     OKTA = "OKTA"
#     FEDERATION = "FEDERATION"
#     SOCIAL = "SOCIAL"
#
#
# class SessionStatus(Enum):
#     ACTIVE = "ACTIVE"
#     MFA_ENROLL = "MFA_ENROLL"
#     MFA_REQUIRED = "MFA_REQUIRED"
#
#
# class SignInPageTouchPointVariant(Enum):
#     OKTA_DEFAULT = "OKTA_DEFAULT"
#     BACKGROUND_SECONDARY_COLOR = "BACKGROUND_SECONDARY_COLOR"
#     BACKGROUND_IMAGE = "BACKGROUND_IMAGE"
#
#
# class SignOnInlineHook(BaseModel):
#     id: Optional[str] = None
#
#
# class SingleLogout(BaseModel):
#     enabled: Optional[bool] = None
#     issuer: Optional[str] = None
#     logoutUrl: Optional[str] = None
#
#
# class SmsTemplateTranslations(BaseModel):
#     pass
#
#
# class SmsTemplateType(Enum):
#     SMS_VERIFY_CODE = "SMS_VERIFY_CODE"
#
#
# class SmsUserFactorProfile(BaseModel):
#     phoneNumber: Optional[str] = None
#
#
# class SocialAuthToken(BaseModel):
#     expiresAt: Optional[datetime] = None
#     id: Optional[str] = None
#     scopes: Optional[List[str]] = None
#     token: Optional[str] = None
#     tokenAuthScheme: Optional[str] = None
#     tokenType: Optional[str] = None
#
#
# class SpCertificate(BaseModel):
#     x5c: Optional[List[str]] = None
#
#
# class SubscriptionStatus(Enum):
#     subscribed = "subscribed"
#     unsubscribed = "unsubscribed"
#
#
# class SwaApplicationSettingsApplication(BaseModel):
#     buttonField: Optional[str] = None
#     checkbox: Optional[str] = None
#     loginUrlRegex: Optional[str] = None
#     passwordField: Optional[str] = None
#     redirectUrl: Optional[str] = None
#     url: Optional[str] = None
#     usernameField: Optional[str] = None
#
#
# class SwaThreeFieldApplicationSettingsApplication(BaseModel):
#     buttonSelector: Optional[str] = None
#     extraFieldSelector: Optional[str] = None
#     extraFieldValue: Optional[str] = None
#     loginUrlRegex: Optional[str] = None
#     passwordSelector: Optional[str] = None
#     targetURL: Optional[str] = None
#     userNameSelector: Optional[str] = None
#
#
# class TempPassword(BaseModel):
#     tempPassword: Optional[str] = None
#
#
# class Theme(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     backgroundImage: Optional[str] = None
#     emailTemplateTouchPointVariant: Optional[
#         EmailTemplateTouchPointVariant
#     ] = None
#     endUserDashboardTouchPointVariant: Optional[
#         EndUserDashboardTouchPointVariant
#     ] = None
#     errorPageTouchPointVariant: Optional[ErrorPageTouchPointVariant] = None
#     primaryColorContrastHex: Optional[str] = None
#     primaryColorHex: Optional[str] = None
#     secondaryColorContrastHex: Optional[str] = None
#     secondaryColorHex: Optional[str] = None
#     signInPageTouchPointVariant: Optional[SignInPageTouchPointVariant] = None
#
#
# class ThemeResponse(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     backgroundImage: Optional[str] = None
#     emailTemplateTouchPointVariant: Optional[
#         EmailTemplateTouchPointVariant
#     ] = None
#     endUserDashboardTouchPointVariant: Optional[
#         EndUserDashboardTouchPointVariant
#     ] = None
#     errorPageTouchPointVariant: Optional[ErrorPageTouchPointVariant] = None
#     favicon: Optional[str] = None
#     id: Optional[str] = None
#     logo: Optional[str] = None
#     primaryColorContrastHex: Optional[str] = None
#     primaryColorHex: Optional[str] = None
#     secondaryColorContrastHex: Optional[str] = None
#     secondaryColorHex: Optional[str] = None
#     signInPageTouchPointVariant: Optional[SignInPageTouchPointVariant] = None
#
#
# class ThreatInsightConfiguration(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     action: Optional[str] = None
#     created: Optional[datetime] = None
#     excludeZones: Optional[List[str]] = None
#     lastUpdated: Optional[datetime] = None
#
#
# class TokenAuthorizationServerPolicyRuleActionInlineHook(BaseModel):
#     id: Optional[str] = None
#
#
# class TokenUserFactorProfile(BaseModel):
#     credentialId: Optional[str] = None
#
#
# class TotpUserFactorProfile(BaseModel):
#     credentialId: Optional[str] = None
#
#
# class U2fUserFactorProfile(BaseModel):
#     credentialId: Optional[str] = None
#
#
# class UserActivationToken(BaseModel):
#     activationToken: Optional[str] = None
#     activationUrl: Optional[str] = None
#
#
# class UserCondition(BaseModel):
#     exclude: Optional[List[str]] = None
#     include: Optional[List[str]] = None
#
#
# class UserIdString(BaseModel):
#     userId: Optional[str] = None
#
#
# class MatchType1(Enum):
#     SUFFIX = "SUFFIX"
#     EXPRESSION = "EXPRESSION"
#     STARTS_WITH = "STARTS_WITH"
#     EQUALS = "EQUALS"
#     CONTAINS = "CONTAINS"
#
#
# class UserIdentifierConditionEvaluatorPattern(BaseModel):
#     matchType: Optional[MatchType1] = None
#     value: Optional[str] = None
#
#
# class Type12(Enum):
#     IDENTIFIER = "IDENTIFIER"
#     ATTRIBUTE = "ATTRIBUTE"
#
#
# class UserIdentifierPolicyRuleCondition(BaseModel):
#     attribute: Optional[str] = None
#     patterns: Optional[List[UserIdentifierConditionEvaluatorPattern]] = None
#     type: Optional[Type12] = None
#
#
# class UserIdentityProviderLinkRequest(BaseModel):
#     externalId: Optional[str] = None
#
#
# class UserLifecycleAttributePolicyRuleCondition(BaseModel):
#     attributeName: Optional[str] = None
#     matchingValue: Optional[str] = None
#
#
# class UserNextLogin(Enum):
#     changePassword = "changePassword"
#
#
# class UserPolicyRuleCondition(BaseModel):
#     exclude: Optional[List[str]] = None
#     inactivity: Optional[InactivityPolicyRuleCondition] = None
#     include: Optional[List[str]] = None
#     lifecycleExpiration: Optional[LifecycleExpirationPolicyRuleCondition] = None
#     passwordExpiration: Optional[PasswordExpirationPolicyRuleCondition] = None
#     userLifecycleAttribute: Optional[
#         UserLifecycleAttributePolicyRuleCondition
#     ] = None
#
#
# class UserProfile(BaseModel):
#     city: Optional[str] = None
#     costCenter: Optional[str] = None
#     countryCode: Optional[str] = None
#     department: Optional[str] = None
#     displayName: Optional[str] = None
#     division: Optional[str] = None
#     email: Optional[str] = None
#     employeeNumber: Optional[str] = None
#     firstName: Optional[str] = None
#     honorificPrefix: Optional[str] = None
#     honorificSuffix: Optional[str] = None
#     lastName: Optional[str] = None
#     locale: Optional[str] = None
#     login: Optional[str] = None
#     manager: Optional[str] = None
#     managerId: Optional[str] = None
#     middleName: Optional[str] = None
#     mobilePhone: Optional[str] = None
#     nickName: Optional[str] = None
#     organization: Optional[str] = None
#     postalAddress: Optional[str] = None
#     preferredLanguage: Optional[str] = None
#     primaryPhone: Optional[str] = None
#     profileUrl: Optional[str] = None
#     secondEmail: Optional[str] = None
#     state: Optional[str] = None
#     streetAddress: Optional[str] = None
#     timezone: Optional[str] = None
#     title: Optional[str] = None
#     userType: Optional[str] = None
#     zipCode: Optional[str] = None
#
#
# class UserSchemaAttributeEnum(BaseModel):
#     const: Optional[str] = None
#     title: Optional[str] = None
#
#
# class UserSchemaAttributeItems(BaseModel):
#     enum: Optional[List[str]] = None
#     oneOf: Optional[List[UserSchemaAttributeEnum]] = None
#     type: Optional[str] = None
#
#
# class UserSchemaAttributeMasterPriority(BaseModel):
#     type: Optional[str] = None
#     value: Optional[str] = None
#
#
# class UserSchemaAttributeMasterType(Enum):
#     PROFILE_MASTER = "PROFILE_MASTER"
#     OKTA = "OKTA"
#     OVERRIDE = "OVERRIDE"
#
#
# class UserSchemaAttributePermission(BaseModel):
#     action: Optional[str] = None
#     principal: Optional[str] = None
#
#
# class UserSchemaAttributeScope(BaseModel):
#     pass
#
#
# class UserSchemaAttributeType(Enum):
#     string = "string"
#     boolean = "boolean"
#     number = "number"
#     integer = "integer"
#     array = "array"
#
#
# class UserSchemaAttributeUnion(BaseModel):
#     pass
#
#
# class UserSchemaPropertiesProfileItem(BaseModel):
#     field_ref: Optional[str] = Field(None, alias="$ref")
#
#
# class UserStatus(Enum):
#     ACTIVE = "ACTIVE"
#     DEPROVISIONED = "DEPROVISIONED"
#     LOCKED_OUT = "LOCKED_OUT"
#     PASSWORD_EXPIRED = "PASSWORD_EXPIRED"
#     PROVISIONED = "PROVISIONED"
#     RECOVERY = "RECOVERY"
#     STAGED = "STAGED"
#     SUSPENDED = "SUSPENDED"
#
#
# class Value(Enum):
#     ACTIVE = "ACTIVE"
#     INACTIVE = "INACTIVE"
#     PENDING = "PENDING"
#     DELETED = "DELETED"
#     EXPIRED_PASSWORD = "EXPIRED_PASSWORD"
#     ACTIVATING = "ACTIVATING"
#     SUSPENDED = "SUSPENDED"
#     DELETING = "DELETING"
#
#
# class UserStatusPolicyRuleCondition(BaseModel):
#     value: Optional[Value] = None
#
#
# class UserType(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[datetime] = None
#     createdBy: Optional[str] = None
#     default: Optional[bool] = None
#     description: Optional[str] = None
#     displayName: Optional[str] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     lastUpdatedBy: Optional[str] = None
#     name: Optional[str] = None
#
#
# class UserTypeCondition(BaseModel):
#     exclude: Optional[List[str]] = None
#     include: Optional[List[str]] = None
#
#
# class UserVerificationEnum(Enum):
#     REQUIRED = "REQUIRED"
#     PREFERRED = "PREFERRED"
#
#
# class VerifyFactorRequest(BaseModel):
#     activationToken: Optional[str] = None
#     answer: Optional[str] = None
#     attestation: Optional[str] = None
#     clientData: Optional[str] = None
#     nextPassCode: Optional[str] = None
#     passCode: Optional[str] = None
#     registrationData: Optional[str] = None
#     stateToken: Optional[str] = None
#
#
# class FactorResult(Enum):
#     SUCCESS = "SUCCESS"
#     EXPIRED = "EXPIRED"
#     CHALLENGE = "CHALLENGE"
#     WAITING = "WAITING"
#     FAILED = "FAILED"
#     REJECTED = "REJECTED"
#     TIMEOUT = "TIMEOUT"
#     TIME_WINDOW_EXCEEDED = "TIME_WINDOW_EXCEEDED"
#     PASSCODE_REPLAYED = "PASSCODE_REPLAYED"
#     ERROR = "ERROR"
#
#
# class VerifyUserFactorResponse(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     expiresAt: Optional[datetime] = None
#     factorResult: Optional[FactorResult] = None
#     factorResultMessage: Optional[str] = None
#
#
# class WebAuthnUserFactorProfile(BaseModel):
#     authenticatorName: Optional[str] = None
#     credentialId: Optional[str] = None
#
#
# class WebUserFactorProfile(BaseModel):
#     credentialId: Optional[str] = None
#
#
# class WsFederationApplicationSettingsApplication(BaseModel):
#     attributeStatements: Optional[str] = None
#     audienceRestriction: Optional[str] = None
#     authnContextClassRef: Optional[str] = None
#     groupFilter: Optional[str] = None
#     groupName: Optional[str] = None
#     groupValueFormat: Optional[str] = None
#     nameIDFormat: Optional[str] = None
#     realm: Optional[str] = None
#     siteURL: Optional[str] = None
#     usernameAttribute: Optional[str] = None
#     wReplyOverride: Optional[bool] = None
#     wReplyURL: Optional[str] = None
#
#
# class AccessPolicyConstraints(BaseModel):
#     knowledge: Optional[KnowledgeConstraint] = None
#     possession: Optional[PossessionConstraint] = None
#
#
# class AccessPolicyRuleConditions(BaseModel):
#     device: Optional[DeviceAccessPolicyRuleCondition] = None
#     elCondition: Optional[AccessPolicyRuleCustomCondition] = None
#     userType: Optional[UserTypeCondition] = None
#
#
# class AppUserCredentials(BaseModel):
#     password: Optional[AppUserPasswordCredential] = None
#     userName: Optional[str] = None
#
#
# class ApplicationCredentialsOAuthClient(BaseModel):
#     autoKeyRotation: Optional[bool] = None
#     client_id: Optional[str] = None
#     client_secret: Optional[str] = None
#     pkce_required: Optional[bool] = None
#     token_endpoint_auth_method: Optional[
#         OAuthEndpointAuthenticationMethod
#     ] = None
#
#
# class ApplicationCredentialsSigning(BaseModel):
#     kid: Optional[str] = None
#     lastRotated: Optional[datetime] = None
#     nextRotation: Optional[datetime] = None
#     rotationMode: Optional[str] = None
#     use: Optional[ApplicationCredentialsSigningUse] = None
#
#
# class ApplicationSettingsNotificationsVpn(BaseModel):
#     helpUrl: Optional[str] = None
#     message: Optional[str] = None
#     network: Optional[ApplicationSettingsNotificationsVpnNetwork] = None
#
#
# class ApplicationVisibility(BaseModel):
#     appLinks: Optional[Dict[str, bool]] = None
#     autoLaunch: Optional[bool] = None
#     autoSubmitToolbar: Optional[bool] = None
#     hide: Optional[ApplicationVisibilityHide] = None
#
#
# class AssignRoleRequest(BaseModel):
#     type: Optional[RoleType] = None
#
#
# class AuthenticationProvider(BaseModel):
#     name: Optional[str] = None
#     type: Optional[AuthenticationProviderType] = None
#
#
# class AuthenticatorProviderConfiguration(BaseModel):
#     authPort: Optional[int] = None
#     host: Optional[str] = None
#     hostName: Optional[str] = None
#     instanceId: Optional[str] = None
#     integrationKey: Optional[str] = None
#     secretKey: Optional[str] = None
#     sharedSecret: Optional[str] = None
#     userNameTemplate: Optional[
#         AuthenticatorProviderConfigurationUserNamePlate
#     ] = None
#
#
# class AuthorizationServerCredentialsSigningConfig(BaseModel):
#     kid: Optional[str] = None
#     lastRotated: Optional[datetime] = None
#     nextRotation: Optional[datetime] = None
#     rotationMode: Optional[AuthorizationServerCredentialsRotationMode] = None
#     use: Optional[AuthorizationServerCredentialsUse] = None
#
#
# class AutoLoginApplicationSettings(BaseModel):
#     signOn: Optional[AutoLoginApplicationSettingsSignOn] = None
#
#
# class BasicApplicationSettings(BaseModel):
#     app: Optional[BasicApplicationSettingsApplication] = None
#
#
# class BeforeScheduledActionPolicyRuleCondition(BaseModel):
#     duration: Optional[Duration] = None
#     lifecycleAction: Optional[ScheduledUserLifecycleAction] = None
#
#
# class BookmarkApplicationSettings(BaseModel):
#     app: Optional[BookmarkApplicationSettingsApplication] = None
#
#
# class CapabilitiesCreateObject(BaseModel):
#     lifecycleCreate: Optional[LifecycleCreateSettingObject] = None
#
#
# class CatalogApplication(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     category: Optional[str] = None
#     description: Optional[str] = None
#     displayName: Optional[str] = None
#     features: Optional[List[str]] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     signOnModes: Optional[List[str]] = None
#     status: Optional[CatalogApplicationStatus] = None
#     verificationStatus: Optional[str] = None
#     website: Optional[str] = None
#
#
# class ChannelBinding(BaseModel):
#     required: Optional[RequiredEnum] = None
#     style: Optional[str] = None
#
#
# class Compliance(BaseModel):
#     fips: Optional[FipsEnum] = None
#
#
# class CsrMetadata(BaseModel):
#     subject: Optional[CsrMetadataSubject] = None
#     subjectAltNames: Optional[CsrMetadataSubjectAltNames] = None
#
#
# class CustomHotpUserFactor(BaseModel):
#     factorProfileId: Optional[str] = None
#     profile: Optional[CustomHotpUserFactorProfile] = None
#
#
# class DNSRecord(BaseModel):
#     expiration: Optional[str] = None
#     fqdn: Optional[str] = None
#     recordType: Optional[DNSRecordType] = None
#     values: Optional[List[str]] = None
#
#
# class DevicePolicyRuleCondition(BaseModel):
#     migrated: Optional[bool] = None
#     platform: Optional[DevicePolicyRuleConditionPlatform] = None
#     rooted: Optional[bool] = None
#     trustLevel: Optional[TrustLevel] = None
#
#
# class Domain(BaseModel):
#     certificateSourceType: Optional[DomainCertificateSourceType] = None
#     dnsRecords: Optional[List[DNSRecord]] = None
#     domain: Optional[str] = None
#     id: Optional[str] = None
#     publicCertificate: Optional[DomainCertificateMetadata] = None
#     validationStatus: Optional[DomainValidationStatus] = None
#
#
# class DomainCertificate(BaseModel):
#     certificate: Optional[str] = None
#     certificateChain: Optional[str] = None
#     privateKey: Optional[str] = None
#     type: Optional[DomainCertificateType] = None
#
#
# class DomainListResponse(BaseModel):
#     domains: Optional[List[Domain]] = None
#
#
# class EmailUserFactor(BaseModel):
#     profile: Optional[EmailUserFactorProfile] = None
#
#
# class EventHookChannelConfigAuthScheme(BaseModel):
#     key: Optional[str] = None
#     type: Optional[EventHookChannelConfigAuthSchemeType] = None
#     value: Optional[str] = None
#
#
# class FeatureStage(BaseModel):
#     state: Optional[FeatureStageState] = None
#     value: Optional[FeatureStageValue] = None
#
#
# class Group(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     lastMembershipUpdated: Optional[datetime] = None
#     lastUpdated: Optional[datetime] = None
#     objectClass: Optional[List[str]] = None
#     profile: Optional[GroupProfile] = None
#     type: Optional[GroupType] = None
#
#
# class GroupRuleAction(BaseModel):
#     assignUserToGroups: Optional[GroupRuleGroupAssignment] = None
#
#
# class GroupRulePeopleCondition(BaseModel):
#     groups: Optional[GroupRuleGroupCondition] = None
#     users: Optional[GroupRuleUserCondition] = None
#
#
# class HardwareUserFactor(BaseModel):
#     profile: Optional[HardwareUserFactorProfile] = None
#
#
# class IdentityProviderCredentials(BaseModel):
#     client: Optional[IdentityProviderCredentialsClient] = None
#     signing: Optional[IdentityProviderCredentialsSigning] = None
#     trust: Optional[IdentityProviderCredentialsTrust] = None
#
#
# class IdpPolicyRuleAction(BaseModel):
#     providers: Optional[List[IdpPolicyRuleActionProvider]] = None
#
#
# class InlineHookChannelConfig(BaseModel):
#     authScheme: Optional[InlineHookChannelConfigAuthScheme] = None
#     headers: Optional[List[InlineHookChannelConfigHeaders]] = None
#     method: Optional[str] = None
#     uri: Optional[str] = None
#
#
# class InlineHookResponse(BaseModel):
#     commands: Optional[List[InlineHookResponseCommands]] = None
#
#
# class LinkedObjectDetails(BaseModel):
#     description: Optional[str] = None
#     name: Optional[str] = None
#     title: Optional[str] = None
#     type: Optional[LinkedObjectDetailsType] = None
#
#
# class LogAuthenticationContext(BaseModel):
#     authenticationProvider: Optional[LogAuthenticationProvider] = None
#     authenticationStep: Optional[int] = None
#     credentialProvider: Optional[LogCredentialProvider] = None
#     credentialType: Optional[LogCredentialType] = None
#     externalSessionId: Optional[str] = None
#     interface: Optional[str] = None
#     issuer: Optional[LogIssuer] = None
#
#
# class LogGeographicalContext(BaseModel):
#     city: Optional[str] = None
#     country: Optional[str] = None
#     geolocation: Optional[LogGeolocation] = None
#     postalCode: Optional[str] = None
#     state: Optional[str] = None
#
#
# class LogIpAddress(BaseModel):
#     geographicalContext: Optional[LogGeographicalContext] = None
#     ip: Optional[str] = None
#     source: Optional[str] = None
#     version: Optional[str] = None
#
#
# class LogRequest(BaseModel):
#     ipChain: Optional[List[LogIpAddress]] = None
#
#
# class Enroll(BaseModel):
#     self: Optional[MultifactorEnrollmentPolicyAuthenticatorStatus] = None
#
#
# class MultifactorEnrollmentPolicyAuthenticatorSettings(BaseModel):
#     constraints: Optional[Constraints] = None
#     enroll: Optional[Enroll] = None
#     key: Optional[MultifactorEnrollmentPolicyAuthenticatorType] = None
#
#
# class MultifactorEnrollmentPolicySettings(BaseModel):
#     authenticators: Optional[
#         List[MultifactorEnrollmentPolicyAuthenticatorSettings]
#     ] = None
#     type: Optional[MultifactorEnrollmentPolicySettingsType] = None
#
#
# class NetworkZoneAddress(BaseModel):
#     type: Optional[NetworkZoneAddressType] = None
#     value: Optional[str] = None
#
#
# class OAuth2Claim(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     alwaysIncludeInToken: Optional[bool] = None
#     claimType: Optional[ClaimType] = None
#     conditions: Optional[OAuth2ClaimConditions] = None
#     group_filter_type: Optional[GroupFilterType] = None
#     id: Optional[str] = None
#     name: Optional[str] = None
#     status: Optional[Status1] = None
#     system: Optional[bool] = None
#     value: Optional[str] = None
#     valueType: Optional[ValueType] = None
#
#
# class OAuth2ScopeConsentGrant(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     clientId: Optional[str] = None
#     created: Optional[datetime] = None
#     createdBy: Optional[OAuth2Actor] = None
#     id: Optional[str] = None
#     issuer: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     scopeId: Optional[str] = None
#     source: Optional[OAuth2ScopeConsentGrantSource] = None
#     status: Optional[OAuth2ScopeConsentGrantStatus] = None
#     userId: Optional[str] = None
#
#
# class OAuthApplicationCredentials(BaseModel):
#     oauthClient: Optional[ApplicationCredentialsOAuthClient] = None
#
#
# class OktaSignOnPolicyRuleSignonActions(BaseModel):
#     access: Optional[Access] = None
#     factorLifetime: Optional[int] = None
#     factorPromptMode: Optional[FactorPromptMode] = None
#     rememberDeviceByDefault: Optional[bool] = False
#     requireFactor: Optional[bool] = False
#     session: Optional[OktaSignOnPolicyRuleSignonSessionActions] = None
#
#
# class OpenIdConnectApplicationSettingsRefreshToken(BaseModel):
#     leeway: Optional[int] = None
#     rotation_type: Optional[OpenIdConnectRefreshTokenRotationType] = None
#
#
# class Org2OrgApplicationSettings(BaseModel):
#     app: Optional[Org2OrgApplicationSettingsApp] = None
#
#
# class PasswordCredentialHash(BaseModel):
#     algorithm: Optional[PasswordCredentialHashAlgorithm] = None
#     salt: Optional[str] = None
#     saltOrder: Optional[str] = None
#     value: Optional[str] = None
#     workFactor: Optional[int] = None
#
#
# class PasswordDictionary(BaseModel):
#     common: Optional[PasswordDictionaryCommon] = None
#
#
# class PasswordPolicyDelegationSettings(BaseModel):
#     options: Optional[PasswordPolicyDelegationSettingsOptions] = None
#
#
# class PasswordPolicyPasswordSettingsComplexity(BaseModel):
#     dictionary: Optional[PasswordDictionary] = None
#     excludeAttributes: Optional[List[str]] = 1
#     excludeUsername: Optional[bool] = True
#     minLength: Optional[int] = 8
#     minLowerCase: Optional[int] = 1
#     minNumber: Optional[int] = 1
#     minSymbol: Optional[int] = 1
#     minUpperCase: Optional[int] = 1
#
#
# class PasswordPolicyRecoveryEmailProperties(BaseModel):
#     recoveryToken: Optional[PasswordPolicyRecoveryEmailRecoveryToken] = None
#
#
# class PasswordPolicyRecoveryQuestion(BaseModel):
#     properties: Optional[PasswordPolicyRecoveryQuestionProperties] = None
#     status: Optional[Status10] = None
#
#
# class PasswordSettingObject(BaseModel):
#     change: Optional[ChangeEnum] = None
#     seed: Optional[SeedEnum] = None
#     status: Optional[EnabledStatus] = None
#
#
# class PlatformConditionEvaluatorPlatformOperatingSystem(BaseModel):
#     expression: Optional[str] = None
#     type: Optional[Type8] = None
#     version: Optional[
#         PlatformConditionEvaluatorPlatformOperatingSystemVersion
#     ] = None
#
#
# class PolicyAccountLinkFilter(BaseModel):
#     groups: Optional[PolicyAccountLinkFilterGroups] = None
#
#
# class PolicyPeopleCondition(BaseModel):
#     groups: Optional[GroupCondition] = None
#     users: Optional[UserCondition] = None
#
#
# class PolicyRuleActionsEnroll(BaseModel):
#     self: Optional[PolicyRuleActionsEnrollSelf] = None
#
#
# class PolicySubject(BaseModel):
#     filter: Optional[str] = None
#     format: Optional[List[str]] = None
#     matchAttribute: Optional[str] = None
#     matchType: Optional[PolicySubjectMatchType] = None
#     userNameTemplate: Optional[PolicyUserNameTemplate] = None
#
#
# class ProfileEnrollmentPolicyRuleAction(BaseModel):
#     access: Optional[str] = None
#     activationRequirements: Optional[
#         ProfileEnrollmentPolicyRuleActivationRequirement
#     ] = None
#     preRegistrationInlineHooks: Optional[List[PreRegistrationInlineHook]] = None
#     profileAttributes: Optional[
#         List[ProfileEnrollmentPolicyRuleProfileAttribute]
#     ] = None
#     targetGroupIds: Optional[List[str]] = None
#     uiSchemaId: Optional[str] = None
#     unknownUserAction: Optional[str] = None
#
#
# class ProfileEnrollmentPolicyRuleActions(BaseModel):
#     profileEnrollment: Optional[ProfileEnrollmentPolicyRuleAction] = None
#
#
# class ProfileMappingProperty(BaseModel):
#     expression: Optional[str] = None
#     pushStatus: Optional[ProfileMappingPropertyPushStatus] = None
#
#
# class ProtocolAlgorithmType(BaseModel):
#     signature: Optional[ProtocolAlgorithmTypeSignature] = None
#
#
# class ProtocolAlgorithms(BaseModel):
#     request: Optional[ProtocolAlgorithmType] = None
#     response: Optional[ProtocolAlgorithmType] = None
#
#
# class ProtocolRelayState(BaseModel):
#     format: Optional[ProtocolRelayStateFormat] = None
#
#
# class ProvisioningConditions(BaseModel):
#     deprovisioned: Optional[ProvisioningDeprovisionedCondition] = None
#     suspended: Optional[ProvisioningSuspendedCondition] = None
#
#
# class ProvisioningConnection(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     authScheme: Optional[ProvisioningConnectionAuthScheme] = None
#     status: Optional[ProvisioningConnectionStatus] = None
#
#
# class PushUserFactor(BaseModel):
#     expiresAt: Optional[datetime] = None
#     factorResult: Optional[FactorResultType] = None
#     profile: Optional[PushUserFactorProfile] = None
#
#
# class SignedNonceFactorProfile(BaseModel):
#     credentialId: Optional[str] = None
#     deviceToken: Optional[str] = None
#     deviceType: Optional[str] = None
#     name: Optional[str] = None
#     platform: Optional[str] = None
#     version: Optional[str] = None
#
#
# class SignedNonceFactor(UserFactor):
#     expiresAt: Optional[datetime] = None
#     factorResult: Optional[FactorResultType] = None
#     profile: Optional[SignedNonceFactorProfile] = None
#
#
# class Role(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     assignmentType: Optional[RoleAssignmentType] = None
#     created: Optional[datetime] = None
#     description: Optional[str] = None
#     id: Optional[str] = None
#     label: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     status: Optional[RoleStatus] = None
#     type: Optional[RoleType] = None
#
#
# class SamlApplicationSettingsSignOn(BaseModel):
#     acsEndpoints: Optional[List[AcsEndpoint]] = None
#     allowMultipleAcsEndpoints: Optional[bool] = None
#     assertionSigned: Optional[bool] = None
#     attributeStatements: Optional[List[SamlAttributeStatement]] = None
#     audience: Optional[str] = None
#     audienceOverride: Optional[str] = None
#     authnContextClassRef: Optional[str] = None
#     defaultRelayState: Optional[str] = None
#     destination: Optional[str] = None
#     destinationOverride: Optional[str] = None
#     digestAlgorithm: Optional[str] = None
#     honorForceAuthn: Optional[bool] = None
#     idpIssuer: Optional[str] = None
#     inlineHooks: Optional[List[SignOnInlineHook]] = None
#     recipient: Optional[str] = None
#     recipientOverride: Optional[str] = None
#     requestCompressed: Optional[bool] = None
#     responseSigned: Optional[bool] = None
#     samlSignedRequestEnabled: Optional[bool] = None
#     signatureAlgorithm: Optional[str] = None
#     slo: Optional[SingleLogout] = None
#     spCertificate: Optional[SpCertificate] = None
#     spIssuer: Optional[str] = None
#     ssoAcsUrl: Optional[str] = None
#     ssoAcsUrlOverride: Optional[str] = None
#     subjectNameIdFormat: Optional[str] = None
#     subjectNameIdTemplate: Optional[str] = None
#
#
# class Scope1(BaseModel):
#     allowedOktaApps: Optional[List[IframeEmbedScopeAllowedApps]] = None
#     stringValue: Optional[str] = None
#     type: Optional[ScopeType] = None
#
#
# class SecurePasswordStoreApplicationSettings(BaseModel):
#     app: Optional[SecurePasswordStoreApplicationSettingsApplication] = None
#
#
# class SecurityQuestionUserFactor(BaseModel):
#     profile: Optional[SecurityQuestionUserFactorProfile] = None
#
#
# class SessionIdentityProvider(BaseModel):
#     id: Optional[str] = None
#     type: Optional[SessionIdentityProviderType] = None
#
#
# class SmsTemplate(BaseModel):
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     template: Optional[str] = None
#     translations: Optional[SmsTemplateTranslations] = None
#     type: Optional[SmsTemplateType] = None
#
#
# class SmsUserFactor(BaseModel):
#     profile: Optional[SmsUserFactorProfile] = None
#
#
# class Subscription(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     channels: Optional[List[str]] = None
#     notificationType: Optional[NotificationType] = None
#     status: Optional[SubscriptionStatus] = None
#
#
# class SwaApplicationSettings(BaseModel):
#     app: Optional[SwaApplicationSettingsApplication] = None
#
#
# class SwaThreeFieldApplicationSettings(BaseModel):
#     app: Optional[SwaThreeFieldApplicationSettingsApplication] = None
#
#
# class TokenAuthorizationServerPolicyRuleAction(BaseModel):
#     accessTokenLifetimeMinutes: Optional[int] = None
#     inlineHook: Optional[
#         TokenAuthorizationServerPolicyRuleActionInlineHook
#     ] = None
#     refreshTokenLifetimeMinutes: Optional[int] = None
#     refreshTokenWindowMinutes: Optional[int] = None
#
#
# class TokenUserFactor(BaseModel):
#     profile: Optional[TokenUserFactorProfile] = None
#
#
# class TotpUserFactor(BaseModel):
#     profile: Optional[TotpUserFactorProfile] = None
#
#
# class TrustedOrigin(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[datetime] = None
#     createdBy: Optional[str] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     lastUpdatedBy: Optional[str] = None
#     name: Optional[str] = None
#     origin: Optional[str] = None
#     scopes: Optional[List[Scope1]] = None
#     status: Optional[str] = None
#
#
# class U2fUserFactor(BaseModel):
#     profile: Optional[U2fUserFactorProfile] = None
#
#
# class UserFactor(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[datetime] = None
#     factorType: Optional[FactorType] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     provider: Optional[FactorProvider] = None
#     status: Optional[FactorStatus] = None
#     verify: Optional[VerifyFactorRequest] = None
#
#
# class UserSchemaAttributeMaster(BaseModel):
#     priority: Optional[List[UserSchemaAttributeMasterPriority]] = None
#     type: Optional[UserSchemaAttributeMasterType] = None
#
#
# class UserSchemaPropertiesProfile(BaseModel):
#     allOf: Optional[List[UserSchemaPropertiesProfileItem]] = None
#
#
# class VerificationMethod(BaseModel):
#     constraints: Optional[List[AccessPolicyConstraints]] = None
#     factorMode: Optional[str] = None
#     inactivityPeriod: Optional[str] = None
#     reauthenticateIn: Optional[str] = None
#     type: Optional[str] = None
#
#
# class WebAuthnUserFactor(BaseModel):
#     profile: Optional[WebAuthnUserFactorProfile] = None
#
#
# class WebUserFactor(BaseModel):
#     profile: Optional[WebUserFactorProfile] = None
#
#
# class WsFederationApplicationSettings(BaseModel):
#     app: Optional[WsFederationApplicationSettingsApplication] = None
#
#
# class AccessPolicyRuleApplicationSignOn(BaseModel):
#     access: Optional[str] = None
#     verificationMethod: Optional[VerificationMethod] = None
#
#
# class AppUser(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[datetime] = None
#     credentials: Optional[AppUserCredentials] = None
#     externalId: Optional[str] = None
#     id: Optional[str] = None
#     lastSync: Optional[datetime] = None
#     lastUpdated: Optional[datetime] = None
#     passwordChanged: Optional[datetime] = None
#     profile: Optional[Dict[str, Dict[str, Any]]] = None
#     scope: Optional[str] = None
#     status: Optional[str] = None
#     statusChanged: Optional[datetime] = None
#     syncState: Optional[str] = None
#
#
# class ApplicationCredentials(BaseModel):
#     signing: Optional[ApplicationCredentialsSigning] = None
#     userNameTemplate: Optional[ApplicationCredentialsUsernameTemplate] = None
#
#
# class ApplicationSettingsNotifications(BaseModel):
#     vpn: Optional[ApplicationSettingsNotificationsVpn] = None
#
#
# class AuthenticatorProvider(BaseModel):
#     configuration: Optional[AuthenticatorProviderConfiguration] = None
#     type: Optional[str] = None
#
#
# class AuthenticatorSettings(BaseModel):
#     allowedFor: Optional[AllowedForEnum] = None
#     appInstanceId: Optional[str] = None
#     channelBinding: Optional[ChannelBinding] = None
#     compliance: Optional[Compliance] = None
#     tokenLifetimeInMinutes: Optional[int] = None
#     userVerification: Optional[UserVerificationEnum] = None
#
#
# class AuthorizationServerCredentials(BaseModel):
#     signing: Optional[AuthorizationServerCredentialsSigningConfig] = None
#
#
# class AuthorizationServerPolicyRuleActions(BaseModel):
#     token: Optional[TokenAuthorizationServerPolicyRuleAction] = None
#
#
# class AuthorizationServerPolicyRuleConditions(BaseModel):
#     clients: Optional[ClientPolicyCondition] = None
#     grantTypes: Optional[GrantTypePolicyRuleCondition] = None
#     people: Optional[PolicyPeopleCondition] = None
#     scopes: Optional[OAuth2ScopesMediationPolicyRuleCondition] = None
#
#
# class BookmarkApplication(BaseModel):
#     name: Optional[Any] = "bookmark"
#     settings: Optional[BookmarkApplicationSettings] = None
#
#
# class CapabilitiesUpdateObject(BaseModel):
#     lifecycleDeactivate: Optional[LifecycleDeactivateSettingObject] = None
#     password: Optional[PasswordSettingObject] = None
#     profile: Optional[ProfileSettingObject] = None
#
#
# class EventHookChannelConfig(BaseModel):
#     authScheme: Optional[EventHookChannelConfigAuthScheme] = None
#     headers: Optional[List[EventHookChannelConfigHeader]] = None
#     uri: Optional[str] = None
#
#
# class Feature(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     description: Optional[str] = None
#     id: Optional[str] = None
#     name: Optional[str] = None
#     stage: Optional[FeatureStage] = None
#     status: Optional[EnabledStatus] = None
#     type: Optional[FeatureType] = None
#
#
# class GroupRuleConditions(BaseModel):
#     expression: Optional[GroupRuleExpression] = None
#     people: Optional[GroupRulePeopleCondition] = None
#
#
# class GroupSchemaAttribute(BaseModel):
#     description: Optional[str] = None
#     enum: Optional[List[str]] = None
#     externalName: Optional[str] = None
#     externalNamespace: Optional[str] = None
#     items: Optional[UserSchemaAttributeItems] = None
#     master: Optional[UserSchemaAttributeMaster] = None
#     maxLength: Optional[int] = None
#     minLength: Optional[int] = None
#     mutability: Optional[str] = None
#     oneOf: Optional[List[UserSchemaAttributeEnum]] = None
#     permissions: Optional[List[UserSchemaAttributePermission]] = None
#     required: Optional[bool] = None
#     scope: Optional[UserSchemaAttributeScope] = None
#     title: Optional[str] = None
#     type: Optional[UserSchemaAttributeType] = None
#     union: Optional[UserSchemaAttributeUnion] = None
#     unique: Optional[str] = None
#
#
# class GroupSchemaBaseProperties(BaseModel):
#     description: Optional[GroupSchemaAttribute] = None
#     name: Optional[GroupSchemaAttribute] = None
#
#
# class GroupSchemaCustom(BaseModel):
#     id: Optional[str] = None
#     properties: Optional[Dict[str, GroupSchemaAttribute]] = None
#     required: Optional[List[str]] = None
#     type: Optional[str] = None
#
#
# class InlineHookChannel(BaseModel):
#     config: Optional[InlineHookChannelConfig] = None
#     type: Optional[Type6] = None
#     version: Optional[str] = None
#
#
# class LinkedObject(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     associated: Optional[LinkedObjectDetails] = None
#     primary: Optional[LinkedObjectDetails] = None
#
#
# class LogClient(BaseModel):
#     device: Optional[str] = None
#     geographicalContext: Optional[LogGeographicalContext] = None
#     id: Optional[str] = None
#     ipAddress: Optional[str] = None
#     userAgent: Optional[LogUserAgent] = None
#     zone: Optional[str] = None
#
#
# class LogEvent(BaseModel):
#     actor: Optional[LogActor] = None
#     authenticationContext: Optional[LogAuthenticationContext] = None
#     client: Optional[LogClient] = None
#     debugContext: Optional[LogDebugContext] = None
#     displayMessage: Optional[str] = None
#     eventType: Optional[str] = None
#     legacyEventType: Optional[str] = None
#     outcome: Optional[LogOutcome] = None
#     published: Optional[datetime] = None
#     request: Optional[LogRequest] = None
#     securityContext: Optional[LogSecurityContext] = None
#     severity: Optional[LogSeverity] = None
#     target: Optional[List[LogTarget]] = None
#     transaction: Optional[LogTransaction] = None
#     uuid: Optional[str] = None
#     version: Optional[str] = None
#
#
# class NetworkZone(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     asns: Optional[List[str]] = None
#     created: Optional[datetime] = None
#     gateways: Optional[List[NetworkZoneAddress]] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     locations: Optional[List[NetworkZoneLocation]] = None
#     name: Optional[str] = None
#     proxies: Optional[List[NetworkZoneAddress]] = None
#     proxyType: Optional[str] = None
#     status: Optional[NetworkZoneStatus] = None
#     system: Optional[bool] = None
#     type: Optional[NetworkZoneType] = None
#     usage: Optional[NetworkZoneUsage] = None
#
#
# class OktaSignOnPolicyConditions(BaseModel):
#     people: Optional[PolicyPeopleCondition] = None
#
#
# class OktaSignOnPolicyRuleActions(BaseModel):
#     signon: Optional[OktaSignOnPolicyRuleSignonActions] = None
#
#
# class OktaSignOnPolicyRuleConditions(BaseModel):
#     authContext: Optional[PolicyRuleAuthContextCondition] = None
#     network: Optional[PolicyNetworkCondition] = None
#     people: Optional[PolicyPeopleCondition] = None
#
#
# class OpenIdConnectApplicationSettingsClient(BaseModel):
#     application_type: Optional[OpenIdConnectApplicationType] = None
#     client_uri: Optional[str] = None
#     consent_method: Optional[OpenIdConnectApplicationConsentMethod] = None
#     grant_types: Optional[List[OAuthGrantType]] = None
#     idp_initiated_login: Optional[
#         OpenIdConnectApplicationIdpInitiatedLogin
#     ] = None
#     initiate_login_uri: Optional[str] = None
#     issuer_mode: Optional[OpenIdConnectApplicationIssuerMode] = None
#     jwks: Optional[OpenIdConnectApplicationSettingsClientKeys] = None
#     logo_uri: Optional[str] = None
#     policy_uri: Optional[str] = None
#     post_logout_redirect_uris: Optional[List[str]] = None
#     redirect_uris: Optional[List[str]] = None
#     refresh_token: Optional[OpenIdConnectApplicationSettingsRefreshToken] = None
#     response_types: Optional[List[OAuthResponseType]] = None
#     tos_uri: Optional[str] = None
#     wildcard_redirect: Optional[str] = None
#
#
# class Org2OrgApplication(BaseModel):
#     name: Optional[Any] = "okta_org2org"
#     settings: Optional[Org2OrgApplicationSettings] = None
#
#
# class PasswordCredential(BaseModel):
#     hash: Optional[PasswordCredentialHash] = None
#     hook: Optional[PasswordCredentialHook] = None
#     value: Optional[SecretStr] = None
#
#
# class PasswordPolicyConditions(BaseModel):
#     authProvider: Optional[PasswordPolicyAuthenticationProviderCondition] = None
#     people: Optional[PolicyPeopleCondition] = None
#
#
# class PasswordPolicyPasswordSettings(BaseModel):
#     age: Optional[PasswordPolicyPasswordSettingsAge] = None
#     complexity: Optional[PasswordPolicyPasswordSettingsComplexity] = None
#     lockout: Optional[PasswordPolicyPasswordSettingsLockout] = None
#
#
# class PasswordPolicyRecoveryEmail(BaseModel):
#     properties: Optional[PasswordPolicyRecoveryEmailProperties] = None
#     status: Optional[Status10] = None
#
#
# class PasswordPolicyRecoveryFactors(BaseModel):
#     okta_call: Optional[PasswordPolicyRecoveryFactorSettings] = None
#     okta_email: Optional[PasswordPolicyRecoveryEmail] = None
#     okta_sms: Optional[PasswordPolicyRecoveryFactorSettings] = None
#     recovery_question: Optional[PasswordPolicyRecoveryQuestion] = None
#
#
# class PasswordPolicyRecoverySettings(BaseModel):
#     factors: Optional[PasswordPolicyRecoveryFactors] = None
#
#
# class PasswordPolicyRuleConditions(BaseModel):
#     network: Optional[PolicyNetworkCondition] = None
#     people: Optional[PolicyPeopleCondition] = None
#
#
# class PasswordPolicySettings(BaseModel):
#     delegation: Optional[PasswordPolicyDelegationSettings] = None
#     password: Optional[PasswordPolicyPasswordSettings] = None
#     recovery: Optional[PasswordPolicyRecoverySettings] = None
#
#
# class PlatformConditionEvaluatorPlatform(BaseModel):
#     os: Optional[PlatformConditionEvaluatorPlatformOperatingSystem] = None
#     type: Optional[Type7] = None
#
#
# class PlatformPolicyRuleCondition(BaseModel):
#     exclude: Optional[List[PlatformConditionEvaluatorPlatform]] = None
#     include: Optional[List[PlatformConditionEvaluatorPlatform]] = None
#
#
# class PolicyAccountLink(BaseModel):
#     action: Optional[Action] = None
#     filter: Optional[PolicyAccountLinkFilter] = None
#
#
# class PolicyRuleActions(BaseModel):
#     enroll: Optional[PolicyRuleActionsEnroll] = None
#     idp: Optional[IdpPolicyRuleAction] = None
#     passwordChange: Optional[PasswordPolicyRuleAction] = None
#     selfServicePasswordReset: Optional[PasswordPolicyRuleAction] = None
#     selfServiceUnlock: Optional[PasswordPolicyRuleAction] = None
#     signon: Optional[OktaSignOnPolicyRuleSignonActions] = None
#
#
# class PolicyRuleConditions(BaseModel):
#     app: Optional[AppAndInstancePolicyRuleCondition] = None
#     apps: Optional[AppInstancePolicyRuleCondition] = None
#     authContext: Optional[PolicyRuleAuthContextCondition] = None
#     authProvider: Optional[PasswordPolicyAuthenticationProviderCondition] = None
#     beforeScheduledAction: Optional[
#         BeforeScheduledActionPolicyRuleCondition
#     ] = None
#     clients: Optional[ClientPolicyCondition] = None
#     context: Optional[ContextPolicyRuleCondition] = None
#     device: Optional[DevicePolicyRuleCondition] = None
#     grantTypes: Optional[GrantTypePolicyRuleCondition] = None
#     groups: Optional[GroupPolicyRuleCondition] = None
#     identityProvider: Optional[IdentityProviderPolicyRuleCondition] = None
#     mdmEnrollment: Optional[MDMEnrollmentPolicyRuleCondition] = None
#     network: Optional[PolicyNetworkCondition] = None
#     people: Optional[PolicyPeopleCondition] = None
#     platform: Optional[PlatformPolicyRuleCondition] = None
#     risk: Optional[RiskPolicyRuleCondition] = None
#     riskScore: Optional[RiskScorePolicyRuleCondition] = None
#     scopes: Optional[OAuth2ScopesMediationPolicyRuleCondition] = None
#     userIdentifier: Optional[UserIdentifierPolicyRuleCondition] = None
#     userStatus: Optional[UserStatusPolicyRuleCondition] = None
#     users: Optional[UserPolicyRuleCondition] = None
#
#
# class ProfileEnrollmentPolicyRule(BaseModel):
#     actions: Optional[ProfileEnrollmentPolicyRuleActions] = None
#     name: Optional[str] = None
#
#
# class ProfileMapping(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     id: Optional[str] = None
#     properties: Optional[Dict[str, ProfileMappingProperty]] = None
#     source: Optional[ProfileMappingSource] = None
#     target: Optional[ProfileMappingSource] = None
#
#
# class Protocol(BaseModel):
#     algorithms: Optional[ProtocolAlgorithms] = None
#     credentials: Optional[IdentityProviderCredentials] = None
#     endpoints: Optional[ProtocolEndpoints] = None
#     issuer: Optional[ProtocolEndpoint] = None
#     relayState: Optional[ProtocolRelayState] = None
#     scopes: Optional[List[str]] = None
#     settings: Optional[ProtocolSettings] = None
#     type: Optional[Type10] = None
#
#
# class Provisioning(BaseModel):
#     action: Optional[Action1] = None
#     conditions: Optional[ProvisioningConditions] = None
#     groups: Optional[ProvisioningGroups] = None
#     profileMaster: Optional[bool] = None
#
#
# class SamlApplicationSettings(BaseModel):
#     signOn: Optional[SamlApplicationSettingsSignOn] = None
#
#
# class SchemeApplicationCredentials(BaseModel):
#     password: Optional[PasswordCredential] = None
#     revealPassword: Optional[bool] = None
#     scheme: Optional[ApplicationCredentialsScheme] = None
#     signing: Optional[ApplicationCredentialsSigning] = None
#     userName: Optional[str] = None
#
#
# class SecurePasswordStoreApplication(BaseModel):
#     credentials: Optional[SchemeApplicationCredentials] = None
#     name: Optional[Any] = "template_sps"
#     settings: Optional[SecurePasswordStoreApplicationSettings] = None
#
#
# class Session(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     amr: Optional[List[SessionAuthenticationMethod]] = None
#     createdAt: Optional[datetime] = None
#     expiresAt: Optional[datetime] = None
#     id: Optional[str] = None
#     idp: Optional[SessionIdentityProvider] = None
#     lastFactorVerification: Optional[datetime] = None
#     lastPasswordVerification: Optional[datetime] = None
#     login: Optional[str] = None
#     status: Optional[SessionStatus] = None
#     userId: Optional[str] = None
#
#
# class SwaApplication(BaseModel):
#     name: Optional[Any] = "template_swa"
#     settings: Optional[SwaApplicationSettings] = None
#
#
# class SwaThreeFieldApplication(BaseModel):
#     name: Optional[Any] = "template_swa3field"
#     settings: Optional[SwaThreeFieldApplicationSettings] = None
#
#
# class UserCredentials(BaseModel):
#     password: Optional[PasswordCredential] = None
#     provider: Optional[AuthenticationProvider] = None
#     recovery_question: Optional[RecoveryQuestionCredential] = None
#
#
# class UserSchemaAttribute(BaseModel):
#     description: Optional[str] = None
#     enum: Optional[List[str]] = None
#     externalName: Optional[str] = None
#     externalNamespace: Optional[str] = None
#     items: Optional[UserSchemaAttributeItems] = None
#     master: Optional[UserSchemaAttributeMaster] = None
#     maxLength: Optional[int] = None
#     minLength: Optional[int] = None
#     mutability: Optional[str] = None
#     oneOf: Optional[List[UserSchemaAttributeEnum]] = None
#     pattern: Optional[str] = None
#     permissions: Optional[List[UserSchemaAttributePermission]] = None
#     required: Optional[bool] = None
#     scope: Optional[UserSchemaAttributeScope] = None
#     title: Optional[str] = None
#     type: Optional[UserSchemaAttributeType] = None
#     union: Optional[UserSchemaAttributeUnion] = None
#     unique: Optional[str] = None
#
#
# class UserSchemaBaseProperties(BaseModel):
#     city: Optional[UserSchemaAttribute] = None
#     costCenter: Optional[UserSchemaAttribute] = None
#     countryCode: Optional[UserSchemaAttribute] = None
#     department: Optional[UserSchemaAttribute] = None
#     displayName: Optional[UserSchemaAttribute] = None
#     division: Optional[UserSchemaAttribute] = None
#     email: Optional[UserSchemaAttribute] = None
#     employeeNumber: Optional[UserSchemaAttribute] = None
#     firstName: Optional[UserSchemaAttribute] = None
#     honorificPrefix: Optional[UserSchemaAttribute] = None
#     honorificSuffix: Optional[UserSchemaAttribute] = None
#     lastName: Optional[UserSchemaAttribute] = None
#     locale: Optional[UserSchemaAttribute] = None
#     login: Optional[UserSchemaAttribute] = None
#     manager: Optional[UserSchemaAttribute] = None
#     managerId: Optional[UserSchemaAttribute] = None
#     middleName: Optional[UserSchemaAttribute] = None
#     mobilePhone: Optional[UserSchemaAttribute] = None
#     nickName: Optional[UserSchemaAttribute] = None
#     organization: Optional[UserSchemaAttribute] = None
#     postalAddress: Optional[UserSchemaAttribute] = None
#     preferredLanguage: Optional[UserSchemaAttribute] = None
#     primaryPhone: Optional[UserSchemaAttribute] = None
#     profileUrl: Optional[UserSchemaAttribute] = None
#     secondEmail: Optional[UserSchemaAttribute] = None
#     state: Optional[UserSchemaAttribute] = None
#     streetAddress: Optional[UserSchemaAttribute] = None
#     timezone: Optional[UserSchemaAttribute] = None
#     title: Optional[UserSchemaAttribute] = None
#     userType: Optional[UserSchemaAttribute] = None
#     zipCode: Optional[UserSchemaAttribute] = None
#
#
# class UserSchemaProperties(BaseModel):
#     profile: Optional[UserSchemaPropertiesProfile] = None
#
#
# class UserSchemaPublic(BaseModel):
#     id: Optional[str] = None
#     properties: Optional[Dict[str, UserSchemaAttribute]] = None
#     required: Optional[List[str]] = None
#     type: Optional[str] = None
#
#
# class WsFederationApplication(BaseModel):
#     name: Optional[Any] = "template_wsfed"
#     settings: Optional[WsFederationApplicationSettings] = None
#
#
# class AccessPolicyRuleActions(BaseModel):
#     appSignOn: Optional[AccessPolicyRuleApplicationSignOn] = None
#
#
# class ApplicationSettings(BaseModel):
#     app: Optional[ApplicationSettingsApplication] = None
#     implicitAssignment: Optional[bool] = None
#     inlineHookId: Optional[str] = None
#     notes: Optional[ApplicationSettingsNotes] = None
#     notifications: Optional[ApplicationSettingsNotifications] = None
#
#
# class Authenticator(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     key: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     provider: Optional[AuthenticatorProvider] = None
#     settings: Optional[AuthenticatorSettings] = None
#     status: Optional[AuthenticatorStatus] = None
#     type: Optional[AuthenticatorType] = None
#
#
# class AuthorizationServer(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     audiences: Optional[List[str]] = None
#     created: Optional[datetime] = None
#     credentials: Optional[AuthorizationServerCredentials] = None
#     default: Optional[bool] = None
#     description: Optional[str] = None
#     id: Optional[str] = None
#     issuer: Optional[str] = None
#     issuerMode: Optional[IssuerMode] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     status: Optional[Status1] = None
#
#
# class AuthorizationServerPolicy(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     conditions: Optional[PolicyRuleConditions] = None
#     created: Optional[datetime] = None
#     description: Optional[str] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     priority: Optional[int] = None
#     status: Optional[Status1] = None
#     system: Optional[bool] = None
#     type: Optional[PolicyType] = None
#
#
# class AuthorizationServerPolicyRule(BaseModel):
#     actions: Optional[AuthorizationServerPolicyRuleActions] = None
#     conditions: Optional[AuthorizationServerPolicyRuleConditions] = None
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     priority: Optional[int] = None
#     status: Optional[Status1] = "ACTIVE"
#     system: Optional[bool] = False
#     type: Optional[Type1] = None
#
#
# class AutoLoginApplication(BaseModel):
#     credentials: Optional[SchemeApplicationCredentials] = None
#     settings: Optional[AutoLoginApplicationSettings] = None
#
#
# class BasicAuthApplication(BaseModel):
#     credentials: Optional[SchemeApplicationCredentials] = None
#     name: Optional[Any] = "template_basic_auth"
#     settings: Optional[BasicApplicationSettings] = None
#
#
# class BrowserPluginApplication(BaseModel):
#     credentials: Optional[SchemeApplicationCredentials] = None
#
#
# class CapabilitiesObject(BaseModel):
#     create: Optional[CapabilitiesCreateObject] = None
#     update: Optional[CapabilitiesUpdateObject] = None
#
#
# class ChangePasswordRequest(BaseModel):
#     newPassword: Optional[PasswordCredential] = None
#     oldPassword: Optional[PasswordCredential] = None
#
#
# class CreateUserRequest(BaseModel):
#     credentials: Optional[UserCredentials] = None
#     groupIds: Optional[List[str]] = None
#     profile: Optional[UserProfile] = None
#     type: Optional[UserType] = None
#
#
# class EventHookChannel(BaseModel):
#     config: Optional[EventHookChannelConfig] = None
#     type: Optional[Type3] = None
#     version: Optional[str] = None
#
#
# class GroupRule(BaseModel):
#     actions: Optional[GroupRuleAction] = None
#     conditions: Optional[GroupRuleConditions] = None
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     status: Optional[GroupRuleStatus] = None
#     type: Optional[str] = None
#
#
# class GroupSchemaBase(BaseModel):
#     id: Optional[str] = None
#     properties: Optional[GroupSchemaBaseProperties] = None
#     required: Optional[List[str]] = None
#     type: Optional[str] = None
#
#
# class GroupSchemaDefinitions(BaseModel):
#     base: Optional[GroupSchemaBase] = None
#     custom: Optional[GroupSchemaCustom] = None
#
#
# class IdentityProviderPolicy(BaseModel):
#     accountLink: Optional[PolicyAccountLink] = None
#     maxClockSkew: Optional[int] = None
#     provisioning: Optional[Provisioning] = None
#     subject: Optional[PolicySubject] = None
#
#
# class InlineHook(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     channel: Optional[InlineHookChannel] = None
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     status: Optional[InlineHookStatus] = None
#     type: Optional[InlineHookType] = None
#     version: Optional[str] = None
#
#
# class OktaSignOnPolicy(BaseModel):
#     conditions: Optional[OktaSignOnPolicyConditions] = None
#
#
# class OktaSignOnPolicyRule(BaseModel):
#     actions: Optional[OktaSignOnPolicyRuleActions] = None
#     conditions: Optional[OktaSignOnPolicyRuleConditions] = None
#     name: Optional[str] = None
#
#
# class OpenIdConnectApplicationSettings(BaseModel):
#     oauthClient: Optional[OpenIdConnectApplicationSettingsClient] = None
#
#
# class PasswordPolicy(BaseModel):
#     conditions: Optional[PasswordPolicyConditions] = None
#     settings: Optional[PasswordPolicySettings] = None
#
#
# class PasswordPolicyRule(BaseModel):
#     actions: Optional[PasswordPolicyRuleActions] = None
#     conditions: Optional[PasswordPolicyRuleConditions] = None
#     name: Optional[str] = None
#
#
# class Policy(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     conditions: Optional[PolicyRuleConditions] = None
#     created: Optional[datetime] = None
#     description: Optional[str] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     priority: Optional[int] = None
#     status: Optional[Status10] = None
#     system: Optional[bool] = None
#     type: Optional[PolicyType] = None
#
#
# class PolicyRule(BaseModel):
#     actions: Optional[PolicyRuleActions] = None
#     conditions: Optional[PolicyRuleConditions] = None
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     priority: Optional[int] = None
#     status: Optional[Status10] = "ACTIVE"
#     system: Optional[bool] = False
#     type: Optional[Type9] = None
#
#
# class SamlApplication(BaseModel):
#     settings: Optional[SamlApplicationSettings] = None
#
#
# class User(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     activated: Optional[datetime] = None
#     created: Optional[datetime] = None
#     credentials: Optional[UserCredentials] = None
#     id: Optional[str] = None
#     lastLogin: Optional[datetime] = None
#     lastUpdated: Optional[datetime] = None
#     passwordChanged: Optional[datetime] = None
#     profile: Optional[UserProfile] = None
#     status: Optional[UserStatus] = None
#     statusChanged: Optional[datetime] = None
#     transitioningToStatus: Optional[UserStatus] = None
#     type: Optional[UserType] = None
#
#
# class UserSchemaBase(BaseModel):
#     id: Optional[str] = None
#     properties: Optional[UserSchemaBaseProperties] = None
#     required: Optional[List[str]] = None
#     type: Optional[str] = None
#
#
# class UserSchemaDefinitions(BaseModel):
#     base: Optional[UserSchemaBase] = None
#     custom: Optional[UserSchemaPublic] = None
#
#
# class AccessPolicyRule(BaseModel):
#     actions: Optional[AccessPolicyRuleActions] = None
#     conditions: Optional[AccessPolicyRuleConditions] = None
#     name: Optional[str] = None
#
#
# class Application(BaseModel):
#     field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_embedded"
#     )
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     accessibility: Optional[ApplicationAccessibility] = None
#     created: Optional[datetime] = None
#     credentials: Optional[ApplicationCredentials] = None
#     features: Optional[List[str]] = None
#     id: Optional[str] = None
#     label: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     licensing: Optional[ApplicationLicensing] = None
#     name: Optional[str] = None
#     profile: Optional[Dict[str, Dict[str, Any]]] = None
#     settings: Optional[ApplicationSettings] = None
#     signOnMode: Optional[ApplicationSignOnMode] = None
#     status: Optional[Status] = None
#     visibility: Optional[ApplicationVisibility] = None
#
#
# class ApplicationFeature(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     capabilities: Optional[CapabilitiesObject] = None
#     description: Optional[str] = None
#     name: Optional[str] = None
#     status: Optional[EnabledStatus] = None
#
#
# class EventHook(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     channel: Optional[EventHookChannel] = None
#     created: Optional[datetime] = None
#     createdBy: Optional[str] = None
#     events: Optional[EventSubscriptions] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     status: Optional[Status1] = None
#     verificationStatus: Optional[VerificationStatus] = None
#
#
# class GroupSchema(BaseModel):
#     field_schema: Optional[str] = Field(None, alias="$schema")
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[str] = None
#     definitions: Optional[GroupSchemaDefinitions] = None
#     description: Optional[str] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[str] = None
#     name: Optional[str] = None
#     properties: Optional[UserSchemaProperties] = None
#     title: Optional[str] = None
#     type: Optional[str] = None
#
#
# class IdentityProvider(BaseModel):
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[datetime] = None
#     id: Optional[str] = None
#     issuerMode: Optional[IssuerMode] = None
#     lastUpdated: Optional[datetime] = None
#     name: Optional[str] = None
#     policy: Optional[IdentityProviderPolicy] = None
#     protocol: Optional[Protocol] = None
#     status: Optional[Status1] = None
#     type: Optional[Type5] = None
#
#
# class MultifactorEnrollmentPolicy(Policy):
#     conditions: Optional[PolicyRuleConditions] = None
#     settings: Optional[MultifactorEnrollmentPolicySettings] = None
#
#
# class OpenIdConnectApplication(BaseModel):
#     credentials: Optional[OAuthApplicationCredentials] = None
#     name: Optional[Any] = "oidc_client"
#     settings: Optional[OpenIdConnectApplicationSettings] = None
#
#
# class UserSchema(BaseModel):
#     field_schema: Optional[str] = Field(None, alias="$schema")
#     field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
#         None, alias="_links"
#     )
#     created: Optional[str] = None
#     definitions: Optional[UserSchemaDefinitions] = None
#     id: Optional[str] = None
#     lastUpdated: Optional[str] = None
#     name: Optional[str] = None
#     properties: Optional[UserSchemaProperties] = None
#     title: Optional[str] = None
#     type: Optional[str] = None
#
#
# class IonField(BaseModel):
#     form: Optional[IonForm] = None
#     label: Optional[str] = None
#     mutable: Optional[bool] = None
#     name: Optional[str] = None
#     required: Optional[bool] = None
#     secret: Optional[bool] = None
#     type: Optional[str] = None
#     value: Optional[Dict[str, Dict[str, Any]]] = None
#     visible: Optional[bool] = None
#
#
# class IonForm(BaseModel):
#     accepts: Optional[str] = None
#     href: Optional[str] = None
#     method: Optional[str] = None
#     name: Optional[str] = None
#     produces: Optional[str] = None
#     refresh: Optional[int] = None
#     rel: Optional[List[str]] = None
#     relatesTo: Optional[List[str]] = None
#     value: Optional[List[IonField]] = None
