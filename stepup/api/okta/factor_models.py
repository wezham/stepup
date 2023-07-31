from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from aenum import MultiValueEnum
from pydantic import BaseModel, Field


class FactorProvider(Enum):
    OKTA = "OKTA"
    RSA = "RSA"
    FIDO = "FIDO"
    GOOGLE = "GOOGLE"
    SYMANTEC = "SYMANTEC"
    DUO = "DUO"
    YUBICO = "YUBICO"
    CUSTOM = "CUSTOM"
    APPLE = "APPLE"


class FactorResultType(Enum):
    SUCCESS = "SUCCESS"
    CHALLENGE = "CHALLENGE"
    WAITING = "WAITING"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    TIMEOUT = "TIMEOUT"
    TIME_WINDOW_EXCEEDED = "TIME_WINDOW_EXCEEDED"
    PASSCODE_REPLAYED = "PASSCODE_REPLAYED"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"


class FactorResult(Enum):
    SUCCESS = "SUCCESS"
    EXPIRED = "EXPIRED"
    CHALLENGE = "CHALLENGE"
    WAITING = "WAITING"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    TIMEOUT = "TIMEOUT"
    TIME_WINDOW_EXCEEDED = "TIME_WINDOW_EXCEEDED"
    PASSCODE_REPLAYED = "PASSCODE_REPLAYED"
    ERROR = "ERROR"


class FactorStatus(Enum):
    PENDING_ACTIVATION = "PENDING_ACTIVATION"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    NOT_SETUP = "NOT_SETUP"
    ENROLLED = "ENROLLED"
    DISABLED = "DISABLED"
    EXPIRED = "EXPIRED"


class FactorType(str, MultiValueEnum):
    """
    An enumeration class for FactorType.
    """

    CALL = "call", "CALL"
    EMAIL = "email", "EMAIL"
    HOTP = "hotp", "HOTP"
    PUSH = "push", "PUSH"
    QUESTION = "question", "QUESTION"
    SMS = "sms", "SMS"
    TOKEN_HARDWARE = "token:hardware", "TOKEN:HARDWARE"
    TOKEN_HOTP = "token:hotp", "TOKEN:HOTP"
    TOKEN_SOFTWARE_TOTP = "token:software:totp", "TOKEN:SOFTWARE:TOTP"
    TOKEN = "token", "TOKEN"
    U_2_F = "u2f", "U2F"
    WEB = "web", "WEB"
    WEBAUTHN = "webauthn", "WEBAUTHN"
    SIGNED_NONCE = "signed_nonce", "SIGNED_NONCE"


class VerifyFactorRequest(BaseModel):
    activationToken: Optional[str] = None
    answer: Optional[str] = None
    attestation: Optional[str] = None
    clientData: Optional[str] = None
    nextPassCode: Optional[str] = None
    passCode: Optional[str] = None
    registrationData: Optional[str] = None
    stateToken: Optional[str] = None


class UserFactor(BaseModel):
    field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, alias="_embedded"
    )
    field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, alias="_links"
    )
    created: Optional[datetime] = None
    factorType: Optional[FactorType] = None
    id: Optional[str] = None
    lastUpdated: Optional[datetime] = None
    provider: Optional[FactorProvider] = None
    status: Optional[FactorStatus] = None
    verify: Optional[VerifyFactorRequest] = None


class EmailUserFactorProfile(BaseModel):
    email: Optional[str] = None


class HardwareUserFactorProfile(BaseModel):
    credentialId: Optional[str] = None


class Type5(Enum):
    SAML2 = "SAML2"
    GOOGLE = "GOOGLE"
    FACEBOOK = "FACEBOOK"
    LINKEDIN = "LINKEDIN"


class PushUserFactorProfile(BaseModel):
    credentialId: Optional[str] = None
    deviceToken: Optional[str] = None
    deviceType: Optional[str] = None
    name: Optional[str] = None
    platform: Optional[str] = None
    version: Optional[str] = None


class SecurityQuestion(BaseModel):
    answer: Optional[str] = None
    question: Optional[str] = None
    questionText: Optional[str] = None


class SecurityQuestionUserFactorProfile(BaseModel):
    answer: Optional[str] = None
    question: Optional[str] = None
    questionText: Optional[str] = None


class SmsUserFactorProfile(BaseModel):
    phoneNumber: Optional[str] = None


class TokenUserFactorProfile(BaseModel):
    credentialId: Optional[str] = None


class TotpUserFactorProfile(BaseModel):
    credentialId: Optional[str] = None


class U2fUserFactorProfile(BaseModel):
    credentialId: Optional[str] = None


class UserActivationToken(BaseModel):
    activationToken: Optional[str] = None
    activationUrl: Optional[str] = None


class WebAuthnUserFactorProfile(BaseModel):
    authenticatorName: Optional[str] = None
    credentialId: Optional[str] = None


class WebUserFactorProfile(BaseModel):
    credentialId: Optional[str] = None


class SignedNonceFactorProfile(BaseModel):
    credentialId: Optional[str] = None
    deviceToken: Optional[str] = None
    deviceType: Optional[str] = None
    name: Optional[str] = None
    platform: Optional[str] = None
    version: Optional[str] = None


class CustomHotpUserFactorProfile(BaseModel):
    sharedSecret: Optional[str] = None


class PushUserFactor(UserFactor):
    expiresAt: Optional[datetime] = None
    factorResult: Optional[FactorResultType] = None
    profile: Optional[PushUserFactorProfile] = None


class CustomHotpUserFactor(UserFactor):
    factorProfileId: Optional[str] = None
    profile: Optional[CustomHotpUserFactorProfile] = None


class EmailUserFactor(UserFactor):
    profile: Optional[EmailUserFactorProfile] = None


class CallUserFactorProfile(BaseModel):
    phoneExtension: Optional[str] = None
    phoneNumber: Optional[str] = None


class SecurityQuestionUserFactor(UserFactor):
    profile: Optional[SecurityQuestionUserFactorProfile] = None


class SmsUserFactor(UserFactor):
    profile: Optional[SmsUserFactorProfile] = None


class TokenUserFactor(UserFactor):
    profile: Optional[TokenUserFactorProfile] = None


class TotpUserFactor(UserFactor):
    profile: Optional[TotpUserFactorProfile] = None


class U2fUserFactor(UserFactor):
    profile: Optional[U2fUserFactorProfile] = None


class WebAuthnUserFactor(UserFactor):
    profile: Optional[WebAuthnUserFactorProfile] = None


class WebUserFactor(UserFactor):
    profile: Optional[WebUserFactorProfile] = None


class SignedNonceFactor(UserFactor):
    expiresAt: Optional[datetime] = None
    factorResult: Optional[FactorResultType] = None
    profile: Optional[SignedNonceFactorProfile] = None


class CallUserFactor(UserFactor):
    profile: Optional[CallUserFactorProfile] = None


class HardwareUserFactor(UserFactor):
    profile: Optional[HardwareUserFactorProfile] = None


class VerifyUserFactorResponse(BaseModel):
    field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, alias="_embedded"
    )
    field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, alias="_links"
    )
    expiresAt: Optional[datetime] = None
    factorResult: Optional[FactorResult] = None
    factorResultMessage: Optional[str] = None


class FactorVerifyResult(BaseModel):
    field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, alias="_embedded"
    )
    field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, alias="_links"
    )
    expiresAt: Optional[datetime] = None
    factorResult: Optional[FactorResult] = None
    factorResultMessage: Optional[str] = None
