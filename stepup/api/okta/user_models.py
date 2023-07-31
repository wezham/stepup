from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, SecretStr


class UserType(BaseModel):
    field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, alias="_links"
    )
    created: Optional[datetime] = None
    createdBy: Optional[str] = None
    default: Optional[bool] = None
    description: Optional[str] = None
    displayName: Optional[str] = None
    id: Optional[str] = None
    lastUpdated: Optional[datetime] = None
    lastUpdatedBy: Optional[str] = None
    name: Optional[str] = None


class UserStatus(Enum):
    ACTIVE = "ACTIVE"
    DEPROVISIONED = "DEPROVISIONED"
    LOCKED_OUT = "LOCKED_OUT"
    PASSWORD_EXPIRED = "PASSWORD_EXPIRED"
    PROVISIONED = "PROVISIONED"
    RECOVERY = "RECOVERY"
    STAGED = "STAGED"
    SUSPENDED = "SUSPENDED"


class UserProfile(BaseModel):
    city: Optional[str] = None
    costCenter: Optional[str] = None
    countryCode: Optional[str] = None
    department: Optional[str] = None
    displayName: Optional[str] = None
    division: Optional[str] = None
    email: Optional[str] = None
    employeeNumber: Optional[str] = None
    firstName: Optional[str] = None
    honorificPrefix: Optional[str] = None
    honorificSuffix: Optional[str] = None
    lastName: Optional[str] = None
    locale: Optional[str] = None
    login: Optional[str] = None
    manager: Optional[str] = None
    managerId: Optional[str] = None
    middleName: Optional[str] = None
    mobilePhone: Optional[str] = None
    nickName: Optional[str] = None
    organization: Optional[str] = None
    postalAddress: Optional[str] = None
    preferredLanguage: Optional[str] = None
    primaryPhone: Optional[str] = None
    profileUrl: Optional[str] = None
    secondEmail: Optional[str] = None
    state: Optional[str] = None
    streetAddress: Optional[str] = None
    timezone: Optional[str] = None
    title: Optional[str] = None
    userType: Optional[str] = None
    zipCode: Optional[str] = None


class RecoveryQuestionCredential(BaseModel):
    answer: Optional[str] = None
    question: Optional[str] = None


class PasswordCredentialHashAlgorithm(Enum):
    BCRYPT = "BCRYPT"
    SHA_512 = "SHA-512"
    SHA_256 = "SHA-256"
    SHA_1 = "SHA-1"
    MD5 = "MD5"


class PasswordCredentialHash(BaseModel):
    algorithm: Optional[PasswordCredentialHashAlgorithm] = None
    salt: Optional[str] = None
    saltOrder: Optional[str] = None
    value: Optional[str] = None
    workFactor: Optional[int] = None


class PasswordCredentialHook(BaseModel):
    type: Optional[str] = None


class PasswordCredential(BaseModel):
    hash: Optional[PasswordCredentialHash] = None
    hook: Optional[PasswordCredentialHook] = None
    value: Optional[SecretStr] = None


class AuthenticationProviderType(Enum):
    ACTIVE_DIRECTORY = "ACTIVE_DIRECTORY"
    FEDERATION = "FEDERATION"
    LDAP = "LDAP"
    OKTA = "OKTA"
    SOCIAL = "SOCIAL"
    IMPORT = "IMPORT"


class AuthenticationProvider(BaseModel):
    name: Optional[str] = None
    type: Optional[AuthenticationProviderType] = None


class UserCredentials(BaseModel):
    password: Optional[PasswordCredential] = None
    provider: Optional[AuthenticationProvider] = None
    recovery_question: Optional[RecoveryQuestionCredential] = None


class User(BaseModel):
    field_embedded: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, alias="_embedded"
    )
    field_links: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, alias="_links"
    )
    activated: Optional[datetime] = None
    created: Optional[datetime] = None
    credentials: Optional[UserCredentials] = None
    id: Optional[str] = None
    lastLogin: Optional[datetime] = None
    lastUpdated: Optional[datetime] = None
    passwordChanged: Optional[datetime] = None
    profile: Optional[UserProfile] = None
    status: Optional[UserStatus] = None
    statusChanged: Optional[datetime] = None
    transitioningToStatus: Optional[UserStatus] = None
    type: Optional[UserType] = None
