from .factor_models import FactorType as FT, SignedNonceFactor
from .factor_models import (
    EmailUserFactor,
    CustomHotpUserFactor,
    PushUserFactor,
    SecurityQuestionUserFactor,
    SmsUserFactor,
    TokenUserFactor,
    HardwareUserFactor,
    TotpUserFactor,
    WebUserFactor,
    WebAuthnUserFactor,
)
from .factor_models import CallUserFactor

OKTA_FACTOR_TYPE_TO_FACTOR = {
    FT.CALL: CallUserFactor,
    FT.EMAIL: EmailUserFactor,
    FT.HOTP: CustomHotpUserFactor,
    FT.PUSH: PushUserFactor,
    FT.QUESTION: SecurityQuestionUserFactor,
    FT.SMS: SmsUserFactor,
    FT.TOKEN: TokenUserFactor,
    FT.TOKEN_HARDWARE: HardwareUserFactor,
    FT.TOKEN_HOTP: CustomHotpUserFactor,
    FT.TOKEN_SOFTWARE_TOTP: TotpUserFactor,
    FT.WEB: WebUserFactor,
    FT.WEBAUTHN: WebAuthnUserFactor,
    FT.SIGNED_NONCE: SignedNonceFactor,
}
