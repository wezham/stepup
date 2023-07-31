import time
from dataclasses import dataclass
from typing import List, Optional, Dict, Type, Callable


from stepup.api.okta.client import Client
from stepup.api.okta.factor_models import (
    FactorType,
    UserFactor,
    PushUserFactor,
    VerifyUserFactorResponse,
    FactorResult,
)

from logging import getLogger

from stepup.api.okta.user_models import User

logger = getLogger(__name__)


@dataclass
class StepUpResult:
    factor_used: Optional[FactorType]
    verification_result: bool
    metadata: Optional[dict]
    message: str


@dataclass
class FactorRanking:
    factor: Type[UserFactor]
    ranking: int


def handle_push_factor(
    okta_client: Client, verification_response: VerifyUserFactorResponse
) -> FactorResult:
    polling_url = verification_response.field_links["poll"]
    while True:
        logger.info("Polling ...")
        poll_result = okta_client.make_request(
            url=polling_url["href"], method="GET"
        )
        result = FactorResult[poll_result["factorResult"]]
        if result is FactorResult.WAITING:
            time.sleep(5)
            continue

    return result


FACTOR_TO_HANDLER_MAPPING: Dict[Type[UserFactor], Callable] = {
    PushUserFactor: handle_push_factor
}


def perform_step_up(
    okta_client: Client,
    user: User,
    preference_ranking: List[FactorRanking],
):
    user_factors = okta_client.list_factors(user_id=user.id)
    if not user_factors:
        logger.error("No factors found for user")
        return StepUpResult(
            factor_used=None,
            verification_result=False,
            metadata=None,
            message="No factors found for user",
        )

    factor_preference_map = {
        factor_.factor: factor_ for factor_ in preference_ranking
    }
    factors_to_try = [
        factor_
        for factor_ in user_factors
        if type(factor_) in factor_preference_map
    ]
    if not factors_to_try:
        logger.error("Factors available are not in the preference ranking")
        return StepUpResult(
            factor_used=None,
            verification_result=False,
            metadata=None,
            message="Factors available are not in the preference ranking",
        )

    sorted_factors_to_try: List[UserFactor] = sorted(
        factors_to_try,
        key=lambda factor_: factor_preference_map[type(factor_)].ranking,
    )
    highest_preference_factor = sorted_factors_to_try[0]
    logger.info(
        f"Attempting to step-up with factor {highest_preference_factor.factorType}",
    )

    verification_response = okta_client.verify_factor(
        user_id=user.id,
        factor_id=highest_preference_factor.id,
        verify_factor_request={},
    )
    factor_handler = FACTOR_TO_HANDLER_MAPPING[type(highest_preference_factor)]
    result = factor_handler(okta_client, verification_response)
    return StepUpResult(
        factor_used=type(highest_preference_factor),
        verification_result=result,
        metadata=None,
        message="Factor check complete",
    )
