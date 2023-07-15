import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Set, Dict, Type, Callable

from okta.client import Client
from okta.models import (
    FactorType,
    UserFactor,
    SmsUserFactor,
    EmailUserFactor,
    PushUserFactor,
    U2FUserFactor,
    CallUserFactor,
)
from okta.models import VerifyFactorRequest, VerifyUserFactorResponse, User

from logging import getLogger

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


async def handle_push_factor(
    okta_client: Client, verification_response: VerifyUserFactorResponse
) -> bool:
    polling_url = verification_response.links["poll"]
    while True:
        request, error = okta_client.get_request_executor().create_request(
            method="GET", url=polling_url
        )
        response, error = await okta_client.get_request_executor().execute(
            request, None
        )
        if response["factorResult"] == "WAITING":
            await asyncio.sleep(5)
        elif response["factorResult"] == "SUCCESS":
            result = True
            break
        else:
            result = True
            break

    return result


LINK_MAPPING: Dict[Type[UserFactor], Callable] = {
    PushUserFactor: handle_push_factor
}


async def perform_step_up(
    okta_client: Client, user: User, preference_ranking: List[FactorRanking]
):
    user_factors = await okta_client.list_factors(userId=user.id)
    if not user_factors:
        logger.error("No factors found for user", user=user.id)
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

    sorted_factors_to_try: List[FactorType] = sorted(
        factors_to_try, key=lambda factor_: factor_.ranking
    )
    highest_preference_factor = sorted_factors_to_try[0]
    logger.info(
        "Attempting to step-up with factor",
        factor=highest_preference_factor,
    )

    verification_response = await okta_client.verify_factor(
        userId=user.id,
        factorId=highest_preference_factor.id,
        verify_factor_request={},
    )

    factor_handler = LINK_MAPPING[type(highest_preference_factor)]
    result = factor_handler(okta_client, verification_response)
    logger.info("result")
