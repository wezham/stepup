from typing import Dict, List, Optional, Union

import requests

from stepup.api.okta.constants import OKTA_FACTOR_TYPE_TO_FACTOR
from stepup.api.okta.factor_models import UserFactor, VerifyUserFactorResponse
from stepup.api.okta.user_models import User


class Client:
    def __init__(self, okta_tenant_domain: str, api_token: str):
        self.api_token = api_token
        self.okta_tenant_domain = okta_tenant_domain

    def headers(self) -> dict:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"SSWS {self.api_token}",
        }

    def make_request(
        self,
        method: str,
        data: dict = None,
        endpoint: Optional[str] = None,
        url: Optional[str] = None,
    ) -> Optional[Union[Dict, List[Dict]]]:
        full_url = url or f"https://{self.okta_tenant_domain}/api/v1{endpoint}"
        response = requests.request(
            method, full_url, headers=self.headers(), json=data
        )
        if 200 <= response.status_code <= 299:
            return response.json()
        else:
            return response.json()

    def list_factors(self, user_id: str) -> List[UserFactor]:
        url = f"/users/{user_id}/factors"
        result = self.make_request(endpoint=url, method="GET")

        if result:
            return [
                OKTA_FACTOR_TYPE_TO_FACTOR[factor.get("factorType")](**factor)
                for factor in result
            ]

    def verify_factor(
        self, user_id: str, factor_id: str, verify_factor_request
    ) -> Optional[VerifyUserFactorResponse]:
        url = f"/users/{user_id}/factors/{factor_id}/verify"
        result = self.make_request(
            endpoint=url, method="POST", data=verify_factor_request
        )
        if result:
            return VerifyUserFactorResponse(**result)

    def get_user(self, user_id: str) -> Optional[User]:
        url = f"/users/{user_id}"
        result = self.make_request(endpoint=url, method="GET")
        if result:
            return User(**result)
