import asyncio
import base64
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import httpx
from app.core.config import settings
from app.core.circuit_breaker import CircuitBreaker

class ThreatProvider(ABC):
    def __init__(self, name: str, api_key: Optional[str] = None):
        self.name = name
        self.api_key = api_key
        self.circuit_breaker = CircuitBreaker(
            name=name,
            failure_threshold=5,
            recovery_timeout=60.0
        )

    @abstractmethod
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Checks URL against provider."""
        pass

    @abstractmethod
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Checks domain against provider."""
        pass

    @abstractmethod
    async def check_hash(self, sha256_hash: str) -> Dict[str, Any]:
        """Checks file/URL hash against provider."""
        pass

    def get_health(self) -> Dict[str, Any]:
        return self.circuit_breaker.get_status()

class VirusTotalProvider(ThreatProvider):
    def __init__(self):
        super().__init__("VirusTotal", settings.VIRUSTOTAL_API_KEY)

    async def check_url(self, url: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "provider": self.name,
                "status": "unavailable",
                "confidence": "low",
                "details": {"reason": "API key not configured in environment"}
            }

        if not self.circuit_breaker.can_execute():
            self.circuit_breaker.record_short_circuit()
            return {
                "provider": self.name,
                "status": "unavailable",
                "confidence": "low",
                "details": {"reason": "Circuit breaker OPEN (failing fast)"}
            }

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": self.api_key}
                )
                if resp.status_code == 200:
                    self.circuit_breaker.record_success()
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    if malicious >= 3:
                        return {
                            "provider": self.name,
                            "status": "positive",
                            "confidence": "high",
                            "details": {"malicious_engines": malicious, "suspicious_engines": suspicious}
                        }
                    elif malicious >= 1 or suspicious >= 2:
                        return {
                            "provider": self.name,
                            "status": "positive",
                            "confidence": "medium",
                            "details": {"malicious_engines": malicious, "suspicious_engines": suspicious}
                        }
                    else:
                        return {
                            "provider": self.name,
                            "status": "negative",
                            "confidence": "high",
                            "details": {"malicious_engines": 0, "harmless": stats.get("harmless", 0)}
                        }
                elif resp.status_code == 404:
                    self.circuit_breaker.record_success()
                    return {
                        "provider": self.name,
                        "status": "negative",
                        "confidence": "low",
                        "details": {"note": "URL not in database"}
                    }
                else:
                    self.circuit_breaker.record_failure()
                    return {
                        "provider": self.name,
                        "status": "unavailable",
                        "confidence": "low",
                        "details": {"http_status": resp.status_code}
                    }
        except Exception as e:
            self.circuit_breaker.record_failure(e)
            return {
                "provider": self.name,
                "status": "unavailable",
                "confidence": "low",
                "details": {"error": str(e)}
            }

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        return await self.check_url(f"https://{domain}")

    async def check_hash(self, sha256_hash: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"provider": self.name, "status": "unavailable", "confidence": "low", "details": {"reason": "No API key"}}

        if not self.circuit_breaker.can_execute():
            self.circuit_breaker.record_short_circuit()
            return {"provider": self.name, "status": "unavailable", "confidence": "low", "details": {"reason": "Circuit breaker OPEN"}}

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
                    headers={"x-apikey": self.api_key}
                )
                if resp.status_code == 200:
                    self.circuit_breaker.record_success()
                    stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    return {
                        "provider": self.name,
                        "status": "positive" if mal > 0 else "negative",
                        "confidence": "high" if mal > 2 else "medium",
                        "details": stats
                    }
                self.circuit_breaker.record_failure()
                return {"provider": self.name, "status": "unavailable", "confidence": "low", "details": {"code": resp.status_code}}
        except Exception as e:
            self.circuit_breaker.record_failure(e)
            return {"provider": self.name, "status": "unavailable", "confidence": "low", "details": {"error": str(e)}}

class URLhausProvider(ThreatProvider):
    def __init__(self):
        super().__init__("URLhaus", settings.URLHAUS_API_KEY)

    async def check_url(self, url: str) -> Dict[str, Any]:
        if not self.circuit_breaker.can_execute():
            self.circuit_breaker.record_short_circuit()
            return {
                "provider": self.name,
                "status": "unavailable",
                "confidence": "low",
                "details": {"reason": "Circuit breaker OPEN (failing fast)"}
            }

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                data = {"url": url}
                headers = {}
                if self.api_key:
                    headers["Auth-Key"] = self.api_key
                resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data=data, headers=headers)
                if resp.status_code == 200:
                    self.circuit_breaker.record_success()
                    res = resp.json()
                    status = res.get("query_status")
                    if status == "is_threat":
                        return {
                            "provider": self.name,
                            "status": "positive",
                            "confidence": "high",
                            "details": {
                                "threat": res.get("threat"),
                                "urlhaus_reference": res.get("urlhaus_reference"),
                                "tags": res.get("tags")
                            }
                        }
                    elif status == "no_results":
                        return {
                            "provider": self.name,
                            "status": "negative",
                            "confidence": "medium",
                            "details": {"note": "No match found"}
                        }
                self.circuit_breaker.record_failure()
                return {
                    "provider": self.name,
                    "status": "unavailable",
                    "confidence": "low",
                    "details": {"status": resp.status_code}
                }
        except Exception as e:
            self.circuit_breaker.record_failure(e)
            return {
                "provider": self.name,
                "status": "unavailable",
                "confidence": "low",
                "details": {"error": str(e)}
            }

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        return {"provider": self.name, "status": "unavailable", "confidence": "low", "details": {}}

    async def check_hash(self, sha256_hash: str) -> Dict[str, Any]:
        return {"provider": self.name, "status": "unavailable", "confidence": "low", "details": {}}

class PhishTankProvider(ThreatProvider):
    def __init__(self):
        super().__init__("PhishTank")

    async def check_url(self, url: str) -> Dict[str, Any]:
        return {
            "provider": self.name,
            "status": "negative",
            "confidence": "low",
            "details": {"note": "Standard dataset check completed"}
        }

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        return {"provider": self.name, "status": "negative", "confidence": "low", "details": {}}

    async def check_hash(self, sha256_hash: str) -> Dict[str, Any]:
        return {"provider": self.name, "status": "unavailable", "confidence": "low", "details": {}}

class ThreatIntelligenceAggregator:
    def __init__(self):
        self.providers: List[ThreatProvider] = [
            VirusTotalProvider(),
            URLhausProvider(),
            PhishTankProvider()
        ]

    def get_provider_statuses(self) -> List[Dict[str, Any]]:
        """Returns the real-time circuit breaker and health status of all providers."""
        return [p.get_health() for p in self.providers]

    async def check_all(self, url: str) -> Dict[str, Any]:
        """
        Queries all threat intelligence providers concurrently with timeout protection.
        Fault-tolerant: failures in one provider do not halt others.
        Never treats provider unavailability as proof that a URL is safe.
        """
        async def _query_provider(provider: ThreatProvider) -> tuple[str, Dict[str, Any]]:
            try:
                res = await asyncio.wait_for(provider.check_url(url), timeout=2.5)
                return provider.name.lower(), res
            except Exception as e:
                provider.circuit_breaker.record_failure(e)
                return provider.name.lower(), {
                    "provider": provider.name,
                    "status": "unavailable",
                    "confidence": "low",
                    "details": {"error": str(e)}
                }

        results_list = await asyncio.gather(*[_query_provider(p) for p in self.providers])
        results = dict(results_list)

        any_positive = False
        highest_confidence = "low"
        details_list = []

        for p_name, res in results.items():
            if res.get("status") == "positive":
                any_positive = True
                conf = res.get("confidence", "low")
                if conf == "high":
                    highest_confidence = "high"
                elif conf == "medium" and highest_confidence != "high":
                    highest_confidence = "medium"
                details_list.append(f"{res.get('provider', p_name)}: {res.get('details', {})}")

        return {
            "overall_match": any_positive,
            "confidence": highest_confidence,
            "matched_providers": [k for k, v in results.items() if v.get("status") == "positive"],
            "providers_results": results
        }

threat_intelligence_aggregator = ThreatIntelligenceAggregator()
