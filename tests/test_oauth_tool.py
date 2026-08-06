import base64
import hashlib
import json
import threading
import unittest
import uuid
from unittest.mock import MagicMock, patch

from tests._import_app import clear_login_attempts, import_web_app_module


class OAuthToolTestBase(unittest.TestCase):
    """OAuth Token 工具测试基类 — 所有子类共享"""

    @classmethod
    def setUpClass(cls):
        cls.module = import_web_app_module()
        cls.app = cls.module.app

    def setUp(self):
        with self.app.app_context():
            clear_login_attempts()
            from outlook_web.db import get_db

            db = get_db()
            db.execute("DELETE FROM settings WHERE key LIKE 'oauth_tool_%'")
            db.execute("DELETE FROM account_claim_logs")
            db.execute("DELETE FROM account_project_usage")
            db.execute("DELETE FROM account_refresh_logs")
            db.execute("DELETE FROM accounts")
            db.commit()

        from outlook_web.services import oauth_tool as oauth_tool_service

        oauth_tool_service.OAUTH_FLOW_STORE.clear()

    def _login(self, client, password="testpass123"):
        resp = client.post("/login", json={"password": password})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json().get("success"))
        return resp

    def _save_oauth_config(self, client, **overrides):
        payload = {
            "client_id": "test-client-id-000",
            "client_secret": "",
            "scope": "offline_access https://outlook.office.com/IMAP.AccessAsUser.All",
            "redirect_uri": "http://localhost:5000/token-tool/callback",
            "tenant": "consumers",
            "prompt_consent": False,
            **overrides,
        }
        return client.post("/api/token-tool/config", json=payload)

    def _insert_test_account(
        self,
        email="user@oauth-test.com",
        client_id="old-client-id",
        refresh_token="old-rt",
    ):
        with self.app.app_context():
            from outlook_web.repositories import accounts as accounts_repo

            accounts_repo.add_account(
                email_addr=email,
                password="",
                client_id=client_id,
                refresh_token=refresh_token,
                group_id=1,
                remark="oauth-test",
            )
            acc = accounts_repo.get_account_by_email(email)
            return acc["id"] if acc else None

    @staticmethod
    def _mock_microsoft_token_response(
        access_token="mock-at",
        refresh_token="mock-new-rt",
        expires_in=3600,
        scope="offline_access https://graph.microsoft.com/.default",
    ):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_in,
            "scope": scope,
            "token_type": "Bearer",
        }
        return resp

    @staticmethod
    def _mock_microsoft_error_response(error="invalid_grant", description="Token expired"):
        resp = MagicMock()
        resp.status_code = 400
        resp.json.return_value = {
            "error": error,
            "error_description": description,
        }
        resp.text = json.dumps(resp.json.return_value)
        return resp

    @staticmethod
    def _build_jwt(payload_data):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=").decode()
        return f"{header}.{payload}.fake-signature"


class OAuthToolPkceTests(OAuthToolTestBase):
    def test_generate_pkce_verifier_length(self):
        from outlook_web.services.oauth_tool import generate_pkce

        verifier, _challenge = generate_pkce()
        self.assertGreaterEqual(len(verifier), 43)
        self.assertLessEqual(len(verifier), 128)

    def test_generate_pkce_verifier_charset(self):
        import re

        from outlook_web.services.oauth_tool import generate_pkce

        verifier, _challenge = generate_pkce()
        self.assertRegex(verifier, re.compile(r"^[A-Za-z0-9\-._~]+$"))

    def test_generate_pkce_challenge_is_s256(self):
        from outlook_web.services.oauth_tool import generate_pkce

        verifier, challenge = generate_pkce()
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        self.assertEqual(challenge, expected)

    def test_generate_pkce_uniqueness(self):
        from outlook_web.services.oauth_tool import generate_pkce

        verifier1, _challenge1 = generate_pkce()
        verifier2, _challenge2 = generate_pkce()
        self.assertNotEqual(verifier1, verifier2)


class OAuthToolScopeTests(OAuthToolTestBase):
    def test_validate_scope_graph_default_ok(self):
        from outlook_web.services.oauth_tool import validate_scope

        normalized, error = validate_scope("offline_access https://graph.microsoft.com/.default")
        self.assertIsNone(error)
        self.assertEqual(
            set(normalized.split()),
            {"offline_access", "https://graph.microsoft.com/.default"},
        )

    def test_validate_scope_imap_ok(self):
        from outlook_web.services.oauth_tool import validate_scope

        normalized, error = validate_scope("offline_access https://outlook.office.com/IMAP.AccessAsUser.All")
        self.assertIsNone(error)
        self.assertEqual(
            set(normalized.split()),
            {"offline_access", "https://outlook.office.com/IMAP.AccessAsUser.All"},
        )

    def test_validate_scope_no_api_scope(self):
        from outlook_web.services.oauth_tool import validate_scope

        normalized, error = validate_scope("offline_access")
        self.assertEqual(normalized, "offline_access")
        self.assertIsNotNone(error)
        self.assertIn("至少需要一个 API scope", error)

    def test_validate_scope_mixed_default_and_named(self):
        from outlook_web.services.oauth_tool import validate_scope

        normalized, error = validate_scope("https://graph.microsoft.com/.default https://graph.microsoft.com/Mail.Read")
        self.assertIn("https://graph.microsoft.com/.default", normalized)
        self.assertIsNotNone(error)
        self.assertIn("不能和命名 scope 混用", error)

    def test_validate_scope_cross_resource(self):
        from outlook_web.services.oauth_tool import validate_scope

        _normalized, error = validate_scope(
            "https://graph.microsoft.com/Mail.Read https://outlook.office.com/IMAP.AccessAsUser.All"
        )
        self.assertIsNotNone(error)
        self.assertIn("一个资源", error)

    def test_normalize_scope_auto_adds_offline_access(self):
        from outlook_web.services.oauth_tool import normalize_scope

        result = normalize_scope("https://graph.microsoft.com/.default")
        self.assertIn("offline_access", result.split())
        self.assertIn("https://graph.microsoft.com/.default", result.split())

    def test_normalize_scope_no_duplicate(self):
        from outlook_web.services.oauth_tool import normalize_scope

        result = normalize_scope("offline_access offline_access https://graph.microsoft.com/.default")
        self.assertEqual(result.split().count("offline_access"), 1)


class OAuthToolFlowStoreTests(OAuthToolTestBase):
    def test_flow_store_crud(self):
        from outlook_web.services.oauth_tool import (
            discard_oauth_flow,
            get_oauth_flow,
            store_oauth_flow,
        )

        state = "test-state-" + uuid.uuid4().hex
        flow_data = {"verifier": "abc", "scope": "test"}
        store_oauth_flow(state, flow_data)
        result = get_oauth_flow(state)
        self.assertIsNotNone(result)
        self.assertEqual(result["verifier"], "abc")
        self.assertEqual(result["scope"], "test")
        self.assertIn("created_at", result)
        discard_oauth_flow(state)
        self.assertIsNone(get_oauth_flow(state))

    @patch("outlook_web.services.oauth_tool.time.time")
    def test_flow_store_ttl_not_expired(self, mock_time):
        from outlook_web.services.oauth_tool import get_oauth_flow, store_oauth_flow

        state = "ttl-ok-" + uuid.uuid4().hex
        mock_time.return_value = 1000.0
        store_oauth_flow(state, {"verifier": "x"})
        mock_time.return_value = 1000.0 + 60
        self.assertIsNotNone(get_oauth_flow(state))

    @patch("outlook_web.services.oauth_tool.time.time")
    def test_flow_store_ttl_expired(self, mock_time):
        from outlook_web.services.oauth_tool import get_oauth_flow, store_oauth_flow

        state = "ttl-expired-" + uuid.uuid4().hex
        mock_time.return_value = 1000.0
        store_oauth_flow(state, {"verifier": "x"})
        mock_time.return_value = 1000.0 + 1260
        self.assertIsNone(get_oauth_flow(state))

    @patch("outlook_web.services.oauth_tool.time.time")
    def test_flow_store_cleanup_removes_expired_only(self, mock_time):
        from outlook_web.services import oauth_tool as oauth_tool_service

        mock_time.return_value = 1000.0
        oauth_tool_service.store_oauth_flow("expired", {"verifier": "old"})
        mock_time.return_value = 1500.0
        oauth_tool_service.store_oauth_flow("fresh", {"verifier": "new"})
        mock_time.return_value = 1000.0 + oauth_tool_service.OAUTH_FLOW_TTL + 1
        fresh = oauth_tool_service.get_oauth_flow("fresh")
        expired = oauth_tool_service.get_oauth_flow("expired")
        self.assertIsNotNone(fresh)
        self.assertIsNone(expired)

    def test_flow_store_thread_safety(self):
        from outlook_web.services.oauth_tool import get_oauth_flow, store_oauth_flow

        results = {}
        errors = []

        def writer(i):
            try:
                key = f"thread-{i}-{uuid.uuid4().hex}"
                store_oauth_flow(key, {"i": i})
                val = get_oauth_flow(key)
                results[i] = val
            except Exception as exc:  # pragma: no cover - 仅作为断言收集
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(len(errors), 0, f"线程安全错误: {errors}")
        self.assertEqual(len(results), 20)
        for index, value in results.items():
            self.assertEqual(value["i"], index)

    def test_flow_store_get_nonexistent_key(self):
        from outlook_web.services.oauth_tool import get_oauth_flow

        self.assertIsNone(get_oauth_flow("missing-" + uuid.uuid4().hex))


class OAuthToolErrorGuidanceTests(OAuthToolTestBase):
    def test_map_unauthorized_client(self):
        from outlook_web.services.oauth_tool import map_error_guidance

        guidance = map_error_guidance("unauthorized_client")
        self.assertIsInstance(guidance, str)
        self.assertIn("个人 Microsoft 账号", guidance)
        self.assertIn("公共客户端流", guidance)

    def test_map_invalid_client(self):
        from outlook_web.services.oauth_tool import map_error_guidance

        guidance = map_error_guidance("invalid_client")
        self.assertIsInstance(guidance, str)
        self.assertIn("client_secret", guidance)
        self.assertIn("公共客户端流", guidance)
        self.assertIn("http://localhost", guidance)

    def test_map_invalid_grant(self):
        from outlook_web.services.oauth_tool import map_error_guidance

        guidance = map_error_guidance("AADSTS70000: invalid_grant")
        self.assertIn("授权码已过期", guidance)

    def test_map_invalid_scope(self):
        from outlook_web.services.oauth_tool import map_error_guidance

        guidance = map_error_guidance("invalid_scope")
        self.assertIn("API 权限", guidance)

    def test_map_unknown_error(self):
        from outlook_web.services.oauth_tool import map_error_guidance

        guidance = map_error_guidance("completely_unknown_xyz")
        self.assertIsInstance(guidance, str)
        self.assertTrue(len(guidance) > 0)


class OAuthToolJwtDecodeTests(OAuthToolTestBase):
    def test_decode_jwt_extracts_fields(self):
        from outlook_web.services.oauth_tool import decode_jwt_payload

        token = self._build_jwt(
            {
                "aud": "https://graph.microsoft.com",
                "scp": "Mail.Read",
                "exp": 9999999999,
            }
        )
        result = decode_jwt_payload(token)
        self.assertEqual(result.get("aud"), "https://graph.microsoft.com")
        self.assertEqual(result.get("scp"), "Mail.Read")

    def test_decode_jwt_invalid_format(self):
        from outlook_web.services.oauth_tool import decode_jwt_payload

        result = decode_jwt_payload("not-a-jwt")
        self.assertIsNone(result)

    def test_decode_jwt_missing_padding(self):
        from outlook_web.services.oauth_tool import decode_jwt_payload

        token = self._build_jwt({"aud": "https://outlook.office.com", "scp": "IMAP.AccessAsUser.All"})
        result = decode_jwt_payload(token)
        self.assertEqual(result.get("aud"), "https://outlook.office.com")
        self.assertEqual(result.get("scp"), "IMAP.AccessAsUser.All")


class OAuthToolTokenExchangeTests(OAuthToolTestBase):
    @patch("outlook_web.services.oauth_tool.requests.post")
    def test_exchange_token_success(self, mock_post):
        from outlook_web.services.oauth_tool import exchange_code_for_tokens

        mock_post.return_value = self._mock_microsoft_token_response()
        result, error = exchange_code_for_tokens(
            code="mock-auth-code",
            oauth_config={
                "client_id": "test-cid",
                "client_secret": "",
                "redirect_uri": "http://localhost:5000/token-tool/callback",
                "scope": "offline_access https://graph.microsoft.com/.default",
                "tenant": "common",
            },
            verifier="test-verifier",
        )
        self.assertIsNone(error)
        self.assertEqual(result["refresh_token"], "mock-new-rt")
        self.assertEqual(result["access_token"], "mock-at")
        self.assertEqual(result["client_id"], "test-cid")

    @patch("outlook_web.services.oauth_tool.requests.post")
    def test_exchange_token_invalid_grant(self, mock_post):
        from outlook_web.services.oauth_tool import exchange_code_for_tokens

        mock_post.return_value = self._mock_microsoft_error_response(
            "invalid_grant",
            "AADSTS70000: The provided value for the input parameter 'code' is not valid.",
        )
        result, error = exchange_code_for_tokens(
            code="bad-code",
            oauth_config={
                "client_id": "cid",
                "client_secret": "",
                "redirect_uri": "http://localhost:5000/token-tool/callback",
                "scope": "offline_access https://graph.microsoft.com/.default",
                "tenant": "common",
            },
            verifier="v",
        )
        self.assertIsNone(result)
        self.assertIn("AADSTS70000", error["message"])
        self.assertIn("授权码已过期", error["guidance"])

    @patch("outlook_web.services.oauth_tool.requests.post")
    def test_exchange_token_network_timeout(self, mock_post):
        import requests as real_requests

        from outlook_web.services.oauth_tool import exchange_code_for_tokens

        mock_post.side_effect = real_requests.exceptions.Timeout("Connection timed out")
        result, error = exchange_code_for_tokens(
            code="mock-auth-code",
            oauth_config={
                "client_id": "cid",
                "client_secret": "",
                "redirect_uri": "http://localhost:5000/token-tool/callback",
                "scope": "offline_access https://graph.microsoft.com/.default",
                "tenant": "common",
            },
            verifier="v",
        )
        self.assertIsNone(result)
        self.assertIn("无法连接 Microsoft 服务器", error)

    @patch("outlook_web.services.oauth_tool.requests.post")
    def test_exchange_token_includes_client_secret_when_provided(self, mock_post):
        from outlook_web.services.oauth_tool import exchange_code_for_tokens

        mock_post.return_value = self._mock_microsoft_token_response()
        result, error = exchange_code_for_tokens(
            code="mock-auth-code",
            oauth_config={
                "client_id": "cid",
                "client_secret": "super-secret",
                "redirect_uri": "http://localhost:5000/token-tool/callback",
                "scope": "offline_access https://graph.microsoft.com/.default",
                "tenant": "organizations",
            },
            verifier="verifier-123",
        )
        self.assertIsNone(error)
        self.assertEqual(result["refresh_token"], "mock-new-rt")
        self.assertEqual(mock_post.call_args.kwargs["data"]["client_secret"], "super-secret")
        self.assertEqual(
            mock_post.call_args.args[0],
            "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
        )

    @patch("outlook_web.services.oauth_tool.requests.post")
    def test_exchange_token_extracts_jwt_claims(self, mock_post):
        from outlook_web.services.oauth_tool import exchange_code_for_tokens

        access_token = self._build_jwt(
            {
                "aud": "https://graph.microsoft.com",
                "scp": "Mail.Read User.Read",
                "roles": ["Mail.Send"],
            }
        )
        mock_post.return_value = self._mock_microsoft_token_response(access_token=access_token)
        result, error = exchange_code_for_tokens(
            code="mock-auth-code",
            oauth_config={
                "client_id": "cid",
                "client_secret": "",
                "redirect_uri": "http://localhost:5000/token-tool/callback",
                "scope": "offline_access https://graph.microsoft.com/.default",
                "tenant": "common",
            },
            verifier="verifier-123",
        )
        self.assertIsNone(error)
        self.assertEqual(result["audience"], "https://graph.microsoft.com")
        self.assertEqual(result["scope_claim"], "Mail.Read User.Read")
        self.assertEqual(result["roles_claim"], "Mail.Send")


class OAuthToolApiPrepareTests(OAuthToolTestBase):
    def test_prepare_returns_auth_url(self):
        from urllib.parse import parse_qs, urlparse

        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "test-cid",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data.get("success"))
            authorize_url = data.get("data", {}).get("authorize_url", "")
            self.assertIn("code_challenge=", authorize_url)
            self.assertIn("response_type=code", authorize_url)
            qs = parse_qs(urlparse(authorize_url).query)
            self.assertTrue(qs.get("state", [""])[0])

    def test_prepare_invalid_scope_rejected(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "cid",
                    "tenant": "consumers",
                    "scope": "https://graph.microsoft.com/.default https://graph.microsoft.com/Mail.Read",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            self.assertEqual(resp.status_code, 400)
            data = resp.get_json()
            self.assertEqual(data.get("code"), "OAUTH_CONFIG_INVALID")

    def test_prepare_rejects_client_secret_in_compat_mode(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "cid",
                    "client_secret": "super-secret",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("不支持 Client Secret", resp.get_json().get("message", ""))

    def test_prepare_rejects_non_consumers_tenant(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "cid",
                    "tenant": "common",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("tenant=consumers", resp.get_json().get("message", ""))

    def test_prepare_missing_client_id(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(resp.get_json().get("code"), "OAUTH_CONFIG_INVALID")

    def test_prepare_requires_login(self):
        with self.app.test_client() as client:
            resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "cid",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            self.assertEqual(resp.status_code, 401)

    def test_prepare_stores_flow(self):
        from urllib.parse import parse_qs, urlparse

        from outlook_web.services import oauth_tool as oauth_tool_service

        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "test-cid",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            authorize_url = resp.get_json().get("data", {}).get("authorize_url", "")
            state = parse_qs(urlparse(authorize_url).query).get("state", [""])[0]
            self.assertIsNotNone(oauth_tool_service.get_oauth_flow(state))


class OAuthToolApiExchangeTests(OAuthToolTestBase):
    @patch("outlook_web.services.oauth_tool.requests.post")
    def test_exchange_success(self, mock_post):
        from urllib.parse import parse_qs, urlparse

        mock_post.return_value = self._mock_microsoft_token_response()
        with self.app.test_client() as client:
            self._login(client)
            prep_resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "cid",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            authorize_url = prep_resp.get_json().get("data", {}).get("authorize_url", "")
            state = parse_qs(urlparse(authorize_url).query).get("state", [""])[0]
            exch_resp = client.post(
                "/api/token-tool/exchange",
                json={
                    "callback_url": f"http://localhost:5000/token-tool/callback?code=mock-auth-code&state={state}",
                },
            )
            self.assertEqual(exch_resp.status_code, 200)
            data = exch_resp.get_json()
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("data", {}).get("refresh_token"), "mock-new-rt")

    def test_exchange_missing_state(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/exchange",
                json={
                    "callback_url": "http://localhost:5000/token-tool/callback?code=some-code",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(resp.get_json().get("code"), "OAUTH_CODE_PARSE_FAILED")

    def test_exchange_state_mismatch(self):
        from urllib.parse import parse_qs, urlparse

        with self.app.test_client() as client:
            self._login(client)
            prep_resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "cid",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            authorize_url = prep_resp.get_json().get("data", {}).get("authorize_url", "")
            original_state = parse_qs(urlparse(authorize_url).query).get("state", [""])[0]
            self.assertTrue(original_state)

            resp = client.post(
                "/api/token-tool/exchange",
                json={
                    "callback_url": "http://localhost:5000/token-tool/callback?code=some-code&state=other-state",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(resp.get_json().get("code"), "OAUTH_MICROSOFT_AUTH_FAILED")

    def test_exchange_expired_flow(self):
        from urllib.parse import parse_qs, urlparse

        from outlook_web.services import oauth_tool as oauth_tool_service

        with self.app.test_client() as client:
            self._login(client)
            prep_resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "cid",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            authorize_url = prep_resp.get_json().get("data", {}).get("authorize_url", "")
            state = parse_qs(urlparse(authorize_url).query).get("state", [""])[0]
            oauth_tool_service.discard_oauth_flow(state)
            resp = client.post(
                "/api/token-tool/exchange",
                json={
                    "callback_url": f"http://localhost:5000/token-tool/callback?code=some-code&state={state}",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(resp.get_json().get("code"), "OAUTH_CODE_INVALID")

    def test_exchange_missing_code(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/exchange",
                json={
                    "callback_url": "http://localhost:5000/token-tool/callback?state=some-state",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(resp.get_json().get("code"), "OAUTH_CODE_PARSE_FAILED")

    def test_exchange_requires_login(self):
        with self.app.test_client() as client:
            resp = client.post(
                "/api/token-tool/exchange",
                json={
                    "callback_url": "http://localhost:5000/token-tool/callback?code=some-code&state=some-state",
                },
            )
            self.assertEqual(resp.status_code, 401)


class OAuthToolApiConfigTests(OAuthToolTestBase):
    def test_config_save_and_load(self):
        with self.app.test_client() as client:
            self._login(client)
            save_resp = self._save_oauth_config(client, client_id="my-cid-123")
            self.assertEqual(save_resp.status_code, 200)
            load_resp = client.get("/api/token-tool/config")
            self.assertEqual(load_resp.status_code, 200)
            data = load_resp.get_json()
            self.assertEqual(data.get("data", {}).get("client_id"), "my-cid-123")
            self.assertEqual(data.get("data", {}).get("client_secret"), "")
            self.assertEqual(data.get("data", {}).get("tenant"), "consumers")

    def test_config_save_rejects_client_secret(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = self._save_oauth_config(client, client_secret="super-secret-value")
            self.assertEqual(resp.status_code, 400)
            self.assertIn("不支持 Client Secret", resp.get_json().get("message", ""))

    def test_config_save_rejects_non_consumers_tenant(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = self._save_oauth_config(client, tenant="common")
            self.assertEqual(resp.status_code, 400)
            self.assertIn("tenant=consumers", resp.get_json().get("message", ""))

    def test_config_load_ignores_legacy_secret_and_tenant(self):
        with self.app.app_context():
            from outlook_web.repositories import settings as settings_repo

            settings_repo.set_setting("oauth_tool_client_secret", "legacy-plain-secret")
            settings_repo.set_setting("oauth_tool_tenant", "organizations")

        with self.app.test_client() as client:
            self._login(client)
            load_resp = client.get("/api/token-tool/config")
            self.assertEqual(load_resp.status_code, 200)
            self.assertEqual(load_resp.get_json().get("data", {}).get("client_secret"), "")
            self.assertEqual(load_resp.get_json().get("data", {}).get("tenant"), "consumers")

    def test_config_load_migrates_legacy_graph_scope_to_imap_default(self):
        with self.app.app_context():
            from outlook_web.repositories import settings as settings_repo

            settings_repo.set_setting(
                "oauth_tool_scope",
                "offline_access https://graph.microsoft.com/.default",
            )

        with self.app.test_client() as client:
            self._login(client)
            load_resp = client.get("/api/token-tool/config")
            self.assertEqual(load_resp.status_code, 200)
            self.assertEqual(
                load_resp.get_json().get("data", {}).get("scope"),
                "offline_access https://outlook.office.com/IMAP.AccessAsUser.All",
            )

    @patch.dict("os.environ", {"OAUTH_CLIENT_ID": "env-cid-123"}, clear=False)
    def test_config_env_override(self):
        with self.app.test_client() as client:
            self._login(client)
            load_resp = client.get("/api/token-tool/config")
            self.assertEqual(load_resp.status_code, 200)
            self.assertEqual(load_resp.get_json().get("data", {}).get("client_id"), "env-cid-123")
            self.assertEqual(load_resp.get_json().get("data", {}).get("tenant"), "consumers")

    def test_config_defaults_to_imap_compat_scope(self):
        with self.app.test_client() as client:
            self._login(client)
            load_resp = client.get("/api/token-tool/config")
            self.assertEqual(load_resp.status_code, 200)
            self.assertEqual(
                load_resp.get_json().get("data", {}).get("scope"),
                "offline_access https://outlook.office.com/IMAP.AccessAsUser.All",
            )

    def test_config_requires_login(self):
        with self.app.test_client() as client:
            resp = client.get("/api/token-tool/config")
            self.assertEqual(resp.status_code, 401)


class OAuthToolApiSaveTests(OAuthToolTestBase):
    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_update_existing_account(self, mock_test_rt):
        mock_test_rt.return_value = (True, None, None)
        acc_id = self._insert_test_account(
            email="save-test@oauth-test.com",
            client_id="old-cid",
            refresh_token="old-rt",
        )
        with self.app.app_context():
            from outlook_web.db import get_db

            db = get_db()
            db.execute("UPDATE accounts SET status = 'inactive' WHERE id = ?", (acc_id,))
            db.commit()

        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "update",
                    "account_id": acc_id,
                    "client_id": "new-cid",
                    "refresh_token": "new-rt",
                },
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.get_json().get("success"))

        with self.app.app_context():
            from outlook_web.repositories import accounts as accounts_repo

            acc = accounts_repo.get_account_by_id(acc_id)
            self.assertEqual(acc["client_id"], "new-cid")
            self.assertEqual(acc["refresh_token"], "new-rt")
            self.assertEqual(acc["status"], "active")

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_create_new_account(self, mock_test_rt):
        mock_test_rt.return_value = (True, None, None)
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "create",
                    "email": "brand-new@oauth-test.com",
                    "client_id": "new-cid",
                    "refresh_token": "new-rt",
                },
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.get_json().get("success"))

        with self.app.app_context():
            from outlook_web.repositories import accounts as accounts_repo

            acc = accounts_repo.get_account_by_email("brand-new@oauth-test.com")
            self.assertIsNotNone(acc)
            self.assertEqual(acc["client_id"], "new-cid")
            self.assertEqual(acc["refresh_token"], "new-rt")

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_validates_refresh_token(self, mock_test_rt):
        mock_test_rt.return_value = (False, "invalid refresh token", None)
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "create",
                    "email": "bad-rt@oauth-test.com",
                    "client_id": "new-cid",
                    "refresh_token": "bad-rt",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("Token 验证失败", resp.get_json().get("message", ""))

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_uses_consumers_and_imap_scope_for_validation(self, mock_test_rt):
        mock_test_rt.return_value = (True, None, None)
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "create",
                    "email": "compat-scope@oauth-test.com",
                    "client_id": "new-cid",
                    "refresh_token": "new-rt",
                },
            )
            self.assertEqual(resp.status_code, 200)

        _args, kwargs = mock_test_rt.call_args
        self.assertEqual(kwargs.get("tenant"), "consumers")
        self.assertEqual(
            kwargs.get("scope"),
            "offline_access https://outlook.office.com/IMAP.AccessAsUser.All",
        )

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_uses_explicit_token_scope_for_validation(self, mock_test_rt):
        mock_test_rt.return_value = (True, None, None)
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "create",
                    "email": "explicit-scope@oauth-test.com",
                    "client_id": "new-cid",
                    "refresh_token": "new-rt",
                    "scope": "Mail.Read User.Read offline_access openid profile",
                },
            )
            self.assertEqual(resp.status_code, 200)

        _args, kwargs = mock_test_rt.call_args
        self.assertEqual(kwargs.get("tenant"), "consumers")
        self.assertEqual(
            kwargs.get("scope"),
            "Mail.Read User.Read offline_access openid profile",
        )

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_preserves_explicit_graph_default_scope_for_validation(self, mock_test_rt):
        mock_test_rt.return_value = (True, None, None)
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "create",
                    "email": "legacy-scope@oauth-test.com",
                    "client_id": "new-cid",
                    "refresh_token": "new-rt",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                },
            )
            self.assertEqual(resp.status_code, 200)

        _args, kwargs = mock_test_rt.call_args
        self.assertEqual(kwargs.get("tenant"), "consumers")
        self.assertEqual(
            kwargs.get("scope"),
            "offline_access https://graph.microsoft.com/.default",
        )

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_personal_only_app_returns_common_endpoint_guidance(self, mock_test_rt):
        mock_test_rt.return_value = (
            False,
            "AADSTS9002331: Application 'test' is configured for use by Microsoft Account users only. Please use the /consumers endpoint to serve this request.",
            None,
        )
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "create",
                    "email": "consumer-only@oauth-test.com",
                    "client_id": "new-cid",
                    "refresh_token": "new-rt",
                },
            )
            self.assertEqual(resp.status_code, 400)
            body = resp.get_json()
            self.assertIn("Token 验证失败", body.get("message", ""))
            self.assertIn(
                "Accounts in any identity provider",
                body.get("error", {}).get("details", ""),
            )

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_rejects_non_consumers_tenant(self, mock_test_rt):
        mock_test_rt.return_value = (True, None, None)
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "create",
                    "email": "tenant-aware@oauth-test.com",
                    "client_id": "new-cid",
                    "refresh_token": "new-rt",
                    "tenant": "1b326a64-05c2-4db0-b4e0-6a8ecdf03d33",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("tenant=consumers", resp.get_json().get("message", ""))

        mock_test_rt.assert_not_called()

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_rejects_client_secret_in_compat_mode(self, mock_test_rt):
        mock_test_rt.return_value = (True, None, None)
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "create",
                    "email": "secret-aware@oauth-test.com",
                    "client_id": "new-cid",
                    "client_secret": "super-secret-value",
                    "refresh_token": "new-rt",
                },
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("不支持 Client Secret", resp.get_json().get("message", ""))

        mock_test_rt.assert_not_called()

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_nonexistent_account_id(self, mock_test_rt):
        mock_test_rt.return_value = (True, None, None)
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "update",
                    "account_id": 999999,
                    "client_id": "new-cid",
                    "refresh_token": "new-rt",
                },
            )
            self.assertEqual(resp.status_code, 404)
            self.assertEqual(resp.get_json().get("code"), "ACCOUNT_NOT_FOUND")

    @patch("outlook_web.services.graph.test_refresh_token_with_rotation")
    def test_save_preserves_account_fields(self, mock_test_rt):
        mock_test_rt.return_value = (True, None, None)
        acc_id = self._insert_test_account(
            email="preserve@oauth-test.com",
            client_id="orig-cid",
            refresh_token="orig-rt",
        )

        with self.app.app_context():
            from outlook_web.repositories import accounts as accounts_repo

            original = accounts_repo.get_account_by_id(acc_id)
            original_email = original["email"]
            original_group = original["group_id"]
            original_remark = original["remark"]

        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "update",
                    "account_id": acc_id,
                    "client_id": "updated-cid",
                    "refresh_token": "updated-rt",
                },
            )
            self.assertEqual(resp.status_code, 200)

        with self.app.app_context():
            from outlook_web.repositories import accounts as accounts_repo

            updated = accounts_repo.get_account_by_id(acc_id)
            self.assertEqual(updated["email"], original_email)
            self.assertEqual(updated["group_id"], original_group)
            self.assertEqual(updated["remark"], original_remark)
            self.assertEqual(updated["status"], "active")

    def test_save_requires_login(self):
        with self.app.test_client() as client:
            resp = client.post(
                "/api/token-tool/save",
                json={
                    "mode": "create",
                    "email": "need-login@oauth-test.com",
                    "client_id": "new-cid",
                    "refresh_token": "new-rt",
                },
            )
            self.assertEqual(resp.status_code, 401)


class OAuthToolAutoImportTests(OAuthToolTestBase):
    """连续授权回调应只在 Graph 校验成功后自动写入账号。"""

    @staticmethod
    def _graph_response(status_code, payload, reason="Graph error"):
        response = MagicMock()
        response.status_code = status_code
        response.json.return_value = payload
        response.reason = reason
        return response

    def _prepare_auto_flow(self, client, *, count=1, **overrides):
        from urllib.parse import parse_qs, urlparse

        payload = {
            "client_id": "auto-client-id",
            "tenant": "consumers",
            "scope": "offline_access https://graph.microsoft.com/.default",
            "redirect_uri": "http://localhost:5000/token-tool/callback",
            "auto_import": {"enabled": True, "count": count, "force_login": True},
            **overrides,
        }
        response = client.post("/api/token-tool/prepare", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        authorize_url = data.get("data", {}).get("authorize_url", "")
        state = parse_qs(urlparse(authorize_url).query).get("state", [""])[0]
        self.assertTrue(state)
        return state

    def test_build_logout_url_uses_registered_callback_only(self):
        from urllib.parse import parse_qs, urlparse

        from outlook_web.services.oauth_tool import build_logout_url

        callback_url = "https://token.example.com/token-tool/callback"
        logout_url = build_logout_url(tenant="consumers", post_logout_redirect_uri=callback_url)
        parsed = urlparse(logout_url)

        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "login.microsoftonline.com")
        self.assertEqual(parsed.path, "/consumers/oauth2/v2.0/logout")
        self.assertEqual(parse_qs(parsed.query), {"post_logout_redirect_uri": [callback_url]})
        self.assertNotIn("refresh_token", logout_url)
        self.assertNotIn("logout_hint", logout_url)

    @patch("outlook_web.controllers.token_tool.requests.get")
    @patch("outlook_web.controllers.token_tool.oauth_tool_service.exchange_code_for_tokens")
    def test_callback_auto_imports_graph_account_to_pool_and_telegram(self, mock_exchange, mock_get):
        mock_exchange.return_value = (
            {
                "access_token": "fresh-access-token",
                "refresh_token": "fresh-refresh-token",
            },
            None,
        )
        mock_get.side_effect = [
            self._graph_response(200, {"mail": "Auto-User@outlook.com"}),
            self._graph_response(200, {"value": []}),
        ]

        with self.app.test_client() as client:
            self._login(client)
            state = self._prepare_auto_flow(client)
            response = client.get(f"/token-tool/callback?code=auto-code&state={state}")
            logout_complete_response = client.get("/token-tool/callback")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("outlook-email-plus-auto-import", html)
        self.assertIn("auto-user@outlook.com----x----auto-client-id----fresh-refresh-token", html)
        self.assertIn("/consumers/oauth2/v2.0/logout", html)
        self.assertIn('"logout_pending": true', html)
        self.assertEqual(logout_complete_response.status_code, 200)
        self.assertIn('"status": "logout_complete"', logout_complete_response.get_data(as_text=True))

        with self.app.app_context():
            from outlook_web.repositories import accounts as accounts_repo

            account = accounts_repo.get_account_by_email("auto-user@outlook.com")
            self.assertIsNotNone(account)
            self.assertEqual(account["client_id"], "auto-client-id")
            self.assertEqual(account["refresh_token"], "fresh-refresh-token")
            self.assertEqual(account["pool_status"], "available")
            self.assertTrue(account["telegram_push_enabled"])

    @patch("outlook_web.controllers.token_tool.requests.get")
    @patch("outlook_web.controllers.token_tool.oauth_tool_service.exchange_code_for_tokens")
    def test_callback_updates_existing_account_logs_out_and_resumes_next_flow(self, mock_exchange, mock_get):
        from urllib.parse import parse_qs, urlparse

        from outlook_web.services import oauth_tool as oauth_tool_service

        account_id = self._insert_test_account(
            email="existing@outlook.com",
            client_id="old-client-id",
            refresh_token="old-refresh-token",
        )
        with self.app.app_context():
            from outlook_web.db import get_db

            db = get_db()
            db.execute("UPDATE accounts SET status = 'inactive' WHERE id = ?", (account_id,))
            db.commit()

        mock_exchange.return_value = (
            {"access_token": "fresh-access-token", "refresh_token": "fresh-refresh-token"},
            None,
        )
        mock_get.side_effect = [
            self._graph_response(200, {"userPrincipalName": "existing@outlook.com"}),
            self._graph_response(200, {"value": []}),
        ]

        with self.app.test_client() as client:
            self._login(client)
            state = self._prepare_auto_flow(
                client,
                auto_import={
                    "enabled": True,
                    "count": 2,
                    "force_login": True,
                    "login_hints": ["existing@outlook.com", "next@outlook.com"],
                },
            )
            first_flow = oauth_tool_service.get_oauth_flow(state)
            response = client.get(f"/token-tool/callback?code=auto-code&state={state}")

            logout_response = client.get("/token-tool/callback")
            consumed_response = client.get("/token-tool/callback")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            parse_qs(urlparse(first_flow["authorize_url"]).query).get("login_hint"),
            ["existing@outlook.com"],
        )
        html = response.get_data(as_text=True)
        self.assertIn("正在退出当前 Microsoft 账号", html)
        self.assertIn("/consumers/oauth2/v2.0/logout", html)
        self.assertEqual(logout_response.status_code, 302)
        self.assertIn("/consumers/oauth2/v2.0/authorize", logout_response.headers["Location"])
        self.assertEqual(
            parse_qs(urlparse(logout_response.headers["Location"]).query).get("login_hint"),
            ["next@outlook.com"],
        )
        self.assertEqual(consumed_response.status_code, 200)
        self.assertIn("回调缺少 code 或 state", consumed_response.get_data(as_text=True))
        next_flows = [
            flow
            for flow in oauth_tool_service.OAUTH_FLOW_STORE.values()
            if flow.get("auto_import", {}).get("batch_id")
        ]
        self.assertEqual(len(next_flows), 1)
        self.assertEqual(next_flows[0]["auto_import"]["current"], 2)
        self.assertEqual(next_flows[0]["auto_import"]["remaining"], 1)

        with self.app.app_context():
            from outlook_web.repositories import accounts as accounts_repo

            account = accounts_repo.get_account_by_id(account_id)
            self.assertEqual(account["client_id"], "auto-client-id")
            self.assertEqual(account["refresh_token"], "fresh-refresh-token")
            self.assertEqual(account["pool_status"], "available")
            self.assertEqual(account["status"], "active")

    def test_auto_import_rejects_login_hint_count_mismatch(self):
        with self.app.test_client() as client:
            self._login(client)
            response = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "auto-client-id",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                    "auto_import": {
                        "enabled": True,
                        "count": 2,
                        "login_hints": ["only-one@outlook.com"],
                    },
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("数量必须与本批次账号数一致", response.get_json().get("message", ""))

    @patch("outlook_web.controllers.token_tool.requests.get")
    @patch("outlook_web.controllers.token_tool.oauth_tool_service.exchange_code_for_tokens")
    def test_callback_does_not_import_when_graph_mailbox_validation_fails(self, mock_exchange, mock_get):
        mock_exchange.return_value = (
            {"access_token": "fresh-access-token", "refresh_token": "fresh-refresh-token"},
            None,
        )
        mock_get.side_effect = [
            self._graph_response(200, {"mail": "no-mail-read@outlook.com"}),
            self._graph_response(403, {"error": {"message": "Access is denied."}}, "Forbidden"),
        ]

        with self.app.test_client() as client:
            self._login(client)
            state = self._prepare_auto_flow(client)
            response = client.get(f"/token-tool/callback?code=auto-code&state={state}")

        self.assertEqual(response.status_code, 200)
        self.assertIn("GRAPH_TOKEN_FAILED", response.get_data(as_text=True))
        with self.app.app_context():
            from outlook_web.repositories import accounts as accounts_repo

            self.assertIsNone(accounts_repo.get_account_by_email("no-mail-read@outlook.com"))

    def test_auto_import_rejects_imap_scope_or_non_callback_redirect_uri(self):
        with self.app.test_client() as client:
            self._login(client)
            imap_response = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "auto-client-id",
                    "tenant": "consumers",
                    "scope": "offline_access https://outlook.office.com/IMAP.AccessAsUser.All",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                    "auto_import": {"enabled": True, "count": 1},
                },
            )
            self.assertEqual(imap_response.status_code, 400)
            self.assertIn("仅支持 Graph", imap_response.get_json().get("message", ""))

            callback_response = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "auto-client-id",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/other-callback",
                    "auto_import": {"enabled": True, "count": 1},
                },
            )
            self.assertEqual(callback_response.status_code, 400)
            self.assertIn("/token-tool/callback", callback_response.get_json().get("message", ""))

            origin_response = client.post(
                "/api/token-tool/prepare",
                headers={"Origin": "https://token.example.com"},
                json={
                    "client_id": "auto-client-id",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "https://other.example.com/token-tool/callback",
                    "auto_import": {"enabled": True, "count": 1},
                },
            )
            self.assertEqual(origin_response.status_code, 400)
            self.assertIn("同域", origin_response.get_json().get("message", ""))


class OAuthToolApiBlueprintTests(OAuthToolTestBase):
    def test_token_tool_page_accessible_when_enabled(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.get("/token-tool")
            self.assertEqual(resp.status_code, 200)
            html = resp.get_data(as_text=True)
            self.assertIn("OAuth Token 工具", html)

    @patch("outlook_web.config.get_oauth_tool_enabled", return_value=False)
    def test_token_tool_disabled_returns_404(self, _mock_enabled):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.get("/token-tool")
            self.assertEqual(resp.status_code, 404)

    @patch("outlook_web.config.get_oauth_tool_enabled", return_value=False)
    def test_token_tool_api_disabled_returns_404(self, _mock_enabled):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.post(
                "/api/token-tool/prepare",
                json={
                    "client_id": "cid",
                    "tenant": "consumers",
                    "scope": "offline_access https://graph.microsoft.com/.default",
                    "redirect_uri": "http://localhost:5000/token-tool/callback",
                },
            )
            self.assertEqual(resp.status_code, 404)


class OAuthToolApiAccountListTests(OAuthToolTestBase):
    def test_accounts_list_returns_non_sensitive_fields(self):
        self._insert_test_account(email="list-test@oauth-test.com")
        with self.app.app_context():
            from outlook_web.repositories import accounts as accounts_repo

            accounts_repo.add_account(
                email_addr="imap-test@oauth-test.com",
                password="",
                client_id="",
                refresh_token="",
                account_type="imap",
                provider="custom",
                imap_host="imap.example.com",
                imap_password="imap-pass",
                group_id=1,
                remark="oauth-test",
            )

        with self.app.test_client() as client:
            self._login(client)
            resp = client.get("/api/token-tool/accounts")
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            accounts = data.get("data", [])
            self.assertTrue(len(accounts) > 0)
            acc = accounts[0]
            self.assertIn("id", acc)
            self.assertIn("email", acc)
            self.assertIn("status", acc)
            self.assertIn("account_type", acc)
            self.assertTrue(all(item.get("account_type") in ("outlook", None) for item in accounts))

    def test_accounts_list_excludes_sensitive_fields(self):
        self._insert_test_account(email="sensitive-test@oauth-test.com")
        with self.app.test_client() as client:
            self._login(client)
            resp = client.get("/api/token-tool/accounts")
            data = resp.get_json()
            for acc in data.get("data", []):
                self.assertNotIn("refresh_token", acc)
                self.assertNotIn("password", acc)
                self.assertNotIn("imap_password", acc)

    def test_accounts_list_empty(self):
        with self.app.test_client() as client:
            self._login(client)
            resp = client.get("/api/token-tool/accounts")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.get_json().get("data"), [])

    def test_accounts_list_requires_login(self):
        with self.app.test_client() as client:
            resp = client.get("/api/token-tool/accounts")
            self.assertEqual(resp.status_code, 401)


class OAuthToolSettingsCompatTests(OAuthToolTestBase):
    def test_oauth_tool_client_secret_supports_legacy_plaintext_value(self):
        with self.app.app_context():
            from outlook_web.repositories import settings as settings_repo

            settings_repo.set_setting("oauth_tool_client_secret", "legacy-plain-secret")
            self.assertEqual(
                settings_repo.get_oauth_tool_client_secret(),
                "legacy-plain-secret",
            )

    def test_oauth_tool_client_secret_returns_empty_for_invalid_encrypted_value(self):
        with self.app.app_context():
            from outlook_web.repositories import settings as settings_repo

            settings_repo.set_setting("oauth_tool_client_secret", "enc:not-a-valid-token")
            self.assertEqual(settings_repo.get_oauth_tool_client_secret(), "")
