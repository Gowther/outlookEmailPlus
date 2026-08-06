"""OAuth Token 获取工具 — 控制器层

编排 OAuth 授权流程、Token 换取、账号写入等业务操作。
被 routes/token_tool.py 的 Blueprint 路由直接调用。

业务背景:
  - PRD: docs/PRD/2026-04-12-OAuth-Token获取工具PRD.md (v1.3)
  - 收口范围: "兼容账号导入模式" — tenant 固定 consumers, 禁用 client_secret

设计决策 (FD v1.0 §收口说明):
  - prepare / config / save 接口均拒绝不兼容输入 (client_secret / 非 consumers tenant)
  - save_to_account 使用 test_refresh_token_with_rotation 验证后再写入
  - 普通回调保持手动粘贴换取；带 auto_import 上下文的回调在服务端完成连续导入
"""

from __future__ import annotations

import logging
import secrets
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

import requests
from flask import abort, jsonify, redirect, render_template, request, session

from outlook_web import config as app_config
from outlook_web.audit import log_audit
from outlook_web.errors import build_error_response
from outlook_web.repositories import accounts as accounts_repo
from outlook_web.repositories import settings as settings_repo
from outlook_web.security.auth import login_required
from outlook_web.services import graph as graph_service
from outlook_web.services import oauth_tool as oauth_tool_service

# 兼容模式常量 — 当前仅支持个人 Microsoft 账号导入 (FD 收口说明)
COMPATIBLE_TENANT = "consumers"
LEGACY_GRAPH_SCOPE = "offline_access https://graph.microsoft.com/.default"
COMPATIBLE_SCOPE = app_config.get_oauth_scope_default()
AUTO_IMPORT_MAX_COUNT = 500
AUTO_IMPORT_CALLBACK_PATH = "/token-tool/callback"
AUTO_IMPORT_LOGOUT_SESSION_KEY = "oauth_auto_logout_continue"
GRAPH_API_BASE_URL = "https://graph.microsoft.com/v1.0"

logger = logging.getLogger(__name__)


def _ensure_oauth_tool_enabled() -> None:
    """功能开关守卫: OAUTH_TOOL_ENABLED=false 时返回 404 (PRD §2.8)"""
    if not app_config.get_oauth_tool_enabled():
        abort(404)


def _compatibility_mode_error(client_secret: str, tenant: str) -> str | None:
    """兼容模式校验: 拒绝 client_secret 和非 consumers tenant (FD 收口说明)"""
    normalized_tenant = (tenant or COMPATIBLE_TENANT).strip() or COMPATIBLE_TENANT
    if client_secret:
        return "兼容账号导入模式不支持 Client Secret，请使用公共客户端并保持 Client Secret 为空"
    if normalized_tenant != COMPATIBLE_TENANT:
        return "兼容账号导入模式仅支持 tenant=consumers，请使用与购买账号一致的个人 Microsoft 账号配置"
    return None


def _save_validation_guidance(error_msg: str) -> str | None:
    """针对特定 Azure 错误码返回修复指引 (AADSTS9002331 — 仅个人账号与 /common 冲突)"""
    detail = (error_msg or "").lower()
    if "aadsts9002331" in detail or "/consumers endpoint" in detail:
        return "当前 Azure 应用被配置为仅 Personal Microsoft accounts，这会与系统现有的 /common 验证与运行模型冲突。请将 Supported account types 改为“Accounts in any identity provider or organizational directory and personal Microsoft accounts”。"
    return None


def _build_oauth_config(
    data: Dict[str, Any],
    *,
    prompt_login: bool = False,
    login_hint: str = "",
) -> Dict[str, Any]:
    """从 API 请求构造 OAuth 配置，保证手动和自动流程使用同一套参数。"""
    return {
        "client_id": (data.get("client_id") or "").strip(),
        "client_secret": "",
        "redirect_uri": (data.get("redirect_uri") or "").strip(),
        "scope": (data.get("scope") or "").strip(),
        "tenant": COMPATIBLE_TENANT,
        "prompt_consent": bool(data.get("prompt_consent")),
        "prompt_login": prompt_login,
        "login_hint": (login_hint or "").strip(),
    }


def _is_graph_scope(scope: str) -> bool:
    """判断标准化后的 scope 是否包含 Microsoft Graph API scope。"""
    normalized_scope, scope_error = oauth_tool_service.validate_scope(scope)
    if scope_error:
        return False
    return any(token.lower().startswith("https://graph.microsoft.com/") for token in normalized_scope.split())


def _build_auto_import_context(
    data: Dict[str, Any],
    *,
    redirect_uri: str,
    scope: str,
    request_origin: str = "",
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """校验并创建仅服务端保存的连续自动导入批次上下文。"""
    auto_import = data.get("auto_import")
    if not isinstance(auto_import, dict) or not auto_import.get("enabled"):
        return None, None

    try:
        count = int(auto_import.get("count", 1))
    except (TypeError, ValueError):
        return None, "授权账号数量必须是 1 到 500 之间的整数"
    if not 1 <= count <= AUTO_IMPORT_MAX_COUNT:
        return None, f"授权账号数量必须是 1 到 {AUTO_IMPORT_MAX_COUNT} 之间的整数"

    parsed_redirect_uri = urlparse(redirect_uri)
    redirect_path = parsed_redirect_uri.path.rstrip("/") or "/"
    if redirect_path != AUTO_IMPORT_CALLBACK_PATH:
        return (
            None,
            "批量自动导入要求 Redirect URI 指向当前服务的 /token-tool/callback；"
            "VPS 部署时请填写可从浏览器访问的公网域名，不可使用远程服务器的 localhost",
        )
    redirect_origin = f"{parsed_redirect_uri.scheme}://{parsed_redirect_uri.netloc}"
    normalized_request_origin = request_origin.rstrip("/")
    if normalized_request_origin and redirect_origin != normalized_request_origin:
        return None, "批量自动导入的 Redirect URI 必须与当前 Token 工具页面同域，确保授权回调能回到本服务"
    if not _is_graph_scope(scope):
        return None, "批量自动导入仅支持 Graph 邮件，请先选择“Graph 邮件”Scope 预设"

    login_hints: list[str] = []
    seen_login_hints: set[str] = set()
    raw_login_hints = auto_import.get("login_hints")
    if raw_login_hints is not None:
        if not isinstance(raw_login_hints, list):
            return None, "批量预填账号列表格式无效"
        for item in raw_login_hints:
            if not isinstance(item, str):
                return None, "批量预填账号列表只能包含邮箱地址"
            email = item.strip()
            if not email or "@" not in email or len(email) > 254:
                return None, "批量预填账号列表包含无效邮箱地址"
            normalized_email = email.lower()
            if normalized_email in seen_login_hints:
                return None, "批量预填账号列表包含重复邮箱地址"
            login_hints.append(email)
            seen_login_hints.add(normalized_email)
        if len(login_hints) != count:
            return None, "批量预填账号数量必须与本批次账号数一致"

    context = {
        "batch_id": secrets.token_urlsafe(12),
        "total": count,
        "current": 1,
        "remaining": count,
        "prompt_consent": bool(data.get("prompt_consent")),
        # 默认强制显示登录页，避免 Microsoft 复用上一个账号而重复导入。
        "prompt_login": bool(auto_import.get("force_login", True)),
    }
    if login_hints:
        # 仅存于服务端 OAuth flow，用于依次预填 Microsoft 登录页的账号框。
        context["login_hints"] = login_hints
        context["login_hint"] = login_hints[0]
    return context, None


def _oauth_config_from_flow(flow_data: Dict[str, Any]) -> Dict[str, Any]:
    """从已校验的 flow 恢复下一次连续授权所需的配置。"""
    auto_import = flow_data.get("auto_import") or {}
    return {
        "client_id": flow_data["client_id"],
        "client_secret": flow_data.get("client_secret", ""),
        "redirect_uri": flow_data["redirect_uri"],
        "scope": flow_data["scope"],
        "tenant": flow_data.get("tenant", COMPATIBLE_TENANT),
        "prompt_consent": bool(auto_import.get("prompt_consent")),
        "prompt_login": bool(auto_import.get("prompt_login")),
        "login_hint": (auto_import.get("login_hint") or "").strip(),
    }


def _graph_response_error(response: requests.Response) -> str:
    """返回适合展示的 Graph 错误概述，不包含请求凭据。"""
    try:
        payload = response.json()
        message = (payload.get("error") or {}).get("message")
        if message:
            return str(message)
    except (TypeError, ValueError):
        pass
    return response.reason or "未知错误"


def _verify_graph_mailbox_and_get_email(access_token: str) -> tuple[Optional[str], Optional[str]]:
    """使用刚换取的 access token 识别邮箱并验证具备读取收件箱的权限。"""
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        profile_response = requests.get(
            f"{GRAPH_API_BASE_URL}/me",
            headers=headers,
            params={"$select": "mail,userPrincipalName"},
            timeout=15,
        )
    except requests.RequestException as exc:
        logger.warning("[oauth_tool] 自动导入读取 Graph 用户信息失败: %s", exc)
        return None, "无法连接 Graph 以识别邮箱，请检查网络后重试"

    if profile_response.status_code != 200:
        return (
            None,
            "无法读取 Graph 用户信息（HTTP %s）：%s。请确认应用已授予 User.Read 委托权限。"
            % (profile_response.status_code, _graph_response_error(profile_response)),
        )

    try:
        profile = profile_response.json()
    except ValueError:
        return None, "Graph 用户信息响应格式异常，请重试"
    email = str(profile.get("mail") or profile.get("userPrincipalName") or "").strip().lower()
    if not email or "@" not in email:
        return None, "Graph 未返回可用邮箱地址，请确认应用已授予 User.Read 委托权限"

    try:
        mailbox_response = requests.get(
            f"{GRAPH_API_BASE_URL}/me/mailFolders/inbox/messages",
            headers=headers,
            params={"$top": "1", "$select": "id"},
            timeout=15,
        )
    except requests.RequestException as exc:
        logger.warning("[oauth_tool] 自动导入验证 Graph 邮箱失败: %s", exc)
        return None, "无法连接 Graph 以验证邮箱权限，请检查网络后重试"

    if mailbox_response.status_code != 200:
        return (
            None,
            "Graph 邮箱读取校验失败（HTTP %s）：%s。请确认应用已授予 Mail.Read 委托权限。"
            % (mailbox_response.status_code, _graph_response_error(mailbox_response)),
        )
    return email, None


def _auto_import_account(
    email: str,
    client_id: str,
    refresh_token: str,
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """创建或更新 Outlook 账号，并固定加入邮箱池、开启 Telegram 推送。"""
    existing = accounts_repo.get_account_by_email(email)
    if existing and (existing.get("account_type") or "outlook").strip().lower() != "outlook":
        return None, "同邮箱已存在非 Outlook 类型账号，为避免覆盖，未自动写入"

    if existing:
        account_id = existing["id"]
        success = accounts_repo.update_account_credentials(
            account_id,
            client_id=client_id,
            refresh_token=refresh_token,
            pool_status="available",
        )
        if not success:
            return None, "更新已有账号凭据失败"
        success = accounts_repo.update_account(
            account_id=account_id,
            email_addr=existing["email"],
            password=None,
            client_id=client_id,
            refresh_token=refresh_token,
            group_id=existing.get("group_id") or 1,
            remark=existing.get("remark") or "",
            status="active",
        )
        if not success:
            return None, "更新已有账号状态失败"
        action = "updated"
    else:
        success = accounts_repo.add_account(
            email_addr=email,
            password="",
            client_id=client_id,
            refresh_token=refresh_token,
            account_type="outlook",
            provider="outlook",
            add_to_pool=True,
        )
        if not success:
            return None, "创建 Outlook 账号失败（邮箱可能已存在）"
        created = accounts_repo.get_account_by_email(email)
        if not created:
            return None, "账号已创建但无法读取账号信息"
        account_id = created["id"]
        action = "created"

    telegram_enabled = accounts_repo.toggle_telegram_push(account_id, True)
    result = {
        "account_id": account_id,
        "email": email,
        "action": action,
        "pool_added": True,
        "telegram_enabled": bool(telegram_enabled),
        # 仅通过同源 popup postMessage 返回给发起页面，不写入日志或数据库。
        "import_line": f"{email}----x----{client_id}----{refresh_token}",
    }
    if not telegram_enabled:
        result["warning"] = "账号已导入邮箱池，但 Telegram 开关开启失败，请在账号列表中手动开启"

    log_audit(
        "update" if action == "updated" else "create",
        "account",
        str(account_id),
        f"OAuth 批量自动导入 (client_id={client_id[:8]}...)",
    )
    return result, None


def _render_auto_import_error(error_code: str, error_description: str, guidance: str = "") -> Any:
    """自动导入失败时通知发起页面；不继续下一账号，避免静默跳过。"""
    return render_template(
        "popup_result.html",
        error=True,
        error_code=error_code,
        error_description=error_description,
        guidance=guidance,
        auto_import=True,
        auto_result={"status": "error", "message": error_description},
    )


def _resume_auto_import_after_logout(error: str = "", error_description: str = "") -> Any | None:
    """消费一次性注销续接状态，并继续下一账号的 OAuth flow。

    Microsoft 对个人账号的 post_logout_redirect_uri 不支持附加查询参数，
    所以续接 state 保存在已签名的本站 Session，真正的授权 URL 仍留在服务端
    OAUTH_FLOW_STORE 中。Session 丢失时不继续，避免跳转到未知 flow。
    """
    continuation = session.pop(AUTO_IMPORT_LOGOUT_SESSION_KEY, None)
    if continuation is None:
        return None

    if not isinstance(continuation, dict):
        return _render_auto_import_error(
            "OAUTH_LOGOUT_CONTINUATION_INVALID",
            "Microsoft 注销完成后无法恢复下一账号授权，请重新发起当前批次",
        )

    batch_id = continuation.get("batch_id")
    if not isinstance(batch_id, str) or not batch_id:
        return _render_auto_import_error(
            "OAUTH_LOGOUT_CONTINUATION_INVALID",
            "Microsoft 注销续接信息无效，请重新发起当前批次",
        )

    if continuation.get("completed") is True:
        current = continuation.get("current")
        total = continuation.get("total")
        warning = continuation.get("warning") or ""
        if type(current) is not int or type(total) is not int or not 1 <= current <= total:
            return _render_auto_import_error(
                "OAUTH_LOGOUT_CONTINUATION_INVALID",
                "Microsoft 注销续接信息无效，请重新发起当前批次",
            )
        if error:
            return _render_auto_import_error(
                "OAUTH_MICROSOFT_LOGOUT_FAILED",
                error_description or f"Microsoft 注销失败：{error}",
                "账号已导入，但请在 Microsoft 页面手动退出当前账号后再继续",
            )
        logger.info("[oauth_tool] Microsoft 注销完成，连续授权批次结束 (batch=%s...)", batch_id[:8])
        return render_template(
            "popup_result.html",
            error=False,
            auto_import=True,
            auto_logout_complete=True,
            auto_result={
                "status": "logout_complete",
                "current": current,
                "total": total,
                "remaining": 0,
                "warning": warning,
            },
        )

    next_state = continuation.get("next_state")
    if not isinstance(next_state, str) or not next_state:
        return _render_auto_import_error(
            "OAUTH_LOGOUT_CONTINUATION_INVALID",
            "Microsoft 注销续接信息无效，请重新发起当前批次",
        )

    next_flow = oauth_tool_service.get_oauth_flow(next_state)
    next_auto_import = (next_flow or {}).get("auto_import") or {}
    next_authorize_url = (next_flow or {}).get("authorize_url") or ""
    is_expected_flow = (
        isinstance(next_auto_import, dict)
        and next_auto_import.get("batch_id") == batch_id
        and isinstance(next_authorize_url, str)
        and next_authorize_url.startswith("https://login.microsoftonline.com/")
    )
    if not is_expected_flow:
        oauth_tool_service.discard_oauth_flow(next_state)
        if session.get("oauth_state") == next_state:
            session.pop("oauth_state", None)
        return _render_auto_import_error(
            "OAUTH_LOGOUT_CONTINUATION_EXPIRED",
            "Microsoft 注销耗时过长或续接已过期，请重新发起当前批次",
        )

    if error:
        oauth_tool_service.discard_oauth_flow(next_state)
        if session.get("oauth_state") == next_state:
            session.pop("oauth_state", None)
        return _render_auto_import_error(
            "OAUTH_MICROSOFT_LOGOUT_FAILED",
            error_description or f"Microsoft 注销失败：{error}",
            "请关闭当前弹窗后重新发起这一账号的授权",
        )

    logger.info("[oauth_tool] Microsoft 注销完成，继续下一账号授权 (state=%s...)", next_state[:8])
    return redirect(next_authorize_url)


def _handle_auto_import_callback(
    *,
    code: str,
    state: str,
    flow_data: Dict[str, Any],
    auto_import: Dict[str, Any],
) -> Any:
    """完成一次自动导入，并在成功时创建下一个账号的授权 flow。"""
    token_data, error_info = oauth_tool_service.exchange_code_for_tokens(
        code=code,
        oauth_config=_oauth_config_from_flow(flow_data),
        verifier=flow_data["verifier"],
    )
    # 授权码无论成功或失败都只能使用一次。
    oauth_tool_service.discard_oauth_flow(state)
    if session.get("oauth_state") == state:
        session.pop("oauth_state", None)

    if token_data is None:
        if isinstance(error_info, dict):
            return _render_auto_import_error(
                "OAUTH_MICROSOFT_REQUEST_FAILED",
                error_info.get("message", "换取 Token 失败"),
                error_info.get("guidance", ""),
            )
        return _render_auto_import_error("OAUTH_MICROSOFT_REQUEST_FAILED", str(error_info))

    refresh_token = (token_data.get("refresh_token") or "").strip()
    access_token = (token_data.get("access_token") or "").strip()
    if not refresh_token or not access_token:
        return _render_auto_import_error("OAUTH_TOKEN_MISSING", "Microsoft 未返回完整的 access_token 或 refresh_token")

    email, graph_error = _verify_graph_mailbox_and_get_email(access_token)
    if graph_error:
        return _render_auto_import_error("GRAPH_TOKEN_FAILED", graph_error)

    result, import_error = _auto_import_account(email, flow_data["client_id"], refresh_token)
    if import_error:
        return _render_auto_import_error("ACCOUNT_IMPORT_FAILED", import_error)

    current = int(auto_import.get("current", 1))
    total = int(auto_import.get("total", current))
    remaining = max(int(auto_import.get("remaining", 1)) - 1, 0)
    result.update({"status": "success", "current": current, "total": total, "remaining": remaining})

    logout_url = ""
    logout_continuation: Optional[Dict[str, Any]] = None
    if remaining:
        next_context = dict(auto_import)
        next_context.update({"current": current + 1, "remaining": remaining})
        login_hints = next_context.get("login_hints") or []
        if login_hints:
            next_context["login_hint"] = login_hints[current]
        next_oauth_config = _oauth_config_from_flow(flow_data)
        next_oauth_config["login_hint"] = next_context.get("login_hint", "")
        next_authorize_url, state_or_error = oauth_tool_service.start_oauth_flow(
            next_oauth_config,
            auto_import_context=next_context,
        )
        if not next_authorize_url:
            result["warning"] = "当前账号已导入，但无法创建下一账号授权：%s" % state_or_error
        else:
            logout_continuation = {
                "batch_id": auto_import["batch_id"],
                "next_state": state_or_error,
            }
            session["oauth_state"] = state_or_error
    # 最后一个账号、或下一条 flow 创建失败时，也要结束当前 Microsoft 会话；
    # 完成页会在注销回跳后再通知主页面，避免用户误以为弹窗已经结束。
    if logout_continuation is None:
        logout_continuation = {
            "batch_id": auto_import["batch_id"],
            "completed": True,
            "current": current,
            "total": total,
            "warning": result.get("warning", ""),
        }

    # 注销回跳不能携带自定义 query 参数（个人 Microsoft 账号限制），因此只将
    # 下一 flow 的 state 放在已签名的本站 Session 中，授权 URL 始终留在服务端。
    session[AUTO_IMPORT_LOGOUT_SESSION_KEY] = logout_continuation
    logout_url = oauth_tool_service.build_logout_url(
        tenant=flow_data.get("tenant", COMPATIBLE_TENANT),
        post_logout_redirect_uri=flow_data["redirect_uri"],
    )
    result["logout_pending"] = True
    # 下一条授权 URL 不渲染到浏览器页面；只由注销回跳时从服务端 flow 恢复。
    next_authorize_url = ""

    return render_template(
        "popup_result.html",
        error=False,
        auto_import=True,
        auto_result=result,
        next_authorize_url=next_authorize_url,
        logout_url=logout_url,
    )


@login_required
def render_page() -> Any:
    _ensure_oauth_tool_enabled()
    return render_template("token_tool.html")


@login_required
def prepare_oauth() -> Any:
    _ensure_oauth_tool_enabled()
    data = request.get_json(silent=True) or {}

    client_id = (data.get("client_id") or "").strip()
    if not client_id:
        return build_error_response("OAUTH_CONFIG_INVALID", "Client ID 不能为空", status=400)

    redirect_uri = (data.get("redirect_uri") or "").strip()
    if not redirect_uri or not redirect_uri.startswith(("http://", "https://")):
        return build_error_response("OAUTH_CONFIG_INVALID", "Redirect URI 格式无效", status=400)

    client_secret = (data.get("client_secret") or "").strip()
    tenant = (data.get("tenant") or COMPATIBLE_TENANT).strip() or COMPATIBLE_TENANT
    compatibility_error = _compatibility_mode_error(client_secret, tenant)
    if compatibility_error:
        return build_error_response("OAUTH_CONFIG_INVALID", compatibility_error, status=400)

    auto_import_context, auto_import_error = _build_auto_import_context(
        data,
        redirect_uri=redirect_uri,
        scope=(data.get("scope") or "").strip(),
        request_origin=request.headers.get("Origin", ""),
    )
    if auto_import_error:
        return build_error_response("OAUTH_CONFIG_INVALID", auto_import_error, status=400)

    oauth_config = _build_oauth_config(
        data,
        prompt_login=bool(auto_import_context and auto_import_context.get("prompt_login")),
        login_hint=(auto_import_context or {}).get("login_hint", ""),
    )

    authorize_url, state_or_error = oauth_tool_service.start_oauth_flow(
        oauth_config,
        auto_import_context=auto_import_context,
    )
    if authorize_url is None:
        return build_error_response("OAUTH_CONFIG_INVALID", state_or_error, status=400)

    session["oauth_state"] = state_or_error
    response_data = {"authorize_url": authorize_url}
    if auto_import_context:
        response_data["auto_import"] = {
            "total": auto_import_context["total"],
            "batch_id": auto_import_context["batch_id"],
        }
    return jsonify({"success": True, "data": response_data})


def handle_callback() -> Any:
    _ensure_oauth_tool_enabled()
    error = request.args.get("error")
    error_description = request.args.get("error_description", "")
    code = request.args.get("code")
    state = request.args.get("state")

    # Microsoft 的注销回跳不含 OAuth code/state；优先消费一次性续接状态，
    # 再进入通常的授权回调处理。
    if not code and not state:
        logout_resume = _resume_auto_import_after_logout(error or "", error_description)
        if logout_resume is not None:
            return logout_resume

    flow_data = oauth_tool_service.get_oauth_flow(state) if state else None
    auto_import = (flow_data or {}).get("auto_import")

    if error:
        guidance = oauth_tool_service.map_error_guidance(error)
        if auto_import:
            oauth_tool_service.discard_oauth_flow(state)
            if session.get("oauth_state") == state:
                session.pop("oauth_state", None)
            return _render_auto_import_error(error, error_description, guidance)
        return render_template(
            "popup_result.html",
            error=True,
            error_code=error,
            error_description=error_description,
            guidance=guidance,
        )

    if not code or not state:
        if auto_import:
            return _render_auto_import_error(
                "missing_params",
                "回调缺少 code 或 state 参数",
                "请关闭当前弹窗后重新发起这一账号的授权",
            )
        return render_template(
            "popup_result.html",
            error=True,
            error_code="missing_params",
            error_description="回调缺少 code 或 state 参数",
            guidance="请重新点击『登录 Microsoft』",
        )

    if auto_import:
        return _handle_auto_import_callback(
            code=code,
            state=state,
            flow_data=flow_data,
            auto_import=auto_import,
        )

    return render_template("popup_result.html", error=False)


@login_required
def exchange_token() -> Any:
    _ensure_oauth_tool_enabled()
    data = request.get_json(silent=True) or {}
    callback_url = (data.get("callback_url") or "").strip()
    if not callback_url:
        return build_error_response("OAUTH_CODE_PARSE_FAILED", "请粘贴回调 URL", status=400)

    parsed = urlparse(callback_url)
    qs = parse_qs(parsed.query)
    code = (qs.get("code") or [None])[0]
    state = (qs.get("state") or [None])[0]

    if not code:
        return build_error_response("OAUTH_CODE_PARSE_FAILED", "URL 中未包含 code 参数", status=400)
    if not state:
        return build_error_response("OAUTH_CODE_PARSE_FAILED", "URL 中未包含 state 参数", status=400)

    # 双层 state 校验 (FD §5.3): Session cookie 防 CSRF + 内存 Store 携带 PKCE verifier
    session_state = session.get("oauth_state")
    if not session_state or session_state != state:
        return build_error_response(
            "OAUTH_MICROSOFT_AUTH_FAILED",
            "state 校验失败，请重新发起授权",
            status=400,
        )

    flow_data = oauth_tool_service.get_oauth_flow(state)
    if not flow_data:
        return build_error_response(
            "OAUTH_CODE_INVALID",
            "授权流程已过期（超过 20 分钟），请重新发起",
            status=400,
        )

    # 换取成功后立即清除 flow 数据,防止授权码重放攻击
    token_data, error_info = oauth_tool_service.exchange_code_for_tokens(
        code=code,
        oauth_config={
            "client_id": flow_data["client_id"],
            "client_secret": flow_data.get("client_secret", ""),
            "redirect_uri": flow_data["redirect_uri"],
            "scope": flow_data["scope"],
            "tenant": flow_data.get("tenant", "consumers"),
        },
        verifier=flow_data["verifier"],
    )

    oauth_tool_service.discard_oauth_flow(state)
    session.pop("oauth_state", None)

    if token_data is None:
        if isinstance(error_info, dict):
            return build_error_response(
                "OAUTH_MICROSOFT_REQUEST_FAILED",
                error_info.get("message", "换取 Token 失败"),
                status=400,
                details=error_info.get("guidance"),
            )
        return build_error_response("OAUTH_MICROSOFT_REQUEST_FAILED", str(error_info), status=400)

    log_audit("create", "oauth_token", flow_data["client_id"], "Token 获取成功")
    return jsonify({"success": True, "data": token_data})


@login_required
def save_to_account() -> Any:
    _ensure_oauth_tool_enabled()
    data = request.get_json(silent=True) or {}
    mode = str(data.get("mode") or "").strip()
    refresh_token = (data.get("refresh_token") or "").strip()
    client_id = (data.get("client_id") or "").strip()

    if not refresh_token:
        return build_error_response("OAUTH_REFRESH_TOKEN_MISSING", "refresh_token 不能为空", status=400)
    if not client_id:
        return build_error_response("OAUTH_CONFIG_INVALID", "client_id 不能为空", status=400)

    compatibility_error = _compatibility_mode_error(
        (data.get("client_secret") or "").strip(),
        (data.get("tenant") or COMPATIBLE_TENANT).strip() or COMPATIBLE_TENANT,
    )
    if compatibility_error:
        return build_error_response("OAUTH_CONFIG_INVALID", compatibility_error, status=400)

    explicit_scope = (data.get("scope") or data.get("requested_scope") or data.get("granted_scope") or "").strip()
    validation_scope = explicit_scope or COMPATIBLE_SCOPE
    if not explicit_scope and validation_scope == LEGACY_GRAPH_SCOPE:
        validation_scope = COMPATIBLE_SCOPE

    valid, error_msg, new_rt = graph_service.test_refresh_token_with_rotation(
        client_id,
        refresh_token,
        tenant=COMPATIBLE_TENANT,
        scope=validation_scope,
    )
    if not valid:
        guidance = _save_validation_guidance(error_msg or "")
        return build_error_response(
            "OAUTH_MICROSOFT_REQUEST_FAILED",
            f"Token 验证失败: {error_msg}",
            status=400,
            details=guidance,
        )
    if new_rt:
        refresh_token = new_rt

    if mode == "update":
        account_id = data.get("account_id")
        if not account_id:
            return build_error_response("OAUTH_CONFIG_INVALID", "account_id 不能为空", status=400)
        try:
            account_id_int = int(account_id)
        except (TypeError, ValueError):
            return build_error_response("OAUTH_CONFIG_INVALID", "account_id 格式无效", status=400)

        existing = accounts_repo.get_account_by_id(account_id_int)
        if not existing:
            return build_error_response("ACCOUNT_NOT_FOUND", "账号不存在", status=404)

        success = accounts_repo.update_account_credentials(
            account_id_int,
            client_id=client_id,
            refresh_token=refresh_token,
        )
        if not success:
            return build_error_response("INTERNAL_ERROR", "更新账号失败", status=500)

        success = accounts_repo.update_account(
            account_id=account_id_int,
            email_addr=existing["email"],
            password=None,
            client_id=client_id,
            refresh_token=refresh_token,
            group_id=existing.get("group_id") or 1,
            remark=existing.get("remark") or "",
            status="active",
        )
        if not success:
            return build_error_response("INTERNAL_ERROR", "更新账号失败", status=500)

        log_audit(
            "update",
            "account",
            str(account_id_int),
            f"Token 工具写入 (client_id={client_id[:8]}...)",
        )
        return jsonify(
            {
                "success": True,
                "data": {
                    "account_id": account_id_int,
                    "email": existing["email"],
                    "status": "active",
                    "token_valid": True,
                },
            }
        )

    if mode == "create":
        email = (data.get("email") or "").strip()
        if not email or "@" not in email:
            return build_error_response("OAUTH_CONFIG_INVALID", "邮箱格式无效", status=400)

        success = accounts_repo.add_account(
            email_addr=email,
            password="",
            client_id=client_id,
            refresh_token=refresh_token,
            account_type="outlook",
            provider="outlook",
        )
        if not success:
            return build_error_response("INTERNAL_ERROR", "创建账号失败（邮箱可能已存在）", status=400)

        created = accounts_repo.get_account_by_email(email)
        log_audit("create", "account", email, f"Token 工具新建 (client_id={client_id[:8]}...)")
        return jsonify(
            {
                "success": True,
                "data": {
                    "account_id": created["id"] if created else None,
                    "email": email,
                    "status": "active",
                    "token_valid": True,
                },
            }
        )

    return build_error_response("OAUTH_CONFIG_INVALID", "mode 必须是 update 或 create", status=400)


@login_required
def get_account_list() -> Any:
    _ensure_oauth_tool_enabled()
    accounts = accounts_repo.load_accounts()
    result = [
        {
            "id": account["id"],
            "email": account["email"],
            "status": account.get("status", "active"),
            "account_type": account.get("account_type", "outlook"),
        }
        for account in accounts
        if account.get("account_type") in ("outlook", None)
    ]
    return jsonify({"success": True, "data": result})


@login_required
def get_config() -> Any:
    _ensure_oauth_tool_enabled()
    scope_value = settings_repo.get_oauth_tool_scope()
    if scope_value == LEGACY_GRAPH_SCOPE:
        scope_value = app_config.get_oauth_scope_default()
    return jsonify(
        {
            "success": True,
            "data": {
                "client_id": settings_repo.get_oauth_tool_client_id(),
                "client_secret": "",
                "redirect_uri": settings_repo.get_oauth_tool_redirect_uri(),
                "scope": scope_value,
                "tenant": COMPATIBLE_TENANT,
                "prompt_consent": settings_repo.get_oauth_tool_prompt_consent(),
            },
        }
    )


@login_required
def save_config() -> Any:
    _ensure_oauth_tool_enabled()
    data = request.get_json(silent=True) or {}
    client_secret = (data.get("client_secret") or "").strip()
    tenant = (data.get("tenant") or COMPATIBLE_TENANT).strip() or COMPATIBLE_TENANT
    compatibility_error = _compatibility_mode_error(client_secret, tenant)
    if compatibility_error:
        return build_error_response("OAUTH_CONFIG_INVALID", compatibility_error, status=400)

    settings_repo.set_setting("oauth_tool_client_id", (data.get("client_id") or "").strip())
    settings_repo.set_setting("oauth_tool_client_secret", "")
    settings_repo.set_setting("oauth_tool_redirect_uri", (data.get("redirect_uri") or "").strip())
    settings_repo.set_setting("oauth_tool_scope", (data.get("scope") or "").strip())
    settings_repo.set_setting("oauth_tool_tenant", COMPATIBLE_TENANT)
    settings_repo.set_setting("oauth_tool_prompt_consent", "true" if data.get("prompt_consent") else "false")

    log_audit("update", "oauth_tool_config", "settings", "保存 OAuth 工具配置")
    return jsonify({"success": True, "message": "配置已保存"})
