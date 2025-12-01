import logging
import config

try:
    from netease_auth_server.client import NeteaseClient
except ImportError:
    NeteaseClient = None

try:
    from netease_auth_server.auth_api import NeteaseAuthApi
except ImportError:
    NeteaseAuthApi = None

try:
    from netease_auth_server.c4399_api import C4399Api
except ImportError:
    C4399Api = None

logger = logging.getLogger("Auth")

def perform_login(username, password):
    """
    执行 4399 -> 网易验证流程
    返回: (token, entity_id, launcher_version)
    """
    if not (C4399Api and NeteaseAuthApi):
        logger.error("缺少登录模块，无法登录")
        return None, None, None

    try:
        logger.info(f"正在为 {username} 进行 4399 登录...")
        c4399 = C4399Api()
        sauth = c4399.login_with_password(username, password)
        
        api = NeteaseAuthApi()
        try:
            login_result = api.x19_login_with_sauth(sauth)
            if not login_result:
                raise ValueError("Login API returned None")
            entity_id, token, auth_otp = login_result
        except TypeError as te:
            # Catching the specific 'NoneType' object is not subscriptable error from within the library
            if "'NoneType' object is not subscriptable" in str(te):
                logger.error(f"登录API返回格式错误 (可能是账号被封禁): {te}")
                return None, None, None
            raise te
        
        launcher_ver = api.game_version if api.game_version else config.LAUNCHER_VERSION
        
        logger.info(f"登录成功! User: {username}, EntityID: {entity_id}")
        return token, entity_id, launcher_ver
    except Exception as e:
        logger.error(f"登录失败 ({username}): {e}")
        return None, None, None
