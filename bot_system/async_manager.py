import asyncio
import logging
import time
from collections import deque

from . import config
from . import auth
from .async_client import BotClient

logger = logging.getLogger("Manager")

class BotManager:
    def __init__(self):
        self.active_bots = {} # username -> task
        self.bot_instances = {} # username -> BotClient instance
        self.running = True
        
        # 去重缓存: 存储 (message_content, timestamp)
        self.recent_messages = deque(maxlen=100)

    async def start(self):
        logger.info(f"BotManager (Async) 启动，配置账号数: {len(config.ACCOUNTS)}")
        
        # 启动监控任务
        monitor_task = asyncio.create_task(self.monitor_loop())
        
        try:
            # 保持主任务运行
            while self.running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def stop(self):
        self.running = False
        logger.info("正在停止所有机器人...")
        
        # 停止所有机器人实例
        for bot in self.bot_instances.values():
            bot.running = False
            await bot.close_connection()
            
        # 取消所有任务
        for task in self.active_bots.values():
            task.cancel()
            
        await asyncio.gather(*self.active_bots.values(), return_exceptions=True)

    async def monitor_loop(self):
        while self.running:
            # 清理已停止的任务
            for username in list(self.active_bots.keys()):
                task = self.active_bots[username]
                if task.done():
                    if task.exception():
                        logger.error(f"机器人 {username} 异常退出: {task.exception()}")
                    else:
                        logger.warning(f"机器人 {username} 已停止")
                    del self.active_bots[username]
                    if username in self.bot_instances:
                        del self.bot_instances[username]

            # 检查并启动机器人
            for account_str in config.ACCOUNTS:
                if ":" not in account_str:
                    continue
                
                username, password = account_str.split(":", 1)
                
                if username in self.active_bots:
                    continue
                
                logger.info(f"准备启动机器人: {username}")
                
                # 在线程池中执行阻塞的登录操作
                loop = asyncio.get_running_loop()
                try:
                    token, entity_id, l_ver = await loop.run_in_executor(
                        None, auth.perform_login, username, password
                    )
                except Exception as e:
                    logger.error(f"登录过程发生异常 ({username}): {e}")
                    token = None

                if token and entity_id:
                    if l_ver:
                        config.LAUNCHER_VERSION = l_ver
                        
                    # 创建并启动机器人
                    bot = BotClient(entity_id, token, entity_id, self)
                    self.bot_instances[username] = bot
                    
                    # 创建异步任务
                    task = asyncio.create_task(bot.run())
                    self.active_bots[username] = task
                    
                    # 错峰登录
                    await asyncio.sleep(5)
                else:
                    logger.warning(f"跳过启动 {username} (登录失败)")
            
            await asyncio.sleep(10)

    def on_chat_message(self, bot_instance, message_json):
        """
        处理来自机器人的聊天消息，并进行去重
        注意：此方法由 async_client 同步调用，不要使用 await
        """
        try:
            content_key = message_json
            current_time = time.time()
            
            # 检查是否在去重窗口内已处理过相同消息
            # Asyncio 是单线程的，这里不需要锁
            is_duplicate = False
            for msg, ts in self.recent_messages:
                if msg == content_key and (current_time - ts) < config.DEDUPLICATION_WINDOW:
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                self.recent_messages.append((content_key, current_time))
                self.process_unique_message(bot_instance, message_json)
                
        except Exception as e:
            logger.error(f"消息处理出错: {e}")

    def process_unique_message(self, bot_instance, message_json):
        logger.info(f"💬 [唯一消息] {message_json}")
        # 这里可以添加更多的业务逻辑，例如解析 JSON 内容
        try:
            msg_obj = None
            # 简单的 JSON 解析尝试
            import json
            msg_obj = json.loads(message_json)
            
            # 示例：提取文本
            if isinstance(msg_obj, dict):
                text = ""
                if 'text' in msg_obj:
                    text += msg_obj['text']
                if 'extra' in msg_obj:
                    for extra in msg_obj['extra']:
                        if isinstance(extra, dict) and 'text' in extra:
                            text += extra['text']
                        elif isinstance(extra, str):
                            text += extra
                if text:
                    print(f"Server Chat: {text}")
        except:
            pass
