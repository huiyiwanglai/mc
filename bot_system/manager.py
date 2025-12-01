import time
import logging
import threading
import json
from collections import deque

from . import config
from . import auth
from .client import BotClient

logger = logging.getLogger("Manager")

class BotManager:
    def __init__(self):
        self.active_bots = {} # username -> BotClient
        self.running = True
        
        # 去重缓存: 存储 (message_content, timestamp)
        # 简单起见，我们只存储最近的消息内容和接收时间
        self.recent_messages = deque(maxlen=100)
        self.message_lock = threading.Lock()

    def start(self):
        logger.info(f"BotManager 启动，配置账号数: {len(config.ACCOUNTS)}")
        
        # 启动监控线程
        monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        monitor_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        logger.info("正在停止所有机器人...")
        for bot in self.active_bots.values():
            bot.running = False
        for bot in self.active_bots.values():
            bot.join()

    def monitor_loop(self):
        while self.running:
            # 清理已停止的机器人
            for username in list(self.active_bots.keys()):
                bot = self.active_bots[username]
                if not bot.is_alive():
                    logger.warning(f"机器人 {username} 已停止，将在稍后重启")
                    del self.active_bots[username]

            # 检查并启动机器人
            for account_str in config.ACCOUNTS:
                if ":" not in account_str:
                    continue
                
                username, password = account_str.split(":", 1)
                
                if username in self.active_bots:
                    continue
                
                logger.info(f"准备启动机器人: {username}")
                
                # 执行登录
                token, entity_id, l_ver = auth.perform_login(username, password)
                
                if token and entity_id:
                    if l_ver:
                        config.LAUNCHER_VERSION = l_ver
                        
                    # 创建并启动机器人，传入 self 作为 manager
                    bot = BotClient(entity_id, token, entity_id, self)
                    bot.start()
                    self.active_bots[username] = bot
                    
                    # 错峰登录
                    time.sleep(5)
                else:
                    logger.warning(f"跳过启动 {username} (登录失败)")
            
            time.sleep(10)

    def on_chat_message(self, bot_instance, message_json):
        """
        处理来自机器人的聊天消息，并进行去重
        """
        try:
            # 尝试解析 JSON 提取纯文本内容以便去重
            # 这里简化处理，直接使用 JSON 字符串作为去重键
            # 实际应用中可能需要解析 tellraw 格式提取 text
            content_key = message_json
            
            current_time = time.time()
            
            with self.message_lock:
                # 检查是否在去重窗口内已处理过相同消息
                is_duplicate = False
                for msg, ts in self.recent_messages:
                    if msg == content_key and (current_time - ts) < config.DEDUPLICATION_WINDOW:
                        is_duplicate = True
                        break
                
                if is_duplicate:
                    # logger.debug(f"忽略重复消息: {content_key[:20]}...")
                    return

                # 记录新消息
                self.recent_messages.append((content_key, current_time))
            
            # --- 这里是处理唯一消息的地方 ---
            self.process_unique_message(message_json)
            
        except Exception as e:
            logger.error(f"处理消息去重时出错: {e}")

    def process_unique_message(self, message_json):
        """
        处理去重后的唯一消息
        """
        # 在这里可以将数据写入数据库、文件或进行其他逻辑处理
        logger.info(f"💬 [唯一消息] {message_json}")
        
        # 示例：解析并打印更友好的格式
        try:
            data = json.loads(message_json)
            text = ""
            if isinstance(data, dict):
                text = data.get('text', '')
                if 'extra' in data:
                    for extra in data['extra']:
                        text += extra.get('text', '')
            elif isinstance(data, list):
                for part in data:
                    if isinstance(part, dict):
                        text += part.get('text', '')
                    elif isinstance(part, str):
                        text += part
            else:
                text = str(data)
            
            if text:
                print(f"Server Chat: {text}")
        except:
            pass
