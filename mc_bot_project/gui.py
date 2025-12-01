import asyncio
import logging
import os

# 设置 Kivy 环境变量，防止在某些环境下报错
os.environ["KIVY_NO_CONSOLELOG"] = "1"

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.clock import Clock
from kivy.utils import platform

import manager
import config

# 自定义日志处理器，将日志输出到界面上的文本框
class KivyLogHandler(logging.Handler):
    def __init__(self, text_input):
        super().__init__()
        self.text_input = text_input

    def emit(self, record):
        msg = self.format(record)
        # Kivy 的 UI 更新必须在主线程进行
        Clock.schedule_once(lambda dt: self.append_log(msg))

    def append_log(self, msg):
        self.text_input.text += msg + '\n'
        # 保持滚动到底部（简单实现）
        # self.text_input.cursor = (0, len(self.text_input.text))

class MCBotApp(App):
    def build(self):
        self.title = "4399 MC Bot"
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # 日志显示区域
        self.log_area = TextInput(
            readonly=True, 
            font_size=14, 
            background_color=(0.1, 0.1, 0.1, 1), 
            foreground_color=(0.9, 0.9, 0.9, 1),
            size_hint=(1, 0.8)
        )
        layout.add_widget(self.log_area)
        
        # 按钮区域
        btn_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.2), spacing=10)
        
        self.btn_start = Button(text='启动挂机', background_color=(0, 0.8, 0, 1))
        self.btn_start.bind(on_press=self.start_bots)
        
        self.btn_stop = Button(text='停止挂机', background_color=(0.8, 0, 0, 1), disabled=True)
        self.btn_stop.bind(on_press=self.stop_bots)
        
        btn_layout.add_widget(self.btn_start)
        btn_layout.add_widget(self.btn_stop)
        layout.add_widget(btn_layout)
        
        # 配置日志
        self.setup_logging()
        
        self.bot_manager = None
        self.manager_task = None
        
        return layout

    def setup_logging(self):
        handler = KivyLogHandler(self.log_area)
        formatter = logging.Formatter('[%(time)s] %(msg)s')
        # 自定义简单的格式化，因为手机屏幕窄
        def format_record(record):
            import datetime
            t = datetime.datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
            return f"[{t}] {record.levelname}: {record.getMessage()}"
        
        handler.format = format_record
        
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.INFO)

    def start_bots(self, instance):
        self.log_area.text += ">>> 正在初始化机器人...\n"
        self.btn_start.disabled = True
        self.btn_stop.disabled = False
        
        self.bot_manager = manager.BotManager()
        # 创建异步任务启动管理器
        self.manager_task = asyncio.create_task(self.bot_manager.start())

    def stop_bots(self, instance):
        if self.bot_manager:
            self.log_area.text += ">>> 正在停止...\n"
            # 创建停止任务
            asyncio.create_task(self.stop_sequence())

    async def stop_sequence(self):
        await self.bot_manager.stop()
        self.btn_start.disabled = False
        self.btn_stop.disabled = True
        self.log_area.text += ">>> 已全部停止\n"

    # 覆盖 async_run 以支持 asyncio
    async def async_run(self, async_lib=None):
        return await super().async_run(async_lib='asyncio')

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(MCBotApp().async_run(async_lib='asyncio'))
    except Exception as e:
        print(e)
