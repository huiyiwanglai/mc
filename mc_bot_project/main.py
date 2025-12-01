import sys
import logging
import os
import asyncio

# 确保当前目录在 sys.path 中
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from manager import BotManager

async def async_main():
    manager = BotManager()
    await manager.start()

def main():
    # 配置根日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s] %(levelname)s [%(name)s]: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler('bot_system.log', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
