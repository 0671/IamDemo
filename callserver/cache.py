import time

class TimedCache:
    def __init__(self):
        self.cache = {}

    def set(self, key, value, timeout=60*60):
        """设置缓存，并指定过期时间（默认1小时）"""
        expire_time = time.time() + timeout
        self.cache[key] = (value, expire_time)

    def get(self, key):
        """获取缓存，若过期则返回None"""
        item = self.cache.get(key)
        if item:
            value, expire_time = item
            if time.time() < expire_time:
                return value
            else:
                # 缓存已过期，删除项
                del self.cache[key]
        return None

    def delete(self, key):
        """删除缓存"""
        if key in self.cache:
            del self.cache[key]

    def clear(self):
        """清除所有缓存"""
        self.cache.clear()

# 使用示例
tc = TimedCache()
# cache.set('name', 'Bob', timeout=5)  # 设置5秒后过期
# time.sleep(6)
# print(cache.get('name'))  # 输出: None，因为已经过期
