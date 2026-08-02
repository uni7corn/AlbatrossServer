# Copyright 2025 QingWan (qingwanmail@foxmail.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import asyncio
import inspect
import threading
import weakref
from collections import defaultdict


def __get_nil():
  class __NIL:
    def __str__(self):
      return "NIL"

    __repr__ = __str__

    def __bool__(self):
      return False

    def __len__(self):
      return 0

  return __NIL()


nil_value = __get_nil()


class TimeoutLock:
  """带超时功能的锁上下文管理器"""

  acquire_lock = False

  def __init__(self, lock=None, timeout=10):
    # 默认为可重入锁，兼容你之前的 threading.RLock
    self.lock = lock or threading.RLock()
    self.timeout = timeout

  def acquire(self, timeout=None):
    """获取锁，支持覆盖默认超时时间"""
    actual_timeout = timeout if timeout is not None else self.timeout
    # 带超时获取锁
    acquired = self.lock.acquire(timeout=actual_timeout)
    self.acquire_lock = acquired

  def release(self):
    """释放锁"""
    if self.acquire_lock:
      self.lock.release()
      self.acquire_lock = False

  def __enter__(self):
    """with 语句进入时调用"""
    # if not self.acquire():
    #   raise TimeoutError(f"获取锁超时（超时时间：{self.timeout} 秒）")
    self.acquire()
    return self

  def __exit__(self, exc_type, exc_val, exc_tb):
    """with 语句退出时调用"""
    self.release()
    # 不抑制异常，让异常正常抛出
    return False


class cached_property(object):
  nil_value = nil_value

  def __init__(self, func):
    self.__doc__ = getattr(func, "__doc__")
    self.__name__ = getattr(func, "__name__", None)
    self.func = func
    self.is_async = inspect.iscoroutinefunction(func)
    self.lock = threading.RLock()
    self.object_locks = {}

  def __get__(self, obj, cls):
    func = self.func
    if obj is None:
      return self
    attr_name = func.__name__
    if self.is_async:
      return self._get_async(obj, attr_name)
    obj_dict = obj.__dict__
    val = obj_dict.get(attr_name, nil_value)
    if val is nil_value:
      obj_id = id(obj)
      with self.lock:
        obj_lock = self.object_locks.get(obj_id)
        if obj_lock is None:
          acquire_lock = True
          obj_lock = threading.RLock()
          self.object_locks[obj_id] = obj_lock
        else:
          acquire_lock = False
      try:
        with obj_lock:
          val = obj_dict.get(attr_name, nil_value)
          if val is nil_value:
            val = func(obj)
            if val is not nil_value:
              obj_dict[attr_name] = val
      finally:
        if acquire_lock:
          with self.lock:
            if self.object_locks.get(obj_id) is obj_lock:
              self.object_locks.pop(obj_id, None)
    return val

  async def _get_async(self, obj, attr_name):
    obj_dict = obj.__dict__
    val = obj_dict.get(attr_name, nil_value)
    if val is nil_value:
      lock_name = f"__cached_property_async_lock_{attr_name}"
      async_lock = obj_dict.get(lock_name)
      if async_lock is None:
        with self.lock:
          async_lock = obj_dict.get(lock_name)
          if async_lock is None:
            async_lock = asyncio.Lock()
            obj_dict[lock_name] = async_lock
      async with async_lock:
        val = obj_dict.get(attr_name, nil_value)
        if val is nil_value:
          val = await self.func(obj)
          if val is not nil_value:
            obj_dict[attr_name] = val
    return val

  @staticmethod
  def reset(obj, attr, v):
    obj.__dict__[attr] = v

  @staticmethod
  def delete(obj, attr):
    obj.__dict__.pop(attr, None)

  @staticmethod
  def get(obj, attr):
    return obj.__dict__.get(attr, nil_value)

  @staticmethod
  def pop(obj, attr):
    return obj.__dict__.pop(attr, nil_value)

  @staticmethod
  def remove_cached_property(obj):
    count = 0
    props = obj.__class__.__dict__
    for k, v in props.items():
      if isinstance(v, cached_property):
        res = obj.__dict__.pop(k, nil_value)
        if res is not nil_value:
          count += 1
    return count


class cached_class_property(object):
  v = nil_value
  nil_value = nil_value

  cls_property_tables = defaultdict(dict)

  def __init__(self, func):
    self.__doc__ = getattr(func, "__doc__")
    self.__name__ = getattr(func, "__name__", None)
    self.is_async = inspect.iscoroutinefunction(func)
    if sys.gettrace():
      v = [False]

      def _wrapper(*args, **kwargs):
        if v[0] is True:
          return nil_value
        v[0] = True
        try:
          return func(*args, **kwargs)
        finally:
          v[0] = False

      async def _async_wrapper(*args, **kwargs):
        if v[0] is True:
          return nil_value
        v[0] = True
        try:
          return await func(*args, **kwargs)
        finally:
          v[0] = False

      if self.is_async:
        _async_wrapper.__name__ = func.__name__
        self.func = _async_wrapper
      else:
        _wrapper.__name__ = func.__name__
        self.func = _wrapper
    else:
      self.func = func
    self.lock = threading.RLock()
    self.async_locks = weakref.WeakKeyDictionary()

  @staticmethod
  def reset(cls, attr, v):
    cls_property = cached_class_property._find_descriptor(cls, attr)
    if cls_property is not None:
      cls_property.v = v
    #   if not cls_property.is_async:
    #     setattr(cls_property._owner_cls(cls), attr, v)
    # else:
    setattr(cls, attr, v)

  @staticmethod
  def delete(cls, attr):
    cls_property = cached_class_property._find_descriptor(cls, attr)
    if cls_property is None:
      try:
        delattr(cls, attr)
        return True
      except Exception:
        return False
    owner_cls = cls_property._owner_cls(cls)
    try:
      cls_property.v = nil_value
      setattr(owner_cls, attr, cls_property)
      return True
    except Exception:
      return False

  @staticmethod
  def pop(cls, attr):
    cls_property = cached_class_property._find_descriptor(cls, attr)
    if cls_property is not None:
      v = cls_property.v
      cached_class_property.delete(cls, attr)
      return v
    return nil_value

  @staticmethod
  def try_get(cls, attr, default_value=nil_value):
    cls_property = cached_class_property._find_descriptor(cls, attr)
    if cls_property is None:
      if hasattr(cls, attr):
        v = getattr(cls, attr)
        return v
      return default_value
    v = cls_property.v
    if v is nil_value:
      return default_value
    return v

  @classmethod
  def _find_descriptor(cls, owner_cls, attr):
    for base in owner_cls.__mro__:
      descriptor = cls.cls_property_tables.get(base, {}).get(attr)
      if descriptor is not None:
        return descriptor
      value = base.__dict__.get(attr, nil_value)
      if isinstance(value, cached_class_property):
        return value
    return None

  def _owner_cls(self, cls):
    func_name = self.func.__name__
    if cls.__dict__.get(func_name) is self:
      return cls
    for base in cls.__mro__:
      if self.cls_property_tables.get(base, {}).get(func_name) is self:
        return base
      if base.__dict__.get(func_name) is self:
        return base
    return cls

  def __get__(self, obj, cls):
    func = self.func
    func_name = func.__name__
    if self.is_async:
      return self._get_async(obj, cls)
    v = self.v
    cls_base = self._owner_cls(cls)
    if v is nil_value:
      with self.lock:
        v = self.v
        if v is nil_value:
          v = func(cls)
          if v is not nil_value:
            setattr(cls_base, func_name, v)
            self.cls_property_tables[cls_base][func_name] = self
            self.v = v
    else:
      setattr(cls, func_name, v)
    if obj is not None and v.__class__.__name__ == 'function':
      return getattr(obj, func_name)
    return v

  async def _get_async(self, obj, cls):
    func = self.func
    func_name = func.__name__
    v = self.v
    cls_base = self._owner_cls(cls)
    if v is nil_value:
      with self.lock:
        async_lock = self.async_locks.get(cls_base)
        if async_lock is None:
          async_lock = asyncio.Lock()
          self.async_locks[cls_base] = async_lock
      async with async_lock:
        v = self.v
        if v is nil_value:
          v = await func(cls)
          if v is not nil_value:
            self.cls_property_tables[cls_base][func_name] = self
            self.v = v
    if obj is not None and v.__class__.__name__ == 'function':
      return getattr(obj, func_name)
    return v


class cached_subclass_property(cached_class_property):

  def __init__(self, func):
    super().__init__(func)
    self.value_tables = weakref.WeakKeyDictionary()

  @staticmethod
  def try_get(cls, attr, default_value=nil_value):
    if attr not in cls.__dict__:
      return default_value
    if hasattr(cls, attr):
      v = getattr(cls, attr)
      return v
    return default_value

  @staticmethod
  def reset(cls, attr, v):
    setattr(cls, attr, v)

  @staticmethod
  def delete(cls, attr):
    try:
      delattr(cls, attr)
      return True
    except Exception:
      return False

  def __get__(self, obj, cls):
    func = self.func
    func_name = func.__name__
    if func_name in cls.__dict__:
      raise Exception("can not call class property in abstract class {}".format(cls.__name__))
    if self.is_async:
      return self._get_async(obj, cls)
    value_tables = self.value_tables
    v = value_tables.get(cls, nil_value)
    if v is nil_value:
      with self.lock:
        v = value_tables.get(cls, nil_value)
        if v is nil_value:
          v = func(cls)
          if v is not nil_value:
            setattr(cls, func_name, v)
            value_tables[cls] = v
    else:
      setattr(cls, func_name, v)
    value_tables.pop(cls, None)
    if obj is not None and v.__class__.__name__ == 'function':
      return getattr(obj, func_name)
    return v

  async def _get_async(self, obj, cls):
    func = self.func
    func_name = func.__name__
    value_tables = self.value_tables
    v = value_tables.get(cls, nil_value)
    if v is nil_value:
      with self.lock:
        async_lock = self.async_locks.get(cls)
        if async_lock is None:
          async_lock = asyncio.Lock()
          self.async_locks[cls] = async_lock
      async with async_lock:
        v = value_tables.get(cls, nil_value)
        if v is nil_value:
          v = await func(cls)
          if v is not nil_value:
            value_tables[cls] = v
    if obj is not None and v.__class__.__name__ == 'function':
      return getattr(obj, func_name)
    return v
