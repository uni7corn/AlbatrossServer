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

from enum import IntFlag, IntEnum

from albatross.rpc_client import RpcClient, rpc_api, void, broadcast_api
from albatross.rpc_common import long, logger


class InsHookResult(IntEnum):
  HOOK_SUCCESS = 0
  ALREADY_HOOK = 1
  CLASS_NOT_FIND = -1
  METHOD_NOT_FIND = -2
  HOOK_FAIL = -3


class MethodScope(IntFlag):
  Static = 1
  Instance = 2
  Constructor = 4


class ExecutionOption(IntFlag):
  JIT_OSR = 1
  JIT_BASELINE = 2
  JIT_OPTIMIZED = 4

  DO_NOTHING = 0
  DECOMPILE = 8
  INTERPRETER = DECOMPILE
  DEFAULT_OPTION = 0x10

  RECOMPILE_OSR = JIT_OSR | DECOMPILE
  RECOMPILE_BASELINE = JIT_BASELINE | DECOMPILE
  RECOMPILE_OPTIMIZED = JIT_OPTIMIZED | DECOMPILE
  DISABLE_AOT = 0x20
  DISABLE_JIT = 0x40
  AOT = 0x80
  NATIVE_CODE = AOT | JIT_OPTIMIZED


class AppClient(RpcClient):

  @rpc_api
  def getuid(self) -> int:
    """
    获取当前进程的用户ID

    Returns:
        int: 用户ID
    """

  @rpc_api
  def get_package_name(self) -> str:
    """
    获取当前应用的包名

    Returns:
        str: 应用包名
    """

  @rpc_api
  def find_method(self, class_name: str, method_name: str, num_args: int, args: str = None) -> str:
    pass

  @rpc_api
  def hook_method(self, class_name: str, method_name: str, num_args: int, args: str = None,
      min_dex_pc: int = 0, max_dex_pc: int = 128, safe_string: bool = False) -> InsHookResult:
    """
    钩子方法，用于拦截和修改方法调用

    Args:
        class_name (str): 类名
        method_name (str): 方法名
        num_args (int): 参数数量
        args (str): 参数信息
        min_dex_pc (int): 最小的DEX程序计数器
        max_dex_pc (int): 最大的DEX程序计数器
        safe_string(bool): 参数是否可以安全的转换成字符串

    Returns:
        int: 监听器ID
    """

  @rpc_api
  def unhook_method(self, class_name: str, method_name: str, num_args: int, args: str = None) -> bool:
    """
    取消方法钩子

    Returns:
        bool: 是否成功取消钩子
    """

  @rpc_api
  def print_all_class_loader(self) -> str:
    pass

  @rpc_api
  def redirect_app_log(self, file_name: str = 'app') -> bool:
    pass

  @rpc_api
  def finish_redirect_app_log(self) -> bool:
    pass

  @rpc_api
  def set_logger(self, log_dir: str, log_file_name: str) -> void:
    pass

  @rpc_api
  def find_class(self, cls_name: str, application: bool = True,
      exec_mode: ExecutionOption = ExecutionOption.DO_NOTHING) -> str:
    pass

  @rpc_api
  def hook_class(self, class_name: str, application: bool = True, scope: MethodScope = MethodScope.Instance,
      safe_tostring: bool = False) -> str:
    pass

  @rpc_api
  def unhook_class(self, class_name: str, application: bool = True, scope: MethodScope = MethodScope.Instance) -> str:
    pass

  @rpc_api
  def class_loaders(self, sync: bool) -> str:
    pass

  @rpc_api
  def get_functions(self, lib_path: str) -> list:
    pass

  @rpc_api
  def get_modules(self, include_sys: bool = False) -> list:
    pass

  @rpc_api
  def init_native_log(self) -> void:
    pass

  @rpc_api
  def watch_func(self, symbol: str, address: long) -> void:
    pass

  @rpc_api
  def watch_library_load(self, on: bool = True) -> void:
    pass

  @rpc_api
  def dump_native_method(self) -> str:
    pass

  @broadcast_api
  def send(self, content: str, exception: str) -> void:
    if exception:
      logger.error("[#] %s %s", content, exception)
    elif not self.quiet:
      logger.info("[*] " + content)

  @broadcast_api
  def on_lib_load(self, lib_name: str, thread_id: str) -> void:
    logger.info(f'load library {lib_name} by {thread_id}')

  @rpc_api
  def set_to_string_config(self, max_length: int, show_bytes: bool = True) -> void:
    pass

  @rpc_api
  def read_file(self, path: str) -> str:
    pass

  def read_maps(self):
    return self.read_file('/proc/self/maps')

  def read_smaps(self):
    return self.read_file('/proc/self/smaps')
