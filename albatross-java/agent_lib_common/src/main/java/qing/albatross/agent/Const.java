/*
 * Copyright 2025 QingWan (qingwanmail@foxmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package qing.albatross.agent;

public class Const {
  public static final int CLEANUP_LOG = 0x40000;
  public static final int FLAG_LOG = 0x80000;
  public static final int REDIRECT_LOG = 0x100000;
//  public static final int WATCH_THREAD = 0x80000;

  public static final int DEX_LOAD_FAIL = 4;
  public static final int DEX_CLASS_NO_FIND = 5;
  public static final int DEX_INIT_FAIL = 6;
  public static final int METHOD_NO_FIND = 7;
  public static final int DEX_SYSTEM_SERVER_ERR = 9;
  public static final int DEX_PROCESS_SLEEPING = 10;
  public static final int DEX_LOAD_SUCCESS = 20;
  public static final int DEX_ALREADY_LOAD = 21;

}
