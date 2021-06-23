/**
 ******************************************************************************
 *
 *  @file bl_main.h
 *
 *  Copyright (C) BouffaloLab 2017-2021
 *
 *  Licensed under the Apache License, Version 2.0 (the License);
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an ASIS BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************
 */


#ifndef _BL_MAIN_H_
#define _BL_MAIN_H_

#include "bl_defs.h"

/* odd number is set command, even number is get command */

#define BL_IOCTL_VERSION     (SIOCIWFIRSTPRIV + 1)

int bl_cfg80211_init(struct bl_plat *bl_plat, void **platform_data);
void bl_cfg80211_deinit(struct bl_hw *bl_hw);
int bl_ioctl(struct net_device *dev, struct ifreq *ifreq, int cmd);
int bl_iw_priv_handler(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);
#endif /* _BL_MAIN_H_ */
