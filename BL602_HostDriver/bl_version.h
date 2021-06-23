/**
 ******************************************************************************
 *
 *  @file bl_version.h
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

#ifndef _BL_VERSION_H_
#define _BL_VERSION_H_

//#include "bl_version_gen.h"

#define RELEASE_VERSION  "105"

static inline void bl_print_version(void)
{
    printk("BL Wlan Driver version %s \n", RELEASE_VERSION);
}

#endif /* _BL_VERSION_H_ */
