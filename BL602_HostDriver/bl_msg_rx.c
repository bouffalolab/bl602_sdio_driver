/**
 ******************************************************************************
 *
 *  @file bl_msg_rx.c
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

#include <linux/version.h>
#include "bl_defs.h"
#include "bl_tx.h"
#include "bl_ftrace.h"
#include "bl_debugfs.h"
#include "bl_msg_tx.h"
#include "bl_compat.h"
#include "bl_strs.h"

static int bl_freq_to_idx(struct bl_hw *bl_hw, int freq)
{
    struct ieee80211_supported_band *sband;
    int band, ch, idx = 0;

    for (band = NL80211_BAND_2GHZ; band < NUM_NL80211_BANDS; band++) {
        sband = bl_hw->wiphy->bands[band];
        if (!sband) {
            continue;
        }

        for (ch = 0; ch < sband->n_channels; ch++, idx++) {
            if (sband->channels[ch].center_freq == freq) {
                goto exit;
            }
        }
    }

    BUG_ON(1);

exit:
    // Channel has been found, return the index
    return idx;
}

/***************************************************************************
 * Messages from MM task
 **************************************************************************/
static inline int bl_rx_chan_pre_switch_ind(struct bl_hw *bl_hw,
                                              struct bl_cmd *cmd,
                                              struct ipc_e2a_msg *msg)
{
    struct bl_vif *bl_vif;
    int chan_idx = ((struct mm_channel_pre_switch_ind *)msg->param)->chan_index;

    BL_DBG(BL_FN_ENTRY_STR);

    list_for_each_entry(bl_vif, &bl_hw->vifs, list) {
        if (bl_vif->up && bl_vif->ch_index == chan_idx) {
            bl_txq_vif_stop(bl_vif, BL_TXQ_STOP_CHAN, bl_hw);
        }
    }

    return 0;
}

static inline int bl_rx_chan_switch_ind(struct bl_hw *bl_hw,
                                          struct bl_cmd *cmd,
                                          struct ipc_e2a_msg *msg)
{
    struct bl_vif *bl_vif;
    int chan_idx = ((struct mm_channel_switch_ind *)msg->param)->chan_index;
    bool roc     = ((struct mm_channel_switch_ind *)msg->param)->roc;

    BL_DBG(BL_FN_ENTRY_STR);

    if (!roc) {
        list_for_each_entry(bl_vif, &bl_hw->vifs, list) {
            if (bl_vif->up && bl_vif->ch_index == chan_idx) {
                bl_txq_vif_start(bl_vif, BL_TXQ_STOP_CHAN, bl_hw);
            }
        }
    } else {
        /* Retrieve the allocated RoC element */
        struct bl_roc_elem *roc_elem = bl_hw->roc_elem;
        /* Get VIF on which RoC has been started */
        bl_vif = netdev_priv(roc_elem->wdev->netdev);

        /* For debug purpose (use ftrace kernel option) */
        trace_switch_roc(bl_vif->vif_index);

        /* If mgmt_roc is true, remain on channel has been started by ourself */
        if (!roc_elem->mgmt_roc) {
            /* Inform the host that we have switch on the indicated off-channel */
            cfg80211_ready_on_channel(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
                                      roc_elem->wdev,
#else
                                      roc_elem->wdev->netdev,
#endif
                                      (u64)(bl_hw->roc_cookie_cnt),
                                      roc_elem->chan,
                                      roc_elem->channel_type,
                                      roc_elem->duration,
                                      GFP_KERNEL);
        }

        /* Keep in mind that we have switched on the channel */
        roc_elem->on_chan = true;

        // Enable traffic on OFF channel queue
        bl_txq_offchan_start(bl_hw);
    }

    bl_hw->cur_chanctx = chan_idx;

    return 0;
}

static inline int bl_rx_remain_on_channel_exp_ind(struct bl_hw *bl_hw,
                                                    struct bl_cmd *cmd,
                                                    struct ipc_e2a_msg *msg)
{
    /* Retrieve the allocated RoC element */
    struct bl_roc_elem *roc_elem = bl_hw->roc_elem;
    /* Get VIF on which RoC has been started */
    struct bl_vif *bl_vif = netdev_priv(roc_elem->wdev->netdev);

    BL_DBG(BL_FN_ENTRY_STR);

    /* For debug purpose (use ftrace kernel option) */
    trace_roc_exp(bl_vif->vif_index);

    /* If mgmt_roc is true, remain on channel has been started by ourself */
    /* If RoC has been cancelled before we switched on channel, do not call cfg80211 */
    if (!roc_elem->mgmt_roc && roc_elem->on_chan) {
        /* Inform the host that off-channel period has expired */
        cfg80211_remain_on_channel_expired(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
                                           roc_elem->wdev,
#else
                                           roc_elem->wdev->netdev,
#endif
                                           (u64)(bl_hw->roc_cookie_cnt),
                                           roc_elem->chan,
                                           roc_elem->channel_type,
                                           GFP_KERNEL);
    }

    /* De-init offchannel TX queue */
    bl_txq_offchan_deinit(bl_vif);

    /* Increase the cookie counter cannot be zero */
    bl_hw->roc_cookie_cnt++;

    if (bl_hw->roc_cookie_cnt == 0) {
        bl_hw->roc_cookie_cnt = 1;
    }

    /* Free the allocated RoC element */
    kfree(roc_elem);
    bl_hw->roc_elem = NULL;

    return 0;
}

static inline int bl_rx_p2p_vif_ps_change_ind(struct bl_hw *bl_hw,
                                                struct bl_cmd *cmd,
                                                struct ipc_e2a_msg *msg)
{
    int vif_idx  = ((struct mm_p2p_vif_ps_change_ind *)msg->param)->vif_index;
    int ps_state = ((struct mm_p2p_vif_ps_change_ind *)msg->param)->ps_state;
    struct bl_vif *vif_entry;

    BL_DBG(BL_FN_ENTRY_STR);

    vif_entry = bl_hw->vif_table[vif_idx];

    if (vif_entry) {
        goto found_vif;
    }

    goto exit;

found_vif:

    if (ps_state == MM_PS_MODE_OFF) {
        // Start TX queues for provided VIF
        bl_txq_vif_start(vif_entry, BL_TXQ_STOP_VIF_PS, bl_hw);
    }
    else {
        // Stop TX queues for provided VIF
        bl_txq_vif_stop(vif_entry, BL_TXQ_STOP_VIF_PS, bl_hw);
    }

exit:
    return 0;
}

static inline int bl_rx_channel_survey_ind(struct bl_hw *bl_hw,
                                             struct bl_cmd *cmd,
                                             struct ipc_e2a_msg *msg)
{
    struct mm_channel_survey_ind *ind = (struct mm_channel_survey_ind *)msg->param;
    // Get the channel index
    int idx = bl_freq_to_idx(bl_hw, ind->freq);
    // Get the survey
    struct bl_survey_info *bl_survey = &bl_hw->survey[idx];

    BL_DBG(BL_FN_ENTRY_STR);

    // Store the received parameters
    bl_survey->chan_time_ms = ind->chan_time_ms;
    bl_survey->chan_time_busy_ms = ind->chan_time_busy_ms;
    bl_survey->noise_dbm = ind->noise_dbm;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    bl_survey->filled = (SURVEY_INFO_CHANNEL_TIME |
                           SURVEY_INFO_CHANNEL_TIME_BUSY);
    #else
    bl_survey->filled = (SURVEY_INFO_TIME |
                           SURVEY_INFO_TIME_BUSY);
    #endif
#endif

    if (ind->noise_dbm != 0) {
        bl_survey->filled |= SURVEY_INFO_NOISE_DBM;
    }

    return 0;
}

static inline int bl_rx_rssi_status_ind(struct bl_hw *bl_hw,
                                          struct bl_cmd *cmd,
                                          struct ipc_e2a_msg *msg)
{
    struct mm_rssi_status_ind *ind = (struct mm_rssi_status_ind *)msg->param;
    int vif_idx  = ind->vif_index;
    bool rssi_status = ind->rssi_status;

    struct bl_vif *vif_entry;

    BL_DBG(BL_FN_ENTRY_STR);

    vif_entry = bl_hw->vif_table[vif_idx];
    if (vif_entry) {
        cfg80211_cqm_rssi_notify(vif_entry->ndev,
                                 rssi_status ? NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW :
                                               NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH,
                                 ind->rssi, GFP_KERNEL);
    }

    return 0;
}

static inline int bl_rx_csa_counter_ind(struct bl_hw *bl_hw,
                                          struct bl_cmd *cmd,
                                          struct ipc_e2a_msg *msg)
{
    struct mm_csa_counter_ind *ind = (struct mm_csa_counter_ind *)msg->param;
    struct bl_vif *vif;
    bool found = false;

    BL_DBG(BL_FN_ENTRY_STR);

    // Look for VIF entry
    list_for_each_entry(vif, &bl_hw->vifs, list) {
        if (vif->vif_index == ind->vif_index) {
            found=true;
            break;
        }
    }

    if (found) {
        if (vif->ap.csa)
            vif->ap.csa->count = ind->csa_count;
        else
            netdev_err(vif->ndev, "CSA counter update but no active CSA");
    }

    return 0;
}

static inline int bl_rx_csa_finish_ind(struct bl_hw *bl_hw,
                                         struct bl_cmd *cmd,
                                         struct ipc_e2a_msg *msg)
{
    struct mm_csa_finish_ind *ind = (struct mm_csa_finish_ind *)msg->param;
    struct bl_vif *vif;
    bool found = false;

    BL_DBG(BL_FN_ENTRY_STR);

    // Look for VIF entry
    list_for_each_entry(vif, &bl_hw->vifs, list) {
        if (vif->vif_index == ind->vif_index) {
            found=true;
            break;
        }
    }

    if (found) {
        if (BL_VIF_TYPE(vif) == NL80211_IFTYPE_AP ||
            BL_VIF_TYPE(vif) == NL80211_IFTYPE_P2P_GO) {
            if (vif->ap.csa) {
                vif->ap.csa->status = ind->status;
                vif->ap.csa->ch_idx = ind->chan_idx;
                schedule_work(&vif->ap.csa->work);
            } else
                netdev_err(vif->ndev, "CSA finish indication but no active CSA");
        } else {
            if (ind->status == 0) {
                bl_chanctx_unlink(vif);
                bl_chanctx_link(vif, ind->chan_idx, NULL);
                if (bl_hw->cur_chanctx == ind->chan_idx) {
                    bl_txq_vif_start(vif, BL_TXQ_STOP_CHAN, bl_hw);
                } else
                    bl_txq_vif_stop(vif, BL_TXQ_STOP_CHAN, bl_hw);
            }
        }
    }

    return 0;
}

static inline int bl_rx_csa_traffic_ind(struct bl_hw *bl_hw,
                                          struct bl_cmd *cmd,
                                          struct ipc_e2a_msg *msg)
{
    struct mm_csa_traffic_ind *ind = (struct mm_csa_traffic_ind *)msg->param;
    struct bl_vif *vif;
    bool found = false;

    BL_DBG(BL_FN_ENTRY_STR);

    // Look for VIF entry
    list_for_each_entry(vif, &bl_hw->vifs, list) {
        if (vif->vif_index == ind->vif_index) {
            found=true;
            break;
        }
    }

    if (found) {
        if (ind->enable)
            bl_txq_vif_start(vif, BL_TXQ_STOP_CSA, bl_hw);
        else
            bl_txq_vif_stop(vif, BL_TXQ_STOP_CSA, bl_hw);
    }

    return 0;
}

static inline int bl_rx_ps_change_ind(struct bl_hw *bl_hw,
                                        struct bl_cmd *cmd,
                                        struct ipc_e2a_msg *msg)
{
    struct mm_ps_change_ind *ind = (struct mm_ps_change_ind *)msg->param;
    struct bl_sta *sta = &bl_hw->sta_table[ind->sta_idx];

    BL_DBG(BL_FN_ENTRY_STR);

    netdev_dbg(bl_hw->vif_table[sta->vif_idx]->ndev,
               "Sta %d, change PS mode to %s", sta->sta_idx,
               ind->ps_state ? "ON" : "OFF");

    if (sta->valid) {
        bl_ps_bh_enable(bl_hw, sta, ind->ps_state);
    } else if (bl_hw->adding_sta) {
        sta->ps.active = ind->ps_state ? true : false;
    } else {
        netdev_err(bl_hw->vif_table[sta->vif_idx]->ndev,
                   "Ignore PS mode change on invalid sta\n");
    }

    return 0;
}


static inline int bl_rx_traffic_req_ind(struct bl_hw *bl_hw,
                                          struct bl_cmd *cmd,
                                          struct ipc_e2a_msg *msg)
{
    struct mm_traffic_req_ind *ind = (struct mm_traffic_req_ind *)msg->param;
    struct bl_sta *sta = &bl_hw->sta_table[ind->sta_idx];

    BL_DBG(BL_FN_ENTRY_STR);

    netdev_dbg(bl_hw->vif_table[sta->vif_idx]->ndev,
               "Sta %d, asked for %d pkt", sta->sta_idx, ind->pkt_cnt);

    bl_ps_bh_traffic_req(bl_hw, sta, ind->pkt_cnt,
                           ind->uapsd ? UAPSD_ID : LEGACY_PS_ID);

    return 0;
}
#ifdef  BL_RX_REORDER
static inline int bl_addba_req_ind(struct bl_hw *bl_hw,
                                          struct bl_cmd *cmd,
                                          struct ipc_e2a_msg *msg)
{
    struct mm_ba_add_req *ind = (struct mm_ba_add_req *)msg->param;
    struct rxreorder_list *reorder_list;	
	u8_l  i;

	
    BL_DBG(BL_FN_ENTRY_STR);
    if(ind->tid >= 8 || ind->sta_idx >= (NX_REMOTE_STA_MAX + NX_VIRT_DEV_MAX)){
        printk("invalid sta id %d or tid %d \n", ind->sta_idx, ind->tid);
        return 0;
	}
	BL_DBG("%s sta id %d tid %d start ssn %d  buf size %d\n", __func__,ind->sta_idx, ind->tid, le16_to_cpu(ind->ssn),ind->bufsz);

    reorder_list = &bl_hw->rx_reorder[ind->sta_idx][ind->tid];

    reorder_list->flag = true;
    reorder_list->check_start_win = true;
    reorder_list->start_win = le16_to_cpu(ind->ssn);
    reorder_list->win_size = ind->bufsz;
    reorder_list->end_win = (reorder_list->start_win + reorder_list->win_size) % MAX_SEQ_VALUE;
    reorder_list->start_win_index = 0;
    reorder_list->flush = false;

	for(i=0; i< reorder_list->win_size; i++){
        reorder_list->reorder_pkt[i] = NULL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
    timer_setup(&reorder_list->timer, bl_rx_reorder_flush, 0);
#else
    init_timer(&reorder_list->timer);
    reorder_list->timer.function = bl_rx_reorder_flush;
    reorder_list->timer.data = (void *)bl_hw;
#endif

    return 0;
}

static inline int bl_delba_req_ind(struct bl_hw *bl_hw,
                                          struct bl_cmd *cmd,
                                          struct ipc_e2a_msg *msg)
{
    struct mm_ba_del_req *ind = (struct mm_ba_del_req *)msg->param;
  //  struct bl_sta *sta = &bl_hw->sta_table[ind->sta_idx];
    struct rxreorder_list *reorder_list;
//	struct sk_buff *skb;
//	u8_l  i;

	
    BL_DBG(BL_FN_ENTRY_STR);
    if(ind->tid >= 8 || ind->sta_idx >= (NX_REMOTE_STA_MAX + NX_VIRT_DEV_MAX)){
        printk("invalid sta id %d or tid %d \n", ind->sta_idx, ind->tid);
        return 0;
	}
	
	BL_DBG("%s sta id %d tid %d \n", __func__,ind->sta_idx, ind->tid);
	
	reorder_list = &bl_hw->rx_reorder[ind->sta_idx][ind->tid];
	
    reorder_list->flag = false;
    reorder_list->start_win = 0;
    reorder_list->end_win = 0;
    reorder_list->last_seq = 0;
    reorder_list->start_win_index = 0;
    reorder_list->flush = false;
	reorder_list->del_ba = true;
	bl_hw->flush_rx = true;
	
	queue_work(bl_hw->rx_workqueue, &bl_hw->rx_work);
	
    if(reorder_list->is_timer_set)
        del_timer(&reorder_list->timer);
	reorder_list->is_timer_set = false;
    return 0;
}
#endif

/***************************************************************************
 * Messages from SCANU task
 **************************************************************************/
#ifdef CONFIG_BL_FULLMAC
static inline int bl_rx_scanu_start_cfm(struct bl_hw *bl_hw,
                                          struct bl_cmd *cmd,
                                          struct ipc_e2a_msg *msg)
{
    BL_DBG(BL_FN_ENTRY_STR);

    if (bl_hw->scan_request) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
        struct cfg80211_scan_info info = {
            .aborted = false,
        };

        cfg80211_scan_done(bl_hw->scan_request, &info);
#else
        cfg80211_scan_done(bl_hw->scan_request, false);
#endif
    }

    bl_hw->scan_request = NULL;

    return 0;
}

static inline int bl_rx_scanu_result_ind(struct bl_hw *bl_hw,
                                           struct bl_cmd *cmd,
                                           struct ipc_e2a_msg *msg)
{
    struct cfg80211_bss *bss = NULL;
    struct ieee80211_channel *chan;
    struct scanu_result_ind *ind = (struct scanu_result_ind *)msg->param;

    BL_DBG(BL_FN_ENTRY_STR);

    chan = ieee80211_get_channel(bl_hw->wiphy, ind->center_freq);

    if (chan != NULL)
        bss = cfg80211_inform_bss_frame(bl_hw->wiphy, chan,
                                        (struct ieee80211_mgmt *)ind->payload,
                                        ind->length, ind->rssi * 100, GFP_ATOMIC);

    if (bss != NULL)
        cfg80211_put_bss(bl_hw->wiphy, bss);

    return 0;
}
#endif /* CONFIG_BL_FULLMAC */

/***************************************************************************
 * Messages from ME task
 **************************************************************************/
#ifdef CONFIG_BL_FULLMAC
static inline int bl_rx_me_tkip_mic_failure_ind(struct bl_hw *bl_hw,
                                                  struct bl_cmd *cmd,
                                                  struct ipc_e2a_msg *msg)
{
    struct me_tkip_mic_failure_ind *ind = (struct me_tkip_mic_failure_ind *)msg->param;
    struct bl_vif *bl_vif = bl_hw->vif_table[ind->vif_idx];
    struct net_device *dev = bl_vif->ndev;

    BL_DBG(BL_FN_ENTRY_STR);

    cfg80211_michael_mic_failure(dev, (u8 *)&ind->addr, (ind->ga?NL80211_KEYTYPE_GROUP:
                                 NL80211_KEYTYPE_PAIRWISE), ind->keyid,
                                 (u8 *)&ind->tsc, GFP_ATOMIC);

    return 0;
}

static inline int bl_rx_me_tx_credits_update_ind(struct bl_hw *bl_hw,
                                                   struct bl_cmd *cmd,
                                                   struct ipc_e2a_msg *msg)
{
    struct me_tx_credits_update_ind *ind = (struct me_tx_credits_update_ind *)msg->param;

    BL_DBG(BL_FN_ENTRY_STR);

    bl_txq_credit_update(bl_hw, ind->sta_idx, ind->tid, ind->credits);

    return 0;
}
#endif /* CONFIG_BL_FULLMAC */

/***************************************************************************
 * Messages from SM task
 **************************************************************************/
static inline int bl_rx_sm_connect_ind(struct bl_hw *bl_hw,
                                         struct bl_cmd *cmd,
                                         struct ipc_e2a_msg *msg)
{
    struct sm_connect_ind *ind = (struct sm_connect_ind *)msg->param;
    struct bl_vif *bl_vif = bl_hw->vif_table[ind->vif_idx];
    struct net_device *dev;
    const u8 *req_ie, *rsp_ie;

    BL_DBG(BL_FN_ENTRY_STR);
    printk("%s : status code %x", __func__, ind->status_code);
	
    if(bl_vif)
        dev = bl_vif->ndev;
    else
        return 0;

    /* Retrieve IE addresses and lengths */
    req_ie = (const u8 *)ind->assoc_ie_buf;
    rsp_ie = req_ie + ind->assoc_req_ie_len;

    // Fill-in the AP information
    if (ind->status_code == 0)
    {
        struct bl_sta *sta = &bl_hw->sta_table[ind->ap_idx];
        u8 txq_status;
        sta->valid = true;
        sta->sta_idx = ind->ap_idx;
        sta->ch_idx = ind->ch_idx;
        sta->vif_idx = ind->vif_idx;
        sta->vlan_idx = sta->vif_idx;
        sta->qos = ind->qos;
        sta->acm = ind->acm;
        sta->ps.active = false;
        sta->aid = ind->aid;
        sta->band = ind->band;
        sta->width = ind->width;
        sta->center_freq = ind->center_freq;
        sta->center_freq1 = ind->center_freq1;
        sta->center_freq2 = ind->center_freq2;
        bl_vif->sta.ap = sta;
        // TODO: Get chan def in this case (add params in cfm ??)
        bl_chanctx_link(bl_vif, ind->ch_idx, NULL);
        memcpy(sta->mac_addr, ind->bssid.array, ETH_ALEN);
        if (ind->ch_idx == bl_hw->cur_chanctx) {
            txq_status = 0;
        } else {
            txq_status = BL_TXQ_STOP_CHAN;
        }
        memcpy(sta->ac_param, ind->ac_param, sizeof(sta->ac_param));
        bl_txq_sta_init(bl_hw, sta, txq_status);
        bl_dbgfs_register_rc_stat(bl_hw, sta);
    }

    if (!ind->roamed)
        cfg80211_connect_result(dev, (const u8 *)ind->bssid.array, req_ie,
                                ind->assoc_req_ie_len, rsp_ie,
                                ind->assoc_rsp_ie_len, ind->status_code,
                                GFP_ATOMIC);

    netif_tx_start_all_queues(dev);
    netif_carrier_on(dev);

    return 0;
}

static inline int bl_rx_sm_disconnect_ind(struct bl_hw *bl_hw,
                                            struct bl_cmd *cmd,
                                            struct ipc_e2a_msg *msg)
{
    struct sm_disconnect_ind *ind = (struct sm_disconnect_ind *)msg->param;
    struct bl_vif *bl_vif = bl_hw->vif_table[ind->vif_idx];
    struct net_device *dev;

    BL_DBG(BL_FN_ENTRY_STR);
    printk("%s : disconnect reason %x \n", __func__, ind->reason_code);

    if(bl_vif)
        dev = bl_vif->ndev;
    else
        return 0;

    /* if vif is not up, bl_close has already been called */
    if (bl_vif->up) {
        if (!ind->ft_over_ds) {
            cfg80211_disconnected(dev, ind->reason_code, NULL, 0, true, GFP_ATOMIC);
        }
        netif_tx_stop_all_queues(dev);
        netif_carrier_off(dev);
    }

#ifdef CONFIG_BL_BFMER
    /* Disable Beamformer if supported */
    bl_bfmer_report_del(bl_hw, bl_vif->sta.ap);
#endif //(CONFIG_BL_BFMER)

    bl_txq_sta_deinit(bl_hw, bl_vif->sta.ap);
    bl_dbgfs_unregister_rc_stat(bl_hw, bl_vif->sta.ap);
    bl_vif->sta.ap->valid = false;
    bl_vif->sta.ap = NULL;
    bl_chanctx_unlink(bl_vif);

    return 0;
}

/***************************************************************************
 * Messages from DEBUG task
 **************************************************************************/
static inline int bl_rx_dbg_error_ind(struct bl_hw *bl_hw,
                                        struct bl_cmd *cmd,
                                        struct ipc_e2a_msg *msg)
{
    BL_DBG(BL_FN_ENTRY_STR);

    bl_error_ind(bl_hw);

    return 0;
}

static msg_cb_fct mm_hdlrs[MSG_I(MM_MAX)] = {
    [MSG_I(MM_CHANNEL_SWITCH_IND)]     = bl_rx_chan_switch_ind,
    [MSG_I(MM_CHANNEL_PRE_SWITCH_IND)] = bl_rx_chan_pre_switch_ind,
    [MSG_I(MM_REMAIN_ON_CHANNEL_EXP_IND)] = bl_rx_remain_on_channel_exp_ind,
    [MSG_I(MM_PS_CHANGE_IND)]          = bl_rx_ps_change_ind,
    [MSG_I(MM_TRAFFIC_REQ_IND)]        = bl_rx_traffic_req_ind,
    [MSG_I(MM_CSA_COUNTER_IND)]        = bl_rx_csa_counter_ind,
    [MSG_I(MM_CSA_FINISH_IND)]         = bl_rx_csa_finish_ind,
    [MSG_I(MM_CSA_TRAFFIC_IND)]        = bl_rx_csa_traffic_ind,
    [MSG_I(MM_CHANNEL_SURVEY_IND)]     = bl_rx_channel_survey_ind,
    [MSG_I(MM_RSSI_STATUS_IND)]        = bl_rx_rssi_status_ind,
#ifdef  BL_RX_REORDER
    [MSG_I(MM_BA_ADD_REQ)]        = bl_addba_req_ind,    
    [MSG_I(MM_BA_DEL_REQ)]        = bl_delba_req_ind,
#endif
};

static msg_cb_fct scan_hdlrs[MSG_I(SCANU_MAX)] = {
    [MSG_I(SCANU_START_CFM)]           = bl_rx_scanu_start_cfm,
    [MSG_I(SCANU_RESULT_IND)]          = bl_rx_scanu_result_ind,
};

static msg_cb_fct me_hdlrs[MSG_I(ME_MAX)] = {
    [MSG_I(ME_TKIP_MIC_FAILURE_IND)] = bl_rx_me_tkip_mic_failure_ind,
    [MSG_I(ME_TX_CREDITS_UPDATE_IND)] = bl_rx_me_tx_credits_update_ind,
};

static msg_cb_fct sm_hdlrs[MSG_I(SM_MAX)] = {
    [MSG_I(SM_CONNECT_IND)]    = bl_rx_sm_connect_ind,
    [MSG_I(SM_DISCONNECT_IND)] = bl_rx_sm_disconnect_ind,
};

static msg_cb_fct apm_hdlrs[MSG_I(APM_MAX)] = {
};

static msg_cb_fct dbg_hdlrs[MSG_I(DBG_MAX)] = {
    [MSG_I(DBG_ERROR_IND)]                = bl_rx_dbg_error_ind,
};

static msg_cb_fct *msg_hdlrs[] = {
    [TASK_MM]    = mm_hdlrs,
    [TASK_DBG]   = dbg_hdlrs,
    [TASK_SCANU] = scan_hdlrs,
    [TASK_ME]    = me_hdlrs,
    [TASK_SM]    = sm_hdlrs,
    [TASK_APM]   = apm_hdlrs,
};

/**
 *
 */
void bl_rx_handle_msg(struct bl_hw *bl_hw, struct ipc_e2a_msg *msg)
{
	bool abnormal_msg = 0;
	BL_DBG(KERN_CRIT "recv: msg:%4d-%-24s\n", msg->id, BL_ID2STR(msg->id));

	switch (MSG_T(msg->id)) {
		case TASK_MM:
			if(MSG_I(msg->id) >= MM_MAX)
				abnormal_msg = 1;
			break;

		case TASK_DBG:
			if(MSG_I(msg->id) >= DBG_MAX)
				abnormal_msg = 1;
			break;

		case TASK_SCANU:
			if(MSG_I(msg->id) >= SCANU_MAX)
				abnormal_msg = 1;
			break;

		case TASK_ME:
			if(MSG_I(msg->id) >= ME_MAX)
				abnormal_msg = 1;
			break;

		case TASK_SM:
			if(MSG_I(msg->id) >= SM_MAX)
				abnormal_msg = 1;
			break;

		case TASK_APM:
			if(MSG_I(msg->id) >= APM_MAX)
				abnormal_msg = 1;
			break;

		default:
			abnormal_msg = 1;
			break;
	}

	if(!abnormal_msg)
		bl_hw->cmd_mgr.msgind(&bl_hw->cmd_mgr, msg, msg_hdlrs[MSG_T(msg->id)][MSG_I(msg->id)]);
	else
		printk("abnormal taskid %d-%d\n", MSG_T(msg->id), MSG_I(msg->id));
}
