kernel/crypto/pcbc.ko crypto_pcbc pcbc

kernel/crypto/ccm.ko crypto_ccm ccm crypto_rfc4309 rfc4309 crypto_ccm_base ccm_base

kernel/crypto/ecb.ko crypto_ecb ecb

kernel/crypto/jitterentropy_rng.ko crypto_jitterentropy_rng jitterentropy_rng

kernel/crypto/gf128mul.ko symbol:gf128mul_64k_lle symbol:gf128mul_free_64k symbol:gf128mul_bbe symbol:gf128mul_4k_lle symbol:gf128mul_lle symbol:gf128mul_x_ble symbol:gf128mul_64k_bbe symbol:gf128mul_4k_bbe symbol:gf128mul_init_64k_bbe symbol:gf128mul_init_4k_bbe symbol:gf128mul_init_64k_lle symbol:gf128mul_init_4k_lle

kernel/crypto/seqiv.ko crypto_seqiv seqiv

kernel/crypto/sha256_generic.ko crypto_sha256_generic sha256_generic crypto_sha256 sha256 crypto_sha224_generic sha224_generic crypto_sha224 sha224 symbol:crypto_sha256_update symbol:crypto_sha256_finup

kernel/crypto/fcrypt.ko crypto_fcrypt fcrypt

kernel/crypto/ctr.ko crypto_ctr ctr crypto_rfc3686 rfc3686

kernel/crypto/cmac.ko crypto_cmac cmac

kernel/crypto/ghash-generic.ko crypto_ghash_generic ghash_generic crypto_ghash ghash
gf128mul

kernel/crypto/echainiv.ko crypto_echainiv echainiv

kernel/crypto/drbg.ko crypto_stdrng stdrng crypto_drbg_nopr_hmac_sha1 drbg_nopr_hmac_sha1 crypto_drbg_pr_hmac_sha1 drbg_pr_hmac_sha1 crypto_drbg_nopr_hmac_sha256 drbg_nopr_hmac_sha256 crypto_drbg_pr_hmac_sha256 drbg_pr_hmac_sha256 crypto_drbg_nopr_hmac_sha384 drbg_nopr_hmac_sha384 crypto_drbg_pr_hmac_sha384 drbg_pr_hmac_sha384 crypto_drbg_nopr_hmac_sha512 drbg_nopr_hmac_sha512 crypto_drbg_pr_hmac_sha512 drbg_pr_hmac_sha512

kernel/crypto/arc4.ko crypto_arc4 arc4

kernel/crypto/gcm.ko crypto_gcm gcm crypto_rfc4543 rfc4543 crypto_rfc4106 rfc4106 crypto_gcm_base gcm_base

kernel/crypto/hmac.ko crypto_hmac hmac

kernel/fs/autofs4/autofs4.ko fs_autofs devname:autofs char_major_10_235

kernel/net/phonet/pn_pep.ko net_pf_35_proto_2
phonet

kernel/net/phonet/phonet.ko net_pf_35 symbol:pn_sock_unhash symbol:phonet_stream_ops symbol:pn_sock_get_port symbol:pn_sock_hash symbol:phonet_header_ops symbol:pn_skb_send symbol:phonet_proto_register symbol:phonet_proto_unregister

kernel/net/rxrpc/rxkad.ko
af_rxrpc

kernel/net/rxrpc/af-rxrpc.ko net_pf_33 symbol:rxrpc_kernel_end_call symbol:rxrpc_kernel_begin_call symbol:rxrpc_kernel_intercept_rx_messages symbol:rxrpc_kernel_reject_call symbol:rxrpc_kernel_accept_call symbol:rxrpc_get_server_data_key symbol:rxrpc_get_null_key symbol:key_type_rxrpc symbol:rxrpc_kernel_abort_call symbol:rxrpc_kernel_send_data symbol:rxrpc_kernel_data_delivered symbol:rxrpc_kernel_get_abort_code symbol:rxrpc_kernel_get_error_number symbol:rxrpc_kernel_is_data_last symbol:rxrpc_unregister_security symbol:rxrpc_register_security symbol:rxrpc_kernel_free_skb

kernel/net/mac80211/mac80211.ko symbol:ieee80211_free_hw symbol:ieee80211_alloc_hw_nm symbol:ieee80211_unregister_hw symbol:ieee80211_register_hw symbol:ieee80211_restart_hw symbol:ieee80211_free_txskb symbol:ieee80211_tx_status_noskb symbol:ieee80211_report_low_ack symbol:ieee80211_tx_status symbol:ieee80211_tx_status_irqsafe symbol:ieee80211_find_sta symbol:ieee80211_find_sta_by_ifaddr symbol:ieee80211_sta_block_awake symbol:ieee80211_sta_set_buffered symbol:ieee80211_sta_eosp symbol:ieee80211_sched_scan_stopped symbol:ieee80211_scan_completed symbol:ieee80211_sched_scan_results symbol:ieee80211_ready_on_channel symbol:ieee80211_remain_on_channel_expired symbol:ieee80211_request_smps symbol:ieee80211_send_bar symbol:ieee80211_start_tx_ba_cb_irqsafe symbol:ieee80211_start_tx_ba_session symbol:ieee80211_stop_tx_ba_cb_irqsafe symbol:ieee80211_stop_tx_ba_session symbol:ieee80211_start_rx_ba_session_offl symbol:ieee80211_stop_rx_ba_session symbol:ieee80211_stop_rx_ba_session_offl symbol:rate_control_send_low symbol:rate_control_set_rates symbol:ieee80211_rate_control_register symbol:ieee80211_get_tx_rates symbol:ieee80211_rate_control_unregister symbol:ieee80211_get_tkip_p1k_iv symbol:ieee80211_get_tkip_rx_p1k symbol:ieee80211_get_tkip_p2k symbol:ieee80211_csa_finish symbol:ieee80211_sta_ps_transition symbol:ieee80211_rx_irqsafe symbol:ieee80211_rx_napi symbol:ieee80211_pspoll_get symbol:ieee80211_csa_update_counter symbol:ieee80211_csa_is_complete symbol:ieee80211_ctstoself_get symbol:ieee80211_beacon_get_template symbol:ieee80211_probereq_get symbol:ieee80211_proberesp_get symbol:ieee80211_tx_dequeue symbol:ieee80211_get_buffered_bc symbol:ieee80211_nullfunc_get symbol:ieee80211_tx_prepare_skb symbol:ieee80211_beacon_get_tim symbol:ieee80211_rts_get symbol:ieee80211_unreserve_tid symbol:ieee80211_reserve_tid symbol:ieee80211_remove_key symbol:ieee80211_set_key_rx_seq symbol:ieee80211_get_key_tx_seq symbol:ieee80211_iter_keys symbol:ieee80211_get_key_rx_seq symbol:ieee80211_set_key_tx_seq symbol:ieee80211_gtk_rekey_notify symbol:ieee80211_gtk_rekey_add symbol:ieee80211_wake_queue symbol:ieee80211_iterate_stations_atomic symbol:ieee80211_iterate_interfaces symbol:ieee80211_wake_queues symbol:ieee80211_rts_duration symbol:ieee80211_iterate_active_interfaces_atomic symbol:ieee80211_queue_delayed_work symbol:ieee80211_update_p2p_noa symbol:ieee80211_stop_queue symbol:ieee80211_ctstoself_duration symbol:wiphy_to_ieee80211_hw symbol:ieee80211_generic_frame_duration symbol:ieee80211_parse_p2p_noa symbol:ieee80211_vif_to_wdev symbol:ieee80211_disable_rssi_reports symbol:ieee80211_resume_disconnect symbol:ieee80211_ave_rssi symbol:ieee80211_queue_work symbol:ieee80211_iterate_active_interfaces_rtnl symbol:ieee80211_stop_queues symbol:ieee80211_radar_detected symbol:wdev_to_ieee80211_vif symbol:ieee80211_enable_rssi_reports symbol:ieee80211_queue_stopped symbol:ieee80211_iter_chan_contexts_atomic symbol:ieee80211_ap_probereq_get symbol:ieee80211_chswitch_done symbol:ieee80211_connection_loss symbol:ieee80211_cqm_rssi_notify symbol:ieee80211_beacon_loss symbol:ieee80211_cqm_beacon_loss_notify symbol:ieee80211_tdls_oper_request symbol:ieee80211_report_wowlan_wakeup
cfg80211

kernel/net/can/can-raw.ko can_proto_1
can

kernel/net/can/can-gw.ko can_gw
can

kernel/net/can/can-bcm.ko can_proto_2
can

kernel/net/can/can.ko net_pf_29 symbol:can_proto_register symbol:can_rx_register symbol:can_proto_unregister symbol:can_ioctl symbol:can_rx_unregister symbol:can_send

kernel/net/wireless/lib80211.ko symbol:lib80211_register_crypto_ops symbol:lib80211_crypt_info_init symbol:lib80211_crypt_delayed_deinit symbol:lib80211_crypt_info_free symbol:lib80211_unregister_crypto_ops symbol:lib80211_get_crypto_ops

kernel/net/wireless/cfg80211.ko net_pf_16_proto_16_family_nl80211 symbol:wiphy_rfkill_stop_polling symbol:wiphy_unregister symbol:wiphy_rfkill_start_polling symbol:wiphy_register symbol:wiphy_free symbol:wiphy_new_nm symbol:cfg80211_unregister_wdev symbol:cfg80211_shutdown_all_interfaces symbol:cfg80211_stop_iface symbol:wiphy_rfkill_set_hw_state symbol:ieee80211_radiotap_iterator_next symbol:ieee80211_radiotap_iterator_init symbol:cfg80211_calculate_bitrate symbol:ieee80211_get_hdrlen_from_skb symbol:ieee80211_ie_split_ric symbol:cfg80211_check_combinations symbol:ieee80211_data_to_8023 symbol:rfc1042_header symbol:ieee80211_mandatory_rates symbol:ieee80211_chandef_to_operating_class symbol:ieee80211_amsdu_to_8023s symbol:ieee80211_frequency_to_channel symbol:ieee80211_operating_class_to_band symbol:ieee80211_data_from_8023 symbol:cfg80211_get_station symbol:ieee80211_get_num_supported_channels symbol:__ieee80211_get_channel symbol:ieee80211_bss_get_ie symbol:cfg80211_classify8021d symbol:ieee80211_hdrlen symbol:bridge_tunnel_header symbol:ieee80211_get_response_rate symbol:ieee80211_channel_to_frequency symbol:ieee80211_ie_split symbol:cfg80211_get_p2p_attr symbol:cfg80211_iter_combinations symbol:ieee80211_get_mesh_hdrlen symbol:regulatory_set_wiphy_regd_sync_rtnl symbol:freq_reg_info symbol:regulatory_hint symbol:regulatory_set_wiphy_regd symbol:reg_initiator_name symbol:wiphy_apply_custom_regulatory symbol:cfg80211_ref_bss symbol:cfg80211_scan_done symbol:cfg80211_inform_bss_frame_data symbol:cfg80211_sched_scan_stopped_rtnl symbol:cfg80211_inform_bss_data symbol:cfg80211_sched_scan_stopped symbol:cfg80211_sched_scan_results symbol:cfg80211_unlink_bss symbol:cfg80211_put_bss symbol:cfg80211_find_vendor_ie symbol:cfg80211_get_bss symbol:cfg80211_find_ie symbol:cfg80211_del_sta_sinfo symbol:cfg80211_remain_on_channel_expired symbol:cfg80211_cqm_pktloss_notify symbol:cfg80211_new_sta symbol:cfg80211_vendor_cmd_reply symbol:cfg80211_tdls_oper_request symbol:__cfg80211_alloc_event_skb symbol:cfg80211_conn_failed symbol:cfg80211_rx_unexpected_4addr_frame symbol:cfg80211_ft_event symbol:cfg80211_cqm_rssi_notify symbol:cfg80211_notify_new_peer_candidate symbol:cfg80211_ready_on_channel symbol:cfg80211_pmksa_candidate_notify symbol:cfg80211_rx_unprot_mlme_mgmt symbol:cfg80211_check_station_change symbol:cfg80211_cqm_beacon_loss_notify symbol:cfg80211_report_wowlan_wakeup symbol:cfg80211_ch_switch_started_notify symbol:cfg80211_crit_proto_stopped symbol:__cfg80211_send_event_skb symbol:cfg80211_gtk_rekey_notify symbol:cfg80211_rx_spurious_frame symbol:cfg80211_mgmt_tx_status symbol:cfg80211_probe_status symbol:cfg80211_cqm_txe_notify symbol:cfg80211_report_obss_beacon symbol:__cfg80211_alloc_reply_skb symbol:cfg80211_ch_switch_notify symbol:cfg80211_rx_mlme_mgmt symbol:cfg80211_auth_timeout symbol:cfg80211_tx_mlme_mgmt symbol:cfg80211_abandon_assoc symbol:cfg80211_assoc_timeout symbol:cfg80211_michael_mic_failure symbol:cfg80211_rx_assoc_resp symbol:cfg80211_cac_event symbol:cfg80211_rx_mgmt symbol:cfg80211_radar_event symbol:cfg80211_ibss_joined symbol:cfg80211_roamed symbol:cfg80211_connect_result symbol:cfg80211_disconnected symbol:cfg80211_roamed_bss symbol:cfg80211_chandef_dfs_required symbol:cfg80211_chandef_create symbol:cfg80211_reg_can_beacon_relax symbol:cfg80211_reg_can_beacon symbol:cfg80211_chandef_valid symbol:cfg80211_chandef_usable symbol:cfg80211_chandef_compatible symbol:cfg80211_get_drvinfo

kernel/net/bluetooth/bnep/bnep.ko bt_proto_4
bluetooth

kernel/net/bluetooth/rfcomm/rfcomm.ko bt_proto_3
bluetooth

kernel/net/bluetooth/bluetooth.ko net_pf_31 symbol:bt_sock_ioctl symbol:bt_sock_unregister symbol:bt_sock_register symbol:bt_sock_wait_ready symbol:bt_accept_unlink symbol:bt_sock_poll symbol:bt_sock_reclassify_lock symbol:bt_debugfs symbol:bt_sock_stream_recvmsg symbol:bt_sock_recvmsg symbol:bt_sock_link symbol:bt_accept_dequeue symbol:bt_procfs_cleanup symbol:bt_sock_unlink symbol:bt_procfs_init symbol:bt_accept_enqueue symbol:bt_sock_wait_state symbol:hci_cmd_sync symbol:hci_unregister_dev symbol:hci_recv_frame symbol:__hci_cmd_sync_ev symbol:hci_reset_dev symbol:hci_register_dev symbol:hci_register_cb symbol:hci_unregister_cb symbol:hci_recv_diag symbol:hci_suspend_dev symbol:hci_resume_dev symbol:hci_free_dev symbol:hci_alloc_dev symbol:__hci_cmd_sync symbol:hci_conn_security symbol:hci_conn_check_secure symbol:hci_conn_switch_role symbol:hci_get_route symbol:hci_mgmt_chan_unregister symbol:hci_mgmt_chan_register symbol:l2cap_chan_connect symbol:l2cap_chan_close symbol:l2cap_chan_send symbol:l2cap_chan_del symbol:l2cap_chan_set_defaults symbol:l2cap_register_user symbol:l2cap_unregister_user symbol:l2cap_conn_get symbol:l2cap_chan_put symbol:l2cap_add_psm symbol:l2cap_conn_put symbol:l2cap_chan_create symbol:l2cap_is_socket symbol:bt_info symbol:bt_err symbol:bt_to_errno symbol:baswap symbol:bt_warn symbol:bt_err_ratelimited

kernel/net/bluetooth/hidp/hidp.ko bt_proto_6
bluetooth

kernel/drivers/connector/cn.ko net_pf_16_proto_11 symbol:cn_netlink_send_mult symbol:cn_del_callback symbol:cn_add_callback symbol:cn_netlink_send

kernel/drivers/hsi/clients/ssi_protocol.ko hsi:ssi_protocol symbol:ssip_slave_running symbol:ssip_slave_get_master symbol:ssip_slave_start_tx symbol:ssip_slave_stop_tx symbol:ssip_reset_event
hsi phonet omap_ssi

kernel/drivers/hsi/controllers/omap_ssi.ko platform:omap_ssi of:N*T*Cti,omap3_ssi* symbol:ssi_waketest
hsi

kernel/drivers/hsi/controllers/omap_ssi_port.ko platform:omap_ssi_port of:N*T*Cti,omap3_ssi_port*
hsi

kernel/drivers/hsi/hsi.ko symbol:hsi_alloc_controller symbol:hsi_alloc_msg symbol:hsi_async symbol:hsi_remove_client symbol:hsi_get_channel_id_by_name symbol:hsi_port_unregister_clients symbol:hsi_new_client symbol:hsi_register_client_driver symbol:hsi_free_msg symbol:hsi_unregister_controller symbol:hsi_register_port_event symbol:hsi_claim_port symbol:hsi_event symbol:hsi_add_clients_from_dt symbol:hsi_put_controller symbol:hsi_register_controller symbol:hsi_release_port symbol:hsi_unregister_port_event

kernel/drivers/usb/class/cdc-wdm.ko usb:v*p*d*dc*dsc*dp*ic02isc09ip*in* symbol:usb_cdc_wdm_register
usbcore

kernel/drivers/usb/core/usbcore.ko usb:v*p*d*dc*dsc*dp*ic09isc*ip*in* usb:v*p*d*dc09dsc*dp*ic*isc*ip*in* usb:v05E3p*d*dc*dsc*dp*ic09isc*ip*in* symbol:usb_ifnum_to_if symbol:usb_find_alt_setting symbol:usb_get_intf symbol:usb_alloc_dev symbol:__usb_get_extra_descriptor symbol:usb_alloc_coherent symbol:usb_get_current_frame_number symbol:usb_free_coherent symbol:usb_for_each_dev symbol:usb_lock_device_for_reset symbol:usb_altnum_to_altsetting symbol:usb_debug_root symbol:usb_disabled symbol:usb_put_dev symbol:usb_find_interface symbol:usb_get_dev symbol:usb_put_intf symbol:usb_hub_claim_port symbol:usb_set_device_state symbol:usb_root_hub_lost_power symbol:usb_ep0_reinit symbol:ehci_cf_port_reset_rwsem symbol:usb_hub_release_port symbol:usb_reset_device symbol:usb_unlocked_enable_lpm symbol:usb_queue_reset_device symbol:usb_unlocked_disable_lpm symbol:usb_wakeup_notification symbol:usb_hub_find_child symbol:usb_hub_clear_tt_buffer symbol:usb_disable_lpm symbol:usb_disable_ltm symbol:usb_enable_lpm symbol:usb_enable_ltm symbol:usb_hcd_resume_root_hub symbol:usb_hcd_poll_rh_status symbol:usb_hcd_is_primary_hcd symbol:usb_mon_deregister symbol:usb_hcd_link_urb_to_ep symbol:usb_hcd_platform_shutdown symbol:usb_create_hcd symbol:usb_hcd_unlink_urb_from_ep symbol:usb_hcd_start_port_resume symbol:usb_hcd_map_urb_for_dma symbol:usb_hcd_end_port_resume symbol:usb_hc_died symbol:usb_hcd_unmap_urb_setup_for_dma symbol:usb_bus_list symbol:usb_alloc_streams symbol:usb_free_streams symbol:usb_bus_list_lock symbol:usb_create_shared_hcd symbol:usb_hcd_unmap_urb_for_dma symbol:usb_hcd_giveback_urb symbol:usb_add_hcd symbol:usb_calc_bus_time symbol:usb_put_hcd symbol:usb_hcds_loaded symbol:usb_hcd_irq symbol:usb_get_hcd symbol:usb_hcd_check_unlink_urb symbol:usb_remove_hcd symbol:usb_mon_register symbol:usb_unpoison_anchored_urbs symbol:usb_anchor_suspend_wakeups symbol:usb_unlink_urb symbol:usb_anchor_empty symbol:usb_scuttle_anchored_urbs symbol:usb_get_urb symbol:usb_unpoison_urb symbol:usb_submit_urb symbol:usb_kill_urb symbol:usb_poison_urb symbol:usb_unanchor_urb symbol:usb_anchor_urb symbol:usb_block_urb symbol:usb_get_from_anchor symbol:usb_init_urb symbol:usb_kill_anchored_urbs symbol:usb_poison_anchored_urbs symbol:usb_anchor_resume_wakeups symbol:usb_wait_anchor_empty_timeout symbol:usb_unlink_anchored_urbs symbol:usb_alloc_urb symbol:usb_free_urb symbol:usb_reset_endpoint symbol:usb_string symbol:usb_clear_halt symbol:usb_sg_wait symbol:usb_bulk_msg symbol:usb_driver_set_configuration symbol:usb_set_configuration symbol:usb_get_descriptor symbol:usb_sg_init symbol:usb_set_interface symbol:usb_reset_configuration symbol:usb_sg_cancel symbol:usb_control_msg symbol:usb_get_status symbol:usb_interrupt_msg symbol:usb_autopm_put_interface_no_suspend symbol:usb_driver_claim_interface symbol:usb_autopm_put_interface_async symbol:usb_autopm_get_interface_no_resume symbol:usb_match_one_id symbol:usb_show_dynids symbol:usb_disable_autosuspend symbol:usb_enable_autosuspend symbol:usb_autopm_get_interface symbol:usb_register_device_driver symbol:usb_autopm_put_interface symbol:usb_autopm_get_interface_async symbol:usb_store_new_id symbol:usb_register_driver symbol:usb_match_id symbol:usb_driver_release_interface symbol:usb_deregister symbol:usb_deregister_device_driver symbol:usb_register_dev symbol:usb_deregister_dev symbol:usb_unregister_notify symbol:usb_register_notify symbol:usb_choose_configuration
usb_common

kernel/drivers/usb/storage/usb-storage.ko usb:v*p*d*dc*dsc*dp*ic08isc06ip50in* usb:v*p*d*dc*dsc*dp*ic08isc05ip50in* usb:v*p*d*dc*dsc*dp*ic08isc04ip50in* usb:v*p*d*dc*dsc*dp*ic08isc03ip50in* usb:v*p*d*dc*dsc*dp*ic08isc02ip50in* usb:v*p*d*dc*dsc*dp*ic08isc01ip50in* usb:v*p*d*dc*dsc*dp*ic08isc06ip00in* usb:v*p*d*dc*dsc*dp*ic08isc05ip00in* usb:v*p*d*dc*dsc*dp*ic08isc04ip00in* usb:v*p*d*dc*dsc*dp*ic08isc03ip00in* usb:v*p*d*dc*dsc*dp*ic08isc02ip00in* usb:v*p*d*dc*dsc*dp*ic08isc01ip00in* usb:v*p*d*dc*dsc*dp*ic08isc06ip01in* usb:v*p*d*dc*dsc*dp*ic08isc05ip01in* usb:v*p*d*dc*dsc*dp*ic08isc04ip01in* usb:v*p*d*dc*dsc*dp*ic08isc03ip01in* usb:v*p*d*dc*dsc*dp*ic08isc02ip01in* usb:v*p*d*dc*dsc*dp*ic08isc01ip01in* usb:vED10p7636d0001dc*dsc*dp*ic*isc*ip*in* usb:vED06p4500d0001dc*dsc*dp*ic*isc*ip*in* usb:vC251p4003d0100dc*dsc*dp*ic*isc*ip*in* usb:v4146pBA01d0100dc*dsc*dp*ic*isc*ip*in* usb:v4102p1059d0000dc*dsc*dp*ic*isc*ip*in* usb:v4102p1020d0100dc*dsc*dp*ic*isc*ip*in* usb:v3340pFFFFd0000dc*dsc*dp*ic*isc*ip*in* usb:v2735p100Bd*dc*dsc*dp*ic*isc*ip*in* usb:v22B8p6426d0101dc*dsc*dp*ic*isc*ip*in* usb:v152Dp9561d*dc*dsc*dp*ic*isc*ip*in* usb:v22B8p3010d0001dc*dsc*dp*ic*isc*ip*in* usb:v2116p0320d0001dc*dsc*dp*ic*isc*ip*in* usb:v2027pA001d*dc*dsc*dp*ic*isc*ip*in* usb:v1E74p4621d0000dc*dsc*dp*ic*isc*ip*in* usb:v1E68p001Bd0000dc*dsc*dp*ic*isc*ip*in* usb:v1DE1pC102d*dc*dsc*dp*ic*isc*ip*in* usb:v1B1Cp1AB5d0200dc*dsc*dp*ic*isc*ip*in* usb:v19D2p1225d*dc*dsc*dp*ic*isc*ip*in* usb:v1908p3335d0200dc*dsc*dp*ic*isc*ip*in* usb:v1908p1320d0000dc*dsc*dp*ic*isc*ip*in* usb:v1908p1315d0000dc*dsc*dp*ic*isc*ip*in* usb:v1822p0001d*dc*dsc*dp*ic*isc*ip*in* usb:v177Fp0400d0000dc*dsc*dp*ic*isc*ip*in* usb:v174Cp55AAd0100dc*dsc*dp*ic*isc*ip*in* usb:v1652p6600d0201dc*dsc*dp*ic*isc*ip*in* usb:v1645p0007d01[0_2]*dc*dsc*dp*ic*isc*ip*in* usb:v1645p0007d013[0_3]dc*dsc*dp*ic*isc*ip*in* usb:v152Dp2566d0114dc*dsc*dp*ic*isc*ip*in* usb:v152Dp2329d0100dc*dsc*dp*ic*isc*ip*in* usb:v152Dp0567d011[4_6]dc*dsc*dp*ic*isc*ip*in* usb:v14CDp6600d0201dc*dsc*dp*ic*isc*ip*in* usb:v13FEp3600d0100dc*dsc*dp*ic*isc*ip*in* usb:v1370p6828d0110dc*dsc*dp*ic*isc*ip*in* usb:v132Bp000Bd0001dc*dsc*dp*ic*isc*ip*in* usb:v12D1p143Fd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p143Ed0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p143Dd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p143Cd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p143Bd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p143Ad0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1439d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1438d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1437d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1436d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1435d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1434d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1433d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1432d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1431d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1430d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p142Fd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p142Ed0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p142Dd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p142Cd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p142Bd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p142Ad0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1429d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1428d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1427d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1426d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1425d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1424d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1423d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1422d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1421d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1420d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p141Fd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p141Ed0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p141Dd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p141Cd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p141Bd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p141Ad0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1419d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1418d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1417d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1416d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1415d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1414d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1413d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1412d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1411d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1410d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p140Fd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p140Ed0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p140Dd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p140Cd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p140Bd0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p140Ad0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1409d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1408d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1407d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1406d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1405d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1404d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1403d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1402d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1401d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1004d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1003d0000dc*dsc*dp*ic*isc*ip*in* usb:v12D1p1001d0000dc*dsc*dp*ic*isc*ip*in* usb:v1210p0003d0100dc*dsc*dp*ic*isc*ip*in* usb:v1199p0FFFd*dc*dsc*dp*ic*isc*ip*in* usb:v1186p3E04d0000dc*dsc*dp*ic*isc*ip*in* usb:v10D6p2200d0100dc*dsc*dp*ic*isc*ip*in* usb:v1058p070Ad*dc*dsc*dp*ic*isc*ip*in* usb:v1058p0704d*dc*dsc*dp*ic*isc*ip*in* usb:v1019p0C55d00*dc*dsc*dp*ic*isc*ip*in* usb:v1019p0C55d010*dc*dsc*dp*ic*isc*ip*in* usb:v1019p0C55d0110dc*dsc*dp*ic*isc*ip*in* usb:v0FCEpE092d0000dc*dsc*dp*ic*isc*ip*in* usb:v0FCEpE031d0000dc*dsc*dp*ic*isc*ip*in* usb:v0FCEpE030d0000dc*dsc*dp*ic*isc*ip*in* usb:v0FCEpD0E1d0000dc*dsc*dp*ic*isc*ip*in* usb:v0FCEpD008d0000dc*dsc*dp*ic*isc*ip*in* usb:v0FCAp8004d0201dc*dsc*dp*ic*isc*ip*in* usb:v0F88p042Ed0100dc*dsc*dp*ic*isc*ip*in* usb:v0F19p0105d0100dc*dsc*dp*ic*isc*ip*in* usb:v0F19p0103d0100dc*dsc*dp*ic*isc*ip*in* usb:v0ED1p7636d0103dc*dsc*dp*ic*isc*ip*in* usb:v0EA0p6828d0110dc*dsc*dp*ic*isc*ip*in* usb:v0EA0p2168d0110dc*dsc*dp*ic*isc*ip*in* usb:v0ED1p6660d0[1_2]*dc*dsc*dp*ic*isc*ip*in* usb:v0ED1p6660d0300dc*dsc*dp*ic*isc*ip*in* usb:v0E21p0520d0100dc*dsc*dp*ic*isc*ip*in* usb:v0DDAp0301d0012dc*dsc*dp*ic*isc*ip*in* usb:v0DDAp0001d0012dc*dsc*dp*ic*isc*ip*in* usb:v0DD8pD202d*dc*dsc*dp*ic*isc*ip*in* usb:v0DD8p1060d*dc*dsc*dp*ic*isc*ip*in* usb:v0DC4p0073d0000dc*dsc*dp*ic*isc*ip*in* usb:v0D96p5200d01*dc*dsc*dp*ic*isc*ip*in* usb:v0D96p5200d00[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v0D96p5200d0200dc*dsc*dp*ic*isc*ip*in* usb:v0D96p5200d000[1_9]dc*dsc*dp*ic*isc*ip*in* usb:v0D96p410Ad[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v0D96p410Ad0[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v0D96p410Ad00[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v0D96p410Ad000[1_9]dc*dsc*dp*ic*isc*ip*in* usb:v0C45p1060d0100dc*dsc*dp*ic*isc*ip*in* usb:v0D49p7310d*dc*dsc*dp*ic*isc*ip*in* usb:v0BC2p3332d*dc*dsc*dp*ic*isc*ip*in* usb:v0BC2p3010d0000dc*dsc*dp*ic*isc*ip*in* usb:v0BC2p2300d*dc*dsc*dp*ic*isc*ip*in* usb:v0AF0pD357d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0pD257d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0pD157d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0pD058d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0pD057d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0pC100d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p8304d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p8302d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p8300d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p7A05d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p7A01d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p7901d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p7706d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p7701d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p7501d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p7401d0000dc*dsc*dp*ic*isc*ip*in* usb:v0AF0p6971d*dc*dsc*dp*ic*isc*ip*in* usb:v0ACEp20FFd0101dc*dsc*dp*ic*isc*ip*in* usb:v0ACEp2011d0101dc*dsc*dp*ic*isc*ip*in* usb:v0A17p0004d1000dc*dsc*dp*ic*isc*ip*in* usb:v090Cp6000d0100dc*dsc*dp*ic*isc*ip*in* usb:v090Cp1132d*dc*dsc*dp*ic*isc*ip*in* usb:v090Ap1200d*dc*dsc*dp*ic*isc*ip*in* usb:v090Ap1050d0100dc*dsc*dp*ic*isc*ip*in* usb:v090Ap1001d0100dc*dsc*dp*ic*isc*ip*in* usb:v08CAp3103d0100dc*dsc*dp*ic*isc*ip*in* usb:v08BDp1100d0000dc*dsc*dp*ic*isc*ip*in* usb:v085Ap0028d01[0_2]*dc*dsc*dp*ic*isc*ip*in* usb:v085Ap0028d013[0_3]dc*dsc*dp*ic*isc*ip*in* usb:v085Ap0026d01[0_2]*dc*dsc*dp*ic*isc*ip*in* usb:v085Ap0026d013[0_3]dc*dsc*dp*ic*isc*ip*in* usb:v0851p1543d0200dc*dsc*dp*ic*isc*ip*in* usb:v0851p1542d0002dc*dsc*dp*ic*isc*ip*in* usb:v084Dp0011d0110dc*dsc*dp*ic*isc*ip*in* usb:v084BpA001d*dc*dsc*dp*ic*isc*ip*in* usb:v0840p0085d0001dc*dsc*dp*ic*isc*ip*in* usb:v0840p0084d0001dc*dsc*dp*ic*isc*ip*in* usb:v0840p0082d0001dc*dsc*dp*ic*isc*ip*in* usb:v0839p000Ad0001dc*dsc*dp*ic*isc*ip*in* usb:v07CFp1167d0100dc*dsc*dp*ic*isc*ip*in* usb:v07CFp1001d[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v07C4pA4A5d*dc*dsc*dp*ic*isc*ip*in* usb:v07C4pA400d*dc*dsc*dp*ic*isc*ip*in* usb:v07AFp0006d0100dc*dsc*dp*ic*isc*ip*in* usb:v07AFp0005d0100dc*dsc*dp*ic*isc*ip*in* usb:v07AFp0004d01[0_2]*dc*dsc*dp*ic*isc*ip*in* usb:v07AFp0004d013[0_3]dc*dsc*dp*ic*isc*ip*in* usb:v07ABpFCCDd*dc*dsc*dp*ic*isc*ip*in* usb:v0781p0100d0100dc*dsc*dp*ic*isc*ip*in* usb:v0781p0002d0009dc*dsc*dp*ic*isc*ip*in* usb:v0781p0001d0200dc*dsc*dp*ic*isc*ip*in* usb:v0727p0306d0100dc*dsc*dp*ic*isc*ip*in* usb:v071Bp3203d0100dc*dsc*dp*ic*isc*ip*in* usb:v071Bp32BBd0000dc*dsc*dp*ic*isc*ip*in* usb:v071Bp3203d0000dc*dsc*dp*ic*isc*ip*in* usb:v06CAp2003d0100dc*dsc*dp*ic*isc*ip*in* usb:v069Bp3004d0001dc*dsc*dp*ic*isc*ip*in* usb:v0693p0005d0100dc*dsc*dp*ic*isc*ip*in* usb:v0686p4017d0001dc*dsc*dp*ic*isc*ip*in* usb:v0686p4011d0001dc*dsc*dp*ic*isc*ip*in* usb:v067Bp3507d00[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v067Bp3507d010[0_1]dc*dsc*dp*ic*isc*ip*in* usb:v067Bp3507d000[1_9]dc*dsc*dp*ic*isc*ip*in* usb:v067Bp2507d00[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v067Bp2507d0100dc*dsc*dp*ic*isc*ip*in* usb:v067Bp2507d000[1_9]dc*dsc*dp*ic*isc*ip*in* usb:v067Bp2317d0001dc*dsc*dp*ic*isc*ip*in* usb:v067Bp1063d0100dc*dsc*dp*ic*isc*ip*in* usb:v066Fp8000d0001dc*dsc*dp*ic*isc*ip*in* usb:v0644p0000d0100dc*dsc*dp*ic*isc*ip*in* usb:v0636p0003d*dc*dsc*dp*ic*isc*ip*in* usb:v05E3p0723d9451dc*dsc*dp*ic*isc*ip*in* usb:v05E3p0702d*dc*dsc*dp*ic*isc*ip*in* usb:v05E3p0701d*dc*dsc*dp*ic*isc*ip*in* usb:v05DCpB002d00*dc*dsc*dp*ic*isc*ip*in* usb:v05DCpB002d010*dc*dsc*dp*ic*isc*ip*in* usb:v05DCpB002d011[0_3]dc*dsc*dp*ic*isc*ip*in* usb:v05C6p1000d*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp120Ad*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp1205d*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp1204d*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp1203d*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp1202d*dc*dsc*dp*ic*isc*ip*in* usb:v05ABp0060d1110dc*dsc*dp*ic*isc*ip*in* usb:v05ABp0060d110[4_9]dc*dsc*dp*ic*isc*ip*in* usb:v059Fp0651d0000dc*dsc*dp*ic*isc*ip*in* usb:v059Fp0643d0000dc*dsc*dp*ic*isc*ip*in* usb:v059Bp0040d0100dc*dsc*dp*ic*isc*ip*in* usb:v059Bp0001d0100dc*dsc*dp*ic*isc*ip*in* usb:v0595p4343d[0_1]*dc*dsc*dp*ic*isc*ip*in* usb:v0595p4343d2[0_1]*dc*dsc*dp*ic*isc*ip*in* usb:v0595p4343d220*dc*dsc*dp*ic*isc*ip*in* usb:v0595p4343d2210dc*dsc*dp*ic*isc*ip*in* usb:v058Fp6387d0141dc*dsc*dp*ic*isc*ip*in* usb:v057Bp0022d*dc*dsc*dp*ic*isc*ip*in* usb:v057Bp0000d0[0_2]*dc*dsc*dp*ic*isc*ip*in* usb:v055Dp2020d0[0_1]*dc*dsc*dp*ic*isc*ip*in* usb:v055Dp2020d020*dc*dsc*dp*ic*isc*ip*in* usb:v055Dp2020d0210dc*dsc*dp*ic*isc*ip*in* usb:v054Cp02A5d0100dc*dsc*dp*ic*isc*ip*in* usb:v054Cp016Ad*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0099d*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp006Dd*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0069d*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0058d*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0032d*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Ed0500dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Ed02*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Ed030*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Ed01[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Ed0310dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Ed010[6_9]dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Dd0100dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Cd1*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Cd0[6_9]*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Cd05[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Cd2000dc*dsc*dp*ic*isc*ip*in* usb:v054Cp002Cd050[1_9]dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0025d0100dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0010d05*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0010d060*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0010d0610dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0010d0[2_3]*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0010d04[0_4]*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0010d01[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0010d0450dc*dsc*dp*ic*isc*ip*in* usb:v054Cp0010d010[6_9]dc*dsc*dp*ic*isc*ip*in* usb:v052Bp1911d0100dc*dsc*dp*ic*isc*ip*in* usb:v052Bp1905d0100dc*dsc*dp*ic*isc*ip*in* usb:v052Bp1807d0100dc*dsc*dp*ic*isc*ip*in* usb:v052Bp1804d0100dc*dsc*dp*ic*isc*ip*in* usb:v052Bp1801d0100dc*dsc*dp*ic*isc*ip*in* usb:v0525pA4A5d*dc*dsc*dp*ic*isc*ip*in* usb:v0525pA140d0100dc*dsc*dp*ic*isc*ip*in* usb:v050Dp0115d0133dc*dsc*dp*ic*isc*ip*in* usb:v04FCp80C2d0100dc*dsc*dp*ic*isc*ip*in* usb:v04E8p5136d*dc*dsc*dp*ic*isc*ip*in* usb:v04E8p5122d*dc*dsc*dp*ic*isc*ip*in* usb:v04E8p507Cd0220dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0101d0200dc*dsc*dp*ic*isc*ip*in* usb:v04E6p000Fd*dc*dsc*dp*ic*isc*ip*in* usb:v04E6p000Cd0100dc*dsc*dp*ic*isc*ip*in* usb:v04E6p000Bd0100dc*dsc*dp*ic*isc*ip*in* usb:v04E6p000Ad0200dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0009d0200dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0007d01*dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0007d0200dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0006d0205dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0006d0100dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0005d01*dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0005d020[0_8]dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0002d0100dc*dsc*dp*ic*isc*ip*in* usb:v04E6p0001d0200dc*dsc*dp*ic*isc*ip*in* usb:v04DAp2373d*dc*dsc*dp*ic*isc*ip*in* usb:v04DAp2372d*dc*dsc*dp*ic*isc*ip*in* usb:v04DAp0D05d0000dc*dsc*dp*ic*isc*ip*in* usb:v04DAp0901d01*dc*dsc*dp*ic*isc*ip*in* usb:v04DAp0901d0200dc*dsc*dp*ic*isc*ip*in* usb:v04CEp0002d026Cdc*dsc*dp*ic*isc*ip*in* usb:v04CBp0100d[0_1]*dc*dsc*dp*ic*isc*ip*in* usb:v04CBp0100d2[0_1]*dc*dsc*dp*ic*isc*ip*in* usb:v04CBp0100d220*dc*dsc*dp*ic*isc*ip*in* usb:v04CBp0100d2210dc*dsc*dp*ic*isc*ip*in* usb:v04B8p0602d0110dc*dsc*dp*ic*isc*ip*in* usb:v04B8p0601d0100dc*dsc*dp*ic*isc*ip*in* usb:v04B3p4001d0110dc*dsc*dp*ic*isc*ip*in* usb:v04B0p0301d0010dc*dsc*dp*ic*isc*ip*in* usb:v04A5p3010d0100dc*dsc*dp*ic*isc*ip*in* usb:v04A4p0004d0001dc*dsc*dp*ic*isc*ip*in* usb:v0482p0107d0100dc*dsc*dp*ic*isc*ip*in* usb:v0482p0103d0100dc*dsc*dp*ic*isc*ip*in* usb:v0482p0101d0100dc*dsc*dp*ic*isc*ip*in* usb:v0482p0100d0100dc*dsc*dp*ic*isc*ip*in* usb:v046BpFF40d0100dc*dsc*dp*ic*isc*ip*in* usb:v045EpFFFFd0000dc*dsc*dp*ic*isc*ip*in* usb:v0457p0151d0100dc*dsc*dp*ic*isc*ip*in* usb:v0457p0150d0100dc*dsc*dp*ic*isc*ip*in* usb:v0451p5416d0100dc*dsc*dp*ic*isc*ip*in* usb:v0436p0005d0100dc*dsc*dp*ic*isc*ip*in* usb:v0421p06AAd1110dc*dsc*dp*ic*isc*ip*in* usb:v0421p05AFd0742dc*dsc*dp*ic*isc*ip*in* usb:v0421p04B9d0350dc*dsc*dp*ic*isc*ip*in* usb:v0421p0495d0370dc*dsc*dp*ic*isc*ip*in* usb:v0421p0492d[1_9]*dc*dsc*dp*ic*isc*ip*in* usb:v0421p0492d0[5_9]*dc*dsc*dp*ic*isc*ip*in* usb:v0421p0492d04[6_9]*dc*dsc*dp*ic*isc*ip*in* usb:v0421p0492d045[2_9]dc*dsc*dp*ic*isc*ip*in* usb:v0421p047Cd0[4_5]*dc*dsc*dp*ic*isc*ip*in* usb:v0421p047Cd060*dc*dsc*dp*ic*isc*ip*in* usb:v0421p047Cd03[7_9]*dc*dsc*dp*ic*isc*ip*in* usb:v0421p047Cd0610dc*dsc*dp*ic*isc*ip*in* usb:v0421p044Ed0100dc*dsc*dp*ic*isc*ip*in* usb:v0421p0446d0100dc*dsc*dp*ic*isc*ip*in* usb:v0421p0444d0100dc*dsc*dp*ic*isc*ip*in* usb:v0421p0434d0100dc*dsc*dp*ic*isc*ip*in* usb:v0421p0433d0100dc*dsc*dp*ic*isc*ip*in* usb:v0421p042Ed0100dc*dsc*dp*ic*isc*ip*in* usb:v0421p0019d060*dc*dsc*dp*ic*isc*ip*in* usb:v0421p0019d0610dc*dsc*dp*ic*isc*ip*in* usb:v0421p0019d059[2_9]dc*dsc*dp*ic*isc*ip*in* usb:v0420p0001d0100dc*dsc*dp*ic*isc*ip*in* usb:v0419pAAF6d0100dc*dsc*dp*ic*isc*ip*in* usb:v0419pAAF5d0100dc*dsc*dp*ic*isc*ip*in* usb:v0419pAACEd0100dc*dsc*dp*ic*isc*ip*in* usb:v0419p0100d0100dc*dsc*dp*ic*isc*ip*in* usb:v0411p001Cd0113dc*dsc*dp*ic*isc*ip*in* usb:v040Dp6205d0003dc*dsc*dp*ic*isc*ip*in* usb:v0409p0040d*dc*dsc*dp*ic*isc*ip*in* usb:v03F3p0001d*dc*dsc*dp*ic*isc*ip*in* usb:v03F0p4002d0001dc*dsc*dp*ic*isc*ip*in* usb:v03F0p070Cd0000dc*dsc*dp*ic*isc*ip*in* usb:v03F0p0107d0200dc*dsc*dp*ic*isc*ip*in* usb:v03EEp6906d0003dc*dsc*dp*ic*isc*ip*in* usb:v03EBp2002d0100dc*dsc*dp*ic*isc*ip*in* symbol:usb_stor_host_template_init symbol:usb_stor_sense_invalidCDB symbol:usb_stor_access_xfer_buf symbol:usb_stor_set_xfer_buf symbol:usb_stor_transparent_scsi_command symbol:usb_stor_Bulk_reset symbol:usb_stor_CB_transport symbol:usb_stor_clear_halt symbol:usb_stor_bulk_srb symbol:usb_stor_bulk_transfer_buf symbol:usb_stor_CB_reset symbol:usb_stor_ctrl_transfer symbol:usb_stor_control_msg symbol:usb_stor_Bulk_transport symbol:usb_stor_bulk_transfer_sg symbol:usb_stor_pre_reset symbol:usb_stor_post_reset symbol:usb_stor_adjust_quirks symbol:usb_stor_suspend symbol:usb_stor_probe1 symbol:usb_stor_probe2 symbol:fill_inquiry_response symbol:usb_stor_resume symbol:usb_stor_disconnect symbol:usb_stor_reset_resume
usbcore

kernel/drivers/usb/dwc3/dwc3.ko platform:dwc3 of:N*T*Csynopsys,dwc3* of:N*T*Csnps,dwc3*
udc_core usb_common

kernel/drivers/usb/dwc3/dwc3-omap.ko platform:omap_dwc3 of:N*T*Cti,am437x_dwc3* of:N*T*Cti,dwc3*
extcon

kernel/drivers/usb/mon/usbmon.ko
usbcore

kernel/drivers/usb/host/xhci-hcd.ko symbol:xhci_init_driver symbol:xhci_suspend symbol:xhci_run symbol:xhci_gen_setup symbol:xhci_resume symbol:xhci_dbg_trace symbol:__tracepoint_xhci_dbg_quirks
usbcore

kernel/drivers/usb/host/xhci-plat-hcd.ko platform:xhci_hcd of:N*T*Crenesas,xhci_r8a7791* of:N*T*Crenesas,xhci_r8a7790* of:N*T*Cmarvell,armada_380_xhci* of:N*T*Cmarvell,armada_375_xhci* of:N*T*Cxhci_platform* of:N*T*Cgeneric_xhci* acpi*:PNP0D10:*
usbcore xhci_hcd

kernel/drivers/usb/host/ohci-omap3.ko platform:ohci_omap3 of:N*T*Cti,ohci_omap3*
usbcore ohci_hcd

kernel/drivers/usb/host/ehci-omap.ko platform:ehci_omap of:N*T*Cti,ehci_omap*
usbcore ehci_hcd

kernel/drivers/usb/host/ohci-hcd.ko symbol:ohci_hub_status_data symbol:ohci_restart symbol:ohci_resume symbol:ohci_setup symbol:ohci_hub_control symbol:ohci_init_driver symbol:ohci_suspend
usbcore

kernel/drivers/usb/host/ehci-hcd.ko symbol:ehci_hub_control symbol:ehci_adjust_port_wakeup_flags symbol:ehci_setup symbol:ehci_init_driver symbol:ehci_suspend symbol:ehci_handshake symbol:ehci_resume symbol:ehci_reset
usbcore

kernel/drivers/usb/common/usb-common.ko symbol:of_usb_host_tpl_support symbol:usb_get_dr_mode symbol:usb_state_string symbol:usb_get_maximum_speed symbol:of_usb_update_otg_caps symbol:usb_otg_state_string symbol:usb_speed_string

kernel/drivers/usb/gadget/legacy/g_zero.ko
libcomposite

kernel/drivers/usb/gadget/legacy/g_nokia.ko
usb_f_mass_storage libcomposite

kernel/drivers/usb/gadget/libcomposite.ko symbol:usb_gadget_get_string symbol:usb_descriptor_fillbuf symbol:usb_free_all_descriptors symbol:usb_assign_descriptors symbol:usb_otg_descriptor_init symbol:usb_copy_descriptors symbol:usb_otg_descriptor_alloc symbol:usb_gadget_config_buf symbol:usb_ep_autoconfig_reset symbol:usb_ep_autoconfig_release symbol:usb_ep_autoconfig_ss symbol:usb_ep_autoconfig symbol:usb_remove_function symbol:usb_add_config symbol:usb_composite_probe symbol:usb_add_config_only symbol:usb_composite_setup_continue symbol:usb_composite_overwrite_options symbol:usb_string_id symbol:usb_add_function symbol:usb_gstrings_attach symbol:usb_function_deactivate symbol:usb_function_activate symbol:config_ep_by_speed symbol:usb_interface_id symbol:usb_string_ids_n symbol:usb_string_ids_tab symbol:usb_composite_unregister symbol:usb_get_function symbol:usb_function_register symbol:usb_put_function_instance symbol:usb_function_unregister symbol:usb_get_function_instance symbol:usb_put_function symbol:usb_os_desc_prepare_interf_dir symbol:unregister_gadget_item symbol:alloc_ep_req
udc_core usb_common

kernel/drivers/usb/gadget/udc/udc-core.ko symbol:usb_gadget_unregister_driver symbol:usb_gadget_unmap_request symbol:usb_udc_vbus_handler symbol:usb_gadget_ep_match_desc symbol:usb_gadget_probe_driver symbol:usb_del_gadget_udc symbol:usb_add_gadget_udc_release symbol:usb_udc_attach_driver symbol:usb_gadget_set_state symbol:usb_gadget_giveback_request symbol:usb_gadget_map_request symbol:gadget_find_ep_by_name symbol:usb_add_gadget_udc symbol:usb_gadget_udc_reset
usb_common

kernel/drivers/usb/gadget/function/usb_f_ecm.ko usbfunc:ecm
libcomposite u_ether

kernel/drivers/usb/gadget/function/usb_f_midi.ko usbfunc:midi
libcomposite snd_rawmidi snd

kernel/drivers/usb/gadget/function/usb_f_fs.ko usbfunc:ffs fs_functionfs symbol:ffs_single_dev symbol:ffs_name_dev symbol:ffs_lock
libcomposite

kernel/drivers/usb/gadget/function/usb_f_mass_storage.ko usbfunc:mass_storage symbol:fsg_common_create_lun symbol:fsg_common_create_luns symbol:fsg_common_get symbol:fsg_common_set_cdev symbol:fsg_common_set_inquiry_string symbol:fsg_common_put symbol:fsg_common_set_num_buffers symbol:fsg_common_remove_luns symbol:fsg_config_from_params symbol:fsg_common_remove_lun symbol:fsg_common_set_sysfs symbol:fsg_common_free_buffers symbol:fsg_lun_open symbol:fsg_fs_bulk_in_desc symbol:fsg_show_cdrom symbol:fsg_hs_function symbol:fsg_store_removable symbol:fsg_ss_function symbol:fsg_show_nofua symbol:store_cdrom_address symbol:fsg_store_file symbol:fsg_hs_bulk_in_desc symbol:fsg_ss_bulk_out_comp_desc symbol:fsg_show_removable symbol:fsg_fs_function symbol:fsg_ss_bulk_out_desc symbol:fsg_lun_close symbol:fsg_store_nofua symbol:fsg_show_file symbol:fsg_lun_fsync_sub symbol:fsg_ss_bulk_in_desc symbol:fsg_fs_bulk_out_desc symbol:fsg_hs_bulk_out_desc symbol:fsg_ss_bulk_in_comp_desc symbol:fsg_show_ro symbol:fsg_store_ro symbol:fsg_intf_desc symbol:fsg_store_cdrom
libcomposite

kernel/drivers/usb/gadget/function/usb_f_obex.ko usbfunc:obex
libcomposite u_serial

kernel/drivers/usb/gadget/function/usb_f_uac2.ko usbfunc:uac2
libcomposite snd_pcm snd

kernel/drivers/usb/gadget/function/usb_f_rndis.ko usbfunc:rndis symbol:rndis_borrow_net symbol:rndis_msg_parser symbol:rndis_add_hdr symbol:rndis_signal_disconnect symbol:rndis_get_next_response symbol:rndis_set_host_mac symbol:rndis_deregister symbol:rndis_set_param_dev symbol:rndis_set_param_vendor symbol:rndis_free_response symbol:rndis_set_param_medium symbol:rndis_signal_connect symbol:rndis_uninit symbol:rndis_rm_hdr symbol:rndis_register
libcomposite u_ether

kernel/drivers/usb/gadget/function/usb_f_phonet.ko usbfunc:phonet
libcomposite u_ether phonet

kernel/drivers/usb/gadget/function/usb_f_ncm.ko usbfunc:ncm
libcomposite u_ether

kernel/drivers/usb/gadget/function/usb_f_ecm_subset.ko usbfunc:geth
libcomposite u_ether

kernel/drivers/usb/gadget/function/u_ether.ko symbol:gether_get_host_addr_cdc symbol:gether_get_qmult symbol:gether_set_qmult symbol:gether_set_dev_addr symbol:gether_register_netdev symbol:gether_disconnect symbol:gether_get_ifname symbol:gether_get_host_addr_u8 symbol:gether_get_host_addr symbol:gether_set_host_addr symbol:gether_cleanup symbol:gether_get_dev_addr symbol:gether_setup_name_default symbol:gether_set_gadget symbol:gether_connect symbol:gether_setup_name

kernel/drivers/usb/gadget/function/usb_f_hid.ko usbfunc:hid
libcomposite

kernel/drivers/usb/gadget/function/usb_f_serial.ko usbfunc:gser
libcomposite u_serial

kernel/drivers/usb/gadget/function/usb_f_uac1.ko usbfunc:uac1
libcomposite snd_pcm

kernel/drivers/usb/gadget/function/usb_f_acm.ko usbfunc:acm
libcomposite u_serial

kernel/drivers/usb/gadget/function/usb_f_ss_lb.ko usbfunc:Loopback usbfunc:SourceSink
libcomposite

kernel/drivers/usb/gadget/function/u_serial.ko symbol:gserial_disconnect symbol:gs_alloc_req symbol:gserial_alloc_line symbol:gserial_free_line symbol:gs_free_req symbol:gserial_connect

kernel/drivers/usb/gadget/function/usb_f_eem.ko usbfunc:eem
libcomposite u_ether

kernel/drivers/usb/musb/musb_dsps.ko of:N*T*Cti,musb_dm816* of:N*T*Cti,musb_am33xx*
musb_hdrc usb_common

kernel/drivers/usb/musb/omap2430.ko of:N*T*Cti,omap3_musb* of:N*T*Cti,omap4_musb* symbol:omap_musb_mailbox
usbcore musb_hdrc

kernel/drivers/usb/musb/am35x.ko
musb_hdrc

kernel/drivers/usb/musb/musb_hdrc.ko platform:musb_hdrc symbol:musb_readl symbol:musb_readw symbol:musb_dma_controller_destroy symbol:musb_interrupt symbol:musb_writel symbol:musb_writew symbol:musb_writeb symbol:musb_dma_completion symbol:musb_dma_controller_create symbol:musb_readb symbol:musbhs_dma_controller_destroy symbol:musbhs_dma_controller_create symbol:cppi41_dma_controller_create symbol:cppi41_dma_controller_destroy
usbcore udc_core usb_common

kernel/drivers/usb/musb/musb_am335x.ko of:N*T*Cti,am33xx_usb*

kernel/drivers/usb/misc/usbtest.ko usb:v0525pA4A3d*dc*dsc*dp*ic*isc*ip*in* usb:v0525pA4A4d*dc*dsc*dp*ic*isc*ip*in* usb:v0525pA4A0d*dc*dsc*dp*ic*isc*ip*in* usb:vFFF0pFFF0d*dc*dsc*dp*ic*isc*ip*in* usb:v04B4p8613d*dc*dsc*dp*ic*isc*ip*in* usb:v0547p0080d*dc*dsc*dp*ic*isc*ip*in* usb:v0547p2235d*dc*dsc*dp*ic*isc*ip*in*
usbcore usb_common

kernel/drivers/watchdog/omap_wdt.ko platform:omap_wdt of:N*T*Cti,omap3_wdt*

kernel/drivers/watchdog/twl4030_wdt.ko platform:twl4030_wdt of:N*T*Cti,twl4030_wdt*

kernel/drivers/mfd/ti_am335x_tscadc.ko of:N*T*Cti,am3359_tscadc* symbol:am335x_tsc_se_clr symbol:am335x_tsc_se_set_cache symbol:am335x_tsc_se_adc_done symbol:am335x_tsc_se_set_once

kernel/drivers/w1/wire.ko symbol:w1_add_master_device symbol:w1_remove_master_device symbol:w1_register_family symbol:w1_unregister_family symbol:w1_reset_select_slave symbol:w1_reset_bus symbol:w1_calc_crc8 symbol:w1_next_pullup symbol:w1_write_8 symbol:w1_reset_resume_command symbol:w1_write_block symbol:w1_touch_block symbol:w1_read_block symbol:w1_read_8
cn

kernel/drivers/w1/masters/omap_hdq.ko of:N*T*Cti,am4372_hdq* of:N*T*Cti,omap3_1w*
wire

kernel/drivers/dma/cppi41.ko of:N*T*Cti,am3359_cppi41*

kernel/drivers/cpufreq/cpufreq-dt.ko platform:cpufreq_dt
thermal_sys

kernel/drivers/spi/spi-ti-qspi.ko platform:ti_qspi of:N*T*Cti,am4372_qspi* of:N*T*Cti,dra7xxx_qspi*

kernel/drivers/mtd/spi-nor/spi-nor.ko symbol:spi_nor_scan

kernel/drivers/mtd/devices/m25p80.ko spi:m25p128_nonjedec spi:m25p64_nonjedec spi:m25p32_nonjedec spi:m25p16_nonjedec spi:m25p80_nonjedec spi:m25p40_nonjedec spi:m25p20_nonjedec spi:m25p10_nonjedec spi:m25p05_nonjedec spi:w25q256 spi:w25q128 spi:w25q80bl spi:w25q32dw spi:w25q32 spi:w25x32 spi:w25x80 spi:m25p128 spi:m25p64 spi:m25p32 spi:m25p16 spi:m25p80 spi:m25p40 spi:sst25wf040 spi:sst25vf032b spi:sst25vf016b spi:sst25vf040b spi:s25fl064k spi:s25fl008k spi:s25sl12801 spi:s25fl512s spi:s25fl256s1 spi:n25q512a spi:n25q128a13 spi:n25q128a11 spi:n25q064 spi:mx66l51235l spi:mx25l25635e spi:mx25l12805d spi:mx25l6405d spi:mx25l1606e spi:mx25l4005a spi:mr25h256 spi:at26df081a spi:at25df641 spi:at25df321a spi:m25px64 spi:m25p10 spi:w25x16 spi:s25sl064a of:N*T*Cjedec,spi_nor*
spi_nor

kernel/drivers/input/touchscreen/ti_am335x_tsc.ko of:N*T*Cti,am3359_tsc*
ti_am335x_tscadc

kernel/drivers/input/touchscreen/edt-ft5x06.ko i2c:edt_ft5506 i2c:edt_ft5x06 of:N*T*Cedt,edt_ft5506* of:N*T*Cedt,edt_ft5406* of:N*T*Cedt,edt_ft5306* of:N*T*Cedt,edt_ft5206*

kernel/drivers/input/touchscreen/tsc200x-core.ko symbol:tsc200x_pm_ops symbol:tsc200x_regmap_config symbol:tsc200x_probe symbol:tsc200x_remove

kernel/drivers/input/touchscreen/tsc2005.ko spi:tsc2005
tsc200x_core regmap_spi

kernel/drivers/input/touchscreen/pixcir_i2c_ts.ko i2c:pixcir_tangoc i2c:pixcir_ts of:N*T*Cpixcir,pixcir_tangoc* of:N*T*Cpixcir,pixcir_ts*

kernel/drivers/input/touchscreen/ads7846.ko spi:ads7846 of:N*T*Cti,ads7873* of:N*T*Cti,ads7846* of:N*T*Cti,ads7845* of:N*T*Cti,ads7843* of:N*T*Cti,tsc2046*
hwmon

kernel/drivers/input/touchscreen/tsc2007.ko i2c:tsc2007 of:N*T*Cti,tsc2007*

kernel/drivers/input/input-polldev.ko symbol:input_register_polled_device symbol:devm_input_allocate_polled_device symbol:input_unregister_polled_device symbol:input_allocate_polled_device symbol:input_free_polled_device

kernel/drivers/input/input-leds.ko input:b*v*p*e*_e*11,*k*r*a*m*l*s*f*w*
led_class

kernel/drivers/input/serio/serport.ko tty_ldisc_2
serio

kernel/drivers/input/serio/libps2.ko symbol:ps2_drain symbol:ps2_begin_command symbol:ps2_handle_response symbol:__ps2_command symbol:ps2_is_keyboard_id symbol:ps2_end_command symbol:ps2_command symbol:ps2_handle_ack symbol:ps2_init symbol:ps2_sendbyte symbol:ps2_cmd_aborted

kernel/drivers/input/serio/serio.ko symbol:serio_unregister_port symbol:serio_unregister_driver symbol:serio_unregister_child_port symbol:serio_bus symbol:__serio_register_driver symbol:serio_interrupt symbol:serio_rescan symbol:__serio_register_port symbol:serio_reconnect symbol:serio_open symbol:serio_close

kernel/drivers/input/evdev.ko input:b*v*p*e*_e*k*r*a*m*l*s*f*w*

kernel/drivers/input/matrix-keymap.ko symbol:matrix_keypad_parse_of_params symbol:matrix_keypad_build_keymap

kernel/drivers/input/keyboard/twl4030_keypad.ko platform:twl4030_keypad of:N*T*Cti,twl4030_keypad*
matrix_keymap

kernel/drivers/input/keyboard/atkbd.ko serio:ty02pr22id*ex* serio:ty06pr*id*ex* serio:ty01pr*id*ex*
serio libps2

kernel/drivers/input/keyboard/omap4-keypad.ko platform:omap4_keypad of:N*T*Cti,omap4_keypad*
matrix_keymap

kernel/drivers/input/keyboard/gpio_keys.ko platform:gpio_keys of:N*T*Cgpio_keys*

kernel/drivers/input/keyboard/matrix_keypad.ko platform:matrix_keypad of:N*T*Cgpio_matrix_keypad*
matrix_keymap

kernel/drivers/input/misc/tps65218-pwrbutton.ko of:N*T*Cti,tps65218_pwrbutton*

kernel/drivers/input/misc/palmas-pwrbutton.ko platform:palmas_pwrbutton of:N*T*Cti,palmas_pwrbutton*

kernel/drivers/input/misc/twl4030-pwrbutton.ko platform:twl4030_pwrbutton of:N*T*Cti,twl4030_pwrbutton*

kernel/drivers/input/joydev.ko input:b*v*p*e*_e*1,*k*2C0,*r*a*m*l*s*f*w* input:b*v*p*e*_e*1,*k*130,*r*a*m*l*s*f*w* input:b*v*p*e*_e*1,*k*120,*r*a*m*l*s*f*w* input:b*v*p*e*_e*3,*k*r*a*6,*m*l*s*f*w* input:b*v*p*e*_e*3,*k*r*a*8,*m*l*s*f*w* input:b*v*p*e*_e*3,*k*r*a*0,*m*l*s*f*w*

kernel/drivers/base/regmap/regmap-spi.ko symbol:__devm_regmap_init_spi symbol:__regmap_init_spi

kernel/drivers/thermal/thermal_sys.ko symbol:thermal_zone_device_unregister symbol:get_thermal_instance symbol:thermal_zone_device_update symbol:thermal_cooling_device_register symbol:thermal_notify_framework symbol:thermal_zone_bind_cooling_device symbol:thermal_zone_device_register symbol:thermal_cooling_device_unregister symbol:thermal_zone_get_zone_by_name symbol:thermal_zone_unbind_cooling_device symbol:thermal_cdev_update symbol:get_tz_trend symbol:thermal_zone_get_temp symbol:thermal_of_cooling_device_register symbol:thermal_generate_netlink_event symbol:of_thermal_get_ntrips symbol:thermal_zone_of_sensor_register symbol:of_thermal_is_trip_valid symbol:of_thermal_get_trip_points symbol:thermal_zone_of_sensor_unregister symbol:cpufreq_cooling_get_level symbol:cpufreq_power_cooling_register symbol:cpufreq_cooling_register symbol:of_cpufreq_cooling_register symbol:of_cpufreq_power_cooling_register symbol:cpufreq_cooling_unregister
hwmon

kernel/drivers/thermal/ti-soc-thermal/ti-soc-thermal.ko platform:ti_soc_thermal of:N*T*Cti,dra752_bandgap* of:N*T*Cti,omap5430_bandgap* of:N*T*Cti,omap4470_bandgap* of:N*T*Cti,omap4460_bandgap* of:N*T*Cti,omap4430_bandgap*
thermal_sys

kernel/drivers/power/bq24735-charger.ko i2c:bq24735_charger of:N*T*Cti,bq24735*

kernel/drivers/power/twl4030_charger.ko platform:twl4030_bci of:N*T*Cti,twl4030_bci*
industrialio

kernel/drivers/power/isp1704_charger.ko platform:isp1704_charger of:N*T*Cnxp,isp1704*

kernel/drivers/power/bq2415x_charger.ko i2c:bq24158 i2c:bq24157s i2c:bq24156a i2c:bq24156 i2c:bq24155 i2c:bq24153a i2c:bq24153 i2c:bq24152 i2c:bq24151a i2c:bq24151 i2c:bq24150a i2c:bq24150 i2c:bq2415x acpi*:BQ241580:* acpi*:BQS24157:* acpi*:BQA24156:* acpi*:BQ241560:* acpi*:BQ241550:* acpi*:BQA24153:* acpi*:BQ241530:* acpi*:BQ241520:* acpi*:BQA24151:* acpi*:BQ241510:* acpi*:BQA24150:* acpi*:BQ241500:* acpi*:BQ2415X:*

kernel/drivers/power/bq24190_charger.ko i2c:bq24190 of:N*T*Cti,bq24190*

kernel/drivers/power/bq27xxx_battery.ko platform:bq27000_battery i2c:bq27621 i2c:bq27441 i2c:bq27425 i2c:bq27421 i2c:bq27545 i2c:bq27742 i2c:bq27546 i2c:bq27542 i2c:bq27541 i2c:bq27531 i2c:bq27530 i2c:bq27520 i2c:bq27510 i2c:bq27500 i2c:bq27210 i2c:bq27200

kernel/drivers/net/usb/cdc-phonet.ko usb:v0421p*d*dc*dsc*dp*ic02iscFEip*in*
usbcore usbnet phonet

kernel/drivers/net/usb/asix.ko usb:v066Bp20F9d*dc*dsc*dp*ic*isc*ip*in* usb:v0B95p172Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0B95p7E2Bd*dc*dsc*dp*ic*isc*ip*in* usb:v0DB0pA877d*dc*dsc*dp*ic*isc*ip*in* usb:v14EApAB11d*dc*dsc*dp*ic*isc*ip*in* usb:v0B95p772Ad*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp1402d*dc*dsc*dp*ic*isc*ip*in* usb:v050Dp5055d*dc*dsc*dp*ic*isc*ip*in* usb:v04BBp0930d*dc*dsc*dp*ic*isc*ip*in* usb:v1737p0039d*dc*dsc*dp*ic*isc*ip*in* usb:v2001p1A02d*dc*dsc*dp*ic*isc*ip*in* usb:v2001p3C05d*dc*dsc*dp*ic*isc*ip*in* usb:v07D1p3C05d*dc*dsc*dp*ic*isc*ip*in* usb:v1557p7720d*dc*dsc*dp*ic*isc*ip*in* usb:v13B1p0018d*dc*dsc*dp*ic*isc*ip*in* usb:v0789p0160d*dc*dsc*dp*ic*isc*ip*in* usb:v0B95p1780d*dc*dsc*dp*ic*isc*ip*in* usb:v0B95p7720d*dc*dsc*dp*ic*isc*ip*in* usb:v0B95p772Bd*dc*dsc*dp*ic*isc*ip*in* usb:v17EFp7203d*dc*dsc*dp*ic*isc*ip*in* usb:v04F1p3008d*dc*dsc*dp*ic*isc*ip*in* usb:v1631p6200d*dc*dsc*dp*ic*isc*ip*in* usb:v1189p0893d*dc*dsc*dp*ic*isc*ip*in* usb:v07AAp0017d*dc*dsc*dp*ic*isc*ip*in* usb:v0DF6p061Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0DF6p0056d*dc*dsc*dp*ic*isc*ip*in* usb:v6189p182Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0411p006Ed*dc*dsc*dp*ic*isc*ip*in* usb:v0411p003Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0557p2009d*dc*dsc*dp*ic*isc*ip*in* usb:v08DDp0114d*dc*dsc*dp*ic*isc*ip*in* usb:v08DDp90FFd*dc*dsc*dp*ic*isc*ip*in* usb:v07B8p420Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0B95p1720d*dc*dsc*dp*ic*isc*ip*in* usb:v2001p1A00d*dc*dsc*dp*ic*isc*ip*in* usb:v0846p1040d*dc*dsc*dp*ic*isc*ip*in* usb:v077Bp2226d*dc*dsc*dp*ic*isc*ip*in*
usbnet usbcore

kernel/drivers/net/usb/smsc95xx.ko usb:v0424p9E08d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9730d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9530d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9909d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9908d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9907d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9906d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9905d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9904d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9903d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9902d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9901d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9900d*dc*dsc*dp*ic*isc*ip*in* usb:v0424pEC00d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9E01d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9E00d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9505d*dc*dsc*dp*ic*isc*ip*in* usb:v0424p9500d*dc*dsc*dp*ic*isc*ip*in*
usbnet usbcore

kernel/drivers/net/usb/usbnet.ko symbol:usbnet_write_cmd_async symbol:usbnet_nway_reset symbol:usbnet_resume symbol:usbnet_change_mtu symbol:usbnet_start_xmit symbol:usbnet_get_msglevel symbol:usbnet_write_cmd_nopm symbol:usbnet_defer_kevent symbol:usbnet_tx_timeout symbol:usbnet_set_msglevel symbol:usbnet_link_change symbol:cdc_parse_cdc_header symbol:usbnet_pause_rx symbol:usbnet_get_ethernet_addr symbol:usbnet_manage_power symbol:usbnet_resume_rx symbol:usbnet_read_cmd_nopm symbol:usbnet_get_drvinfo symbol:usbnet_stop symbol:usbnet_probe symbol:usbnet_skb_return symbol:usbnet_update_max_qlen symbol:usbnet_disconnect symbol:usbnet_unlink_rx_urbs symbol:usbnet_device_suggests_idle symbol:usbnet_set_settings symbol:usbnet_status_stop symbol:usbnet_read_cmd symbol:usbnet_status_start symbol:usbnet_get_endpoints symbol:usbnet_get_settings symbol:usbnet_suspend symbol:usbnet_get_link symbol:usbnet_purge_paused_rxq symbol:usbnet_open symbol:usbnet_write_cmd
usbcore

kernel/drivers/net/usb/cdc_ncm.ko usb:v*p*d*dc*dsc*dp*ic02isc0Dip00in* usb:v1519p0443d*dc*dsc*dp*ic02isc0Dip00in* usb:v12D1p*d*dc*dsc*dp*ic02isc0Dip00in* usb:v0930p*d*dc*dsc*dp*ic02isc0Dip00in* usb:v413Cp*d*dc*dsc*dp*ic02isc0Dip00in* usb:v413Cp81BCd*dc*dsc*dp*ic02isc0Dip00in* usb:v413Cp81BBd*dc*dsc*dp*ic02isc0Dip00in* usb:v0BDBp*d*dc*dsc*dp*ic02isc0Dip00in* symbol:cdc_ncm_rx_verify_ndp16 symbol:cdc_ncm_bind_common symbol:cdc_ncm_tx_fixup symbol:cdc_ncm_fill_tx_frame symbol:cdc_ncm_rx_verify_nth16 symbol:cdc_ncm_unbind symbol:cdc_ncm_select_altsetting symbol:cdc_ncm_rx_fixup symbol:cdc_ncm_change_mtu
usbcore usbnet

kernel/drivers/net/usb/ax88179_178a.ko usb:v17EFp304Bd*dc*dsc*dp*ic*isc*ip*in* usb:v04E8pA100d*dc*dsc*dp*ic*isc*ip*in* usb:v0DF6p0072d*dc*dsc*dp*ic*isc*ip*in* usb:v2001p4A00d*dc*dsc*dp*ic*isc*ip*in* usb:v0B95p178Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0B95p1790d*dc*dsc*dp*ic*isc*ip*in*
usbnet usbcore

kernel/drivers/net/usb/cdc_ether.ko usb:v12D1p*d*dc*dsc*dp*ic02isc06ipFFin* usb:v*p*d*dc*dsc*dp*ic02isc0Aip00in* usb:v*p*d*dc*dsc*dp*ic02isc06ip00in* usb:v413Cp81BAd*dc*dsc*dp*ic02isc06ip00in* usb:v1BC7p*d*dc*dsc*dp*ic02isc06ip00in* usb:v19D2p1181d*dc*dsc*dp*ic02isc06ip00in* usb:v19D2p1177d*dc*dsc*dp*ic02isc06ip00in* usb:v19D2p1173d*dc*dsc*dp*ic02isc06ip00in* usb:v19D2p1015d*dc*dsc*dp*ic02isc06ip00in* usb:v19D2p1003d*dc*dsc*dp*ic02isc06ip00in* usb:v0955p09FFd*dc*dsc*dp*ic02isc06ip00in* usb:v17EFp7205d*dc*dsc*dp*ic02isc06ip00in* usb:v04E8pA101d*dc*dsc*dp*ic02isc06ip00in* usb:v0BDAp8153d*dc*dsc*dp*ic02isc06ip00in* usb:v0BDAp8152d*dc*dsc*dp*ic02isc06ip00in* usb:v12D1p14ACd*dc*dsc*dp*ic*isc*ip*in01* usb:v16D5p650Ad*dc*dsc*dp*ic02isc06ip00in* usb:v03F0p421Dd*dc*dsc*dp*ic02isc06ip00in* usb:v1410p9011d*dc*dsc*dp*ic02isc06ip00in* usb:v413Cp819Bd*dc*dsc*dp*ic02isc06ip00in* usb:v413Cp8196d*dc*dsc*dp*ic02isc06ip00in* usb:v413Cp8195d*dc*dsc*dp*ic02isc06ip00in* usb:v1410p9010d*dc*dsc*dp*ic02isc06ip00in* usb:v1410pB001d*dc*dsc*dp*ic02isc06ip00in* usb:v046DpC11Fd*dc*dsc*dp*ic02isc0Aip00in* usb:v1004p61AAd*dc*dsc*dp*ic02isc06ip00in* usb:v07B4p0F02d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp9050d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp9032d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp9031d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp8007d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp8006d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp8005d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp8004d*dc*dsc*dp*ic02isc06ip00in* symbol:usbnet_cdc_status symbol:usbnet_cdc_bind symbol:usbnet_generic_cdc_bind symbol:usbnet_cdc_unbind
usbnet usbcore

kernel/drivers/net/usb/cdc_subset.ko usb:v0525pA4A2d*dc*dsc*dp*ic*isc*ip*in* usb:v1286p8001d*dc*dsc*dp*ic*isc*ip*in* usb:v8086p07D3d*dc*dsc*dp*ic*isc*ip*in* usb:v0E7Ep1001d*dc*dsc*dp*ic*isc*ip*in* usb:v049Fp505Ad*dc*dsc*dp*ic*isc*ip*in* usb:v050Fp0190d*dc*dsc*dp*ic*isc*ip*in* usb:v0525p2888d*dc*dsc*dp*ic*isc*ip*in* usb:v0525p9901d*dc*dsc*dp*ic*isc*ip*in* usb:v056Cp8100d*dc*dsc*dp*ic*isc*ip*in* usb:v050Dp0004d*dc*dsc*dp*ic*isc*ip*in* usb:v0547p2727d*dc*dsc*dp*ic*isc*ip*in* usb:v0547p2720d*dc*dsc*dp*ic*isc*ip*in* usb:v182Dp207Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0402p5632d*dc*dsc*dp*ic*isc*ip*in*
usbnet usbcore

kernel/drivers/net/usb/net1080.ko usb:v06D0p0622d*dc*dsc*dp*ic*isc*ip*in* usb:v0525p1080d*dc*dsc*dp*ic*isc*ip*in*
usbnet usbcore

kernel/drivers/net/usb/zaurus.ko usb:v046DpC11Fd*dc*dsc*dp*ic02isc0Aip00in* usb:v07B4p0F02d*dc*dsc*dp*ic02isc06ip00in* usb:v22B8p6425d*dc*dsc*dp*ic02isc0Aip00in* usb:v22B8p6027d*dc*dsc*dp*ic02isc0Aip00in* usb:v04DDp9050d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp9032d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp9031d*dc*dsc*dp*ic02isc0Aip00in* usb:v04DDp9031d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp8007d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp8006d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp8005d*dc*dsc*dp*ic02isc06ip00in* usb:v04DDp8004d*dc*dsc*dp*ic02isc06ip00in*
usbnet cdc_ether usbcore

kernel/drivers/net/can/can-dev.ko rtnl_link_can symbol:can_free_echo_skb symbol:can_dlc2len symbol:can_get_echo_skb symbol:unregister_candev symbol:can_change_mtu symbol:safe_candev_priv symbol:can_bus_off symbol:alloc_candev symbol:alloc_canfd_skb symbol:register_candev symbol:alloc_can_skb symbol:open_candev symbol:close_candev symbol:free_candev symbol:can_change_state symbol:can_len2dlc symbol:can_put_echo_skb symbol:alloc_can_err_skb

kernel/drivers/net/can/c_can/c_can_platform.ko platform:d_can platform:c_can platform:c_can_platform of:N*T*Cti,am4372_d_can* of:N*T*Cti,am3352_d_can* of:N*T*Cti,dra7_d_can* of:N*T*Cbosch,d_can* of:N*T*Cbosch,c_can*
c_can

kernel/drivers/net/can/c_can/c_can.ko symbol:free_c_can_dev symbol:c_can_power_up symbol:alloc_c_can_dev symbol:c_can_power_down symbol:register_c_can_dev symbol:unregister_c_can_dev
can_dev

kernel/drivers/net/wireless/mwifiex/mwifiex_sdio.ko sdio:c*v02DFd9141* sdio:c*v02DFd9139* sdio:c*v02DFd9135* sdio:c*v02DFd912D* sdio:c*v02DFd9129* sdio:c*v02DFd9119* sdio:c*v02DFd9116*
mwifiex

kernel/drivers/net/wireless/mwifiex/mwifiex_usb.ko usb:v1286p204Ed*dc*dsc*dp*icFFiscFFipFFin* usb:v1286p2052d*dc*dsc*dp*ic*isc*ip*in* usb:v1286p204Ad*dc*dsc*dp*icFFiscFFipFFin* usb:v1286p2049d*dc*dsc*dp*ic*isc*ip*in* usb:v1286p2044d*dc*dsc*dp*icFFiscFFipFFin* usb:v1286p2043d*dc*dsc*dp*ic*isc*ip*in* usb:v1286p2042d*dc*dsc*dp*icFFiscFFipFFin* usb:v1286p2041d*dc*dsc*dp*ic*isc*ip*in*
mwifiex usbcore

kernel/drivers/net/wireless/mwifiex/mwifiex.ko symbol:mwifiex_multi_chan_resync symbol:mwifiex_main_process symbol:mwifiex_remove_card symbol:mwifiex_upload_device_dump symbol:mwifiex_add_card symbol:_mwifiex_dbg symbol:mwifiex_drv_info_dump symbol:mwifiex_queue_main_work symbol:mwifiex_process_hs_config symbol:mwifiex_process_sleep_confirm_resp symbol:mwifiex_alloc_dma_align_buf symbol:mwifiex_init_shutdown_fw symbol:mwifiex_write_data_complete symbol:mwifiex_handle_rx_packet symbol:mwifiex_deauthenticate_all symbol:mwifiex_disable_auto_ds symbol:mwifiex_cancel_hs symbol:mwifiex_enable_hs symbol:mwifiex_add_virtual_intf symbol:mwifiex_del_virtual_intf
cfg80211

kernel/drivers/net/wireless/ti/wl18xx/wl18xx.ko platform:wl18xx
wlcore mac80211 cfg80211

kernel/drivers/net/wireless/ti/wl12xx/wl12xx.ko platform:wl12xx
wlcore mac80211

kernel/drivers/net/wireless/ti/wlcore/wlcore_spi.ko spi:wl1271

kernel/drivers/net/wireless/ti/wlcore/wlcore_sdio.ko sdio:c*v0097d4076*

kernel/drivers/net/wireless/ti/wlcore/wlcore.ko symbol:wlcore_free_hw symbol:wlcore_set_key symbol:wlcore_alloc_hw symbol:wlcore_probe symbol:wl12xx_debug_level symbol:wlcore_remove symbol:wlcore_cmd_generic_cfg symbol:wl1271_cmd_send symbol:wl1271_cmd_test symbol:wlcore_cmd_wait_for_event_or_timeout symbol:wlcore_get_native_channel_type symbol:wl1271_cmd_configure symbol:wl12xx_cmd_build_probe_req symbol:wl1271_cmd_data_path symbol:wlcore_disable_interrupts symbol:wlcore_enable_interrupts symbol:wlcore_set_partition symbol:wlcore_disable_interrupts_nosync symbol:wlcore_translate_addr symbol:wlcore_synchronize_interrupts symbol:wlcore_event_channel_switch symbol:wlcore_event_ba_rx_constraint symbol:wlcore_event_roc_complete symbol:wlcore_event_max_tx_failure symbol:wlcore_event_beacon_loss symbol:wlcore_event_soft_gemini_sense symbol:wlcore_event_inactive_sta symbol:wlcore_event_dummy_packet symbol:wlcore_event_sched_scan_completed symbol:wlcore_event_rssi_trigger symbol:wl1271_free_tx_id symbol:wl1271_tx_flush symbol:wl1271_tx_min_rate_get symbol:wlcore_calc_packet_alignment symbol:wl12xx_is_dummy_packet symbol:wlcore_tx_complete symbol:wl1271_ps_elp_wakeup symbol:wl1271_ps_elp_sleep symbol:wl1271_acx_pm_config symbol:wl1271_acx_init_mem_config symbol:wl1271_acx_sleep_auth symbol:wl12xx_acx_mem_cfg symbol:wl1271_acx_set_ht_capabilities symbol:wlcore_boot_upload_nvs symbol:wlcore_boot_upload_firmware symbol:wlcore_boot_run_firmware symbol:wl1271_format_buffer symbol:wl1271_debugfs_update_stats symbol:wlcore_scan_sched_scan_results symbol:wlcore_scan_sched_scan_ssid_list symbol:wlcore_set_scan_chan_params
mac80211 cfg80211

kernel/drivers/net/wireless/libertas/libertas_sdio.ko sdio:c*v02DFd9104* sdio:c*v02DFd9103*
libertas

kernel/drivers/net/wireless/libertas/libertas.ko symbol:__lbs_cmd symbol:lbs_cmd_copyback symbol:lbs_host_sleep_cfg symbol:lbs_add_card symbol:lbs_debug symbol:lbs_resume symbol:lbs_host_to_card_done symbol:lbs_disablemesh symbol:lbs_remove_card symbol:lbs_queue_event symbol:lbs_notify_command_response symbol:lbs_suspend symbol:lbs_start_card symbol:lbs_stop_card symbol:lbs_process_rxed_packet symbol:lbs_send_tx_feedback symbol:lbs_get_firmware symbol:lbs_get_firmware_async
cfg80211

kernel/drivers/net/wireless/libertas/usb8xxx.ko usb:v05A3p8388d*dc*dsc*dp*ic*isc*ip*in* usb:v1286p2001d*dc*dsc*dp*ic*isc*ip*in*
libertas usbcore

kernel/drivers/hwmon/lm75.ko i2c:tmp75c i2c:tmp75 i2c:tmp275 i2c:tmp175 i2c:tmp112 i2c:tmp105 i2c:tmp101 i2c:tmp100 i2c:tcn75 i2c:stds75 i2c:mcp980x i2c:max6626 i2c:max6625 i2c:lm75b i2c:lm75a i2c:lm75 i2c:g751 i2c:ds7505 i2c:ds75 i2c:ds1775 i2c:adt75
thermal_sys hwmon

kernel/drivers/hwmon/gpio-fan.ko platform:gpio_fan of:N*T*Cgpio_fan*
thermal_sys hwmon

kernel/drivers/hwmon/tmp102.ko i2c:tmp102
hwmon thermal_sys

kernel/drivers/hwmon/hwmon.ko symbol:hwmon_device_register_with_groups symbol:devm_hwmon_device_register_with_groups symbol:devm_hwmon_device_unregister symbol:hwmon_device_register symbol:hwmon_device_unregister

kernel/drivers/leds/leds-pwm.ko platform:leds_pwm of:N*T*Cpwm_leds*
led_class

kernel/drivers/leds/trigger/ledtrig-gpio.ko

kernel/drivers/leds/trigger/ledtrig-oneshot.ko

kernel/drivers/leds/trigger/ledtrig-heartbeat.ko

kernel/drivers/leds/trigger/ledtrig-backlight.ko

kernel/drivers/leds/trigger/ledtrig-default-on.ko

kernel/drivers/leds/trigger/ledtrig-timer.ko

kernel/drivers/leds/leds-gpio.ko platform:leds_gpio of:N*T*Cgpio_leds*
led_class

kernel/drivers/leds/led-class.ko symbol:led_classdev_resume symbol:led_classdev_register symbol:led_classdev_suspend symbol:devm_led_classdev_unregister symbol:led_classdev_unregister symbol:devm_led_classdev_register

kernel/drivers/char/hw_random/rng-core.ko symbol:hwrng_unregister symbol:devm_hwrng_register symbol:devm_hwrng_unregister symbol:hwrng_register

kernel/drivers/char/hw_random/omap3-rom-rng.ko platform:omap3_rom_rng
rng_core

kernel/drivers/char/hw_random/omap-rng.ko platform:omap_rng of:N*T*Cti,omap4_rng* of:N*T*Cti,omap2_rng*
rng_core

kernel/drivers/rtc/rtc-omap.ko platform:omap_rtc platform:da830_rtc platform:am3352_rtc of:N*T*Cti,da830_rtc* of:N*T*Cti,am3352_rtc*

kernel/drivers/rtc/rtc-twl.ko platform:twl_rtc of:N*T*Cti,twl4030_rtc*

kernel/drivers/rtc/rtc-ds1307.ko i2c:rx8025 i2c:pt7c4338 i2c:mcp7941x i2c:mcp7940x i2c:m41t00 i2c:ds3231 i2c:ds1340 i2c:ds1388 i2c:ds1339 i2c:ds1338 i2c:ds1337 i2c:ds1307

kernel/drivers/rtc/rtc-palmas.ko platform:palmas_rtc of:N*T*Cti,palmas_rtc*

kernel/drivers/extcon/extcon.ko symbol:extcon_get_extcon_dev symbol:extcon_get_edev_by_phandle symbol:extcon_update_state symbol:devm_extcon_dev_allocate symbol:devm_extcon_dev_free symbol:extcon_register_interest symbol:extcon_set_cable_state symbol:extcon_get_cable_state symbol:extcon_dev_unregister symbol:extcon_unregister_interest symbol:devm_extcon_dev_unregister symbol:extcon_get_cable_state_ symbol:extcon_dev_free symbol:extcon_set_cable_state_ symbol:extcon_dev_register symbol:extcon_unregister_notifier symbol:devm_extcon_dev_register symbol:extcon_set_state symbol:extcon_register_notifier

kernel/drivers/extcon/extcon-palmas.ko platform:palmas_usb of:N*T*Cti,twl6035_usb_vid* of:N*T*Cti,twl6035_usb* of:N*T*Cti,palmas_usb_vid* of:N*T*Cti,palmas_usb*
extcon

kernel/drivers/extcon/extcon-usb-gpio.ko of:N*T*Clinux,extcon_usb_gpio*
extcon

kernel/drivers/gpio/gpio-pca953x.ko i2c:xra1202 i2c:tca9539 i2c:tca6424 i2c:tca6416 i2c:tca6408 i2c:pca6107 i2c:max7315 i2c:max7313 i2c:max7312 i2c:max7310 i2c:pca9698 i2c:pca9575 i2c:pca9574 i2c:pca9557 i2c:pca9556 i2c:pca9555 i2c:pca9554 i2c:pca9539 i2c:pca9538 i2c:pca9537 i2c:pca9536 i2c:pca9535 i2c:pca9534 i2c:pca9505 acpi*:INT3491:* of:N*T*Cexar,xra1202* of:N*T*Cti,tca6424* of:N*T*Cti,tca6416* of:N*T*Cti,tca6408* of:N*T*Cti,pca6107* of:N*T*Cmaxim,max7315* of:N*T*Cmaxim,max7313* of:N*T*Cmaxim,max7312* of:N*T*Cmaxim,max7310* of:N*T*Cnxp,pca9698* of:N*T*Cnxp,pca9575* of:N*T*Cnxp,pca9574* of:N*T*Cnxp,pca9557* of:N*T*Cnxp,pca9556* of:N*T*Cnxp,pca9555* of:N*T*Cnxp,pca9554* of:N*T*Cnxp,pca9539* of:N*T*Cnxp,pca9538* of:N*T*Cnxp,pca9537* of:N*T*Cnxp,pca9536* of:N*T*Cnxp,pca9535* of:N*T*Cnxp,pca9534* of:N*T*Cnxp,pca9505*

kernel/drivers/regulator/tps62360-regulator.ko of:N*T*Cti,tps62363* of:N*T*Cti,tps62362* of:N*T*Cti,tps62361* of:N*T*Cti,tps62360* i2c:tps62363 i2c:tps62362 i2c:tps62361 i2c:tps62360

kernel/drivers/pwm/pwm-tiecap.ko of:N*T*Cti,am33xx_ecap*

kernel/drivers/pwm/pwm-tiehrpwm.ko of:N*T*Cti,am33xx_ehrpwm*

kernel/drivers/pwm/pwm-twl-led.ko platform:twl_pwmled of:N*T*Cti,twl6030_pwmled* of:N*T*Cti,twl4030_pwmled*

kernel/drivers/pwm/pwm-twl.ko platform:twl_pwm of:N*T*Cti,twl6030_pwm* of:N*T*Cti,twl4030_pwm*

kernel/drivers/clk/clk-palmas.ko platform:palmas_clk of:N*T*Cti,palmas_clk32kgaudio* of:N*T*Cti,palmas_clk32kg*

kernel/drivers/iio/buffer/kfifo_buf.ko symbol:iio_kfifo_allocate symbol:devm_iio_kfifo_allocate symbol:iio_kfifo_free symbol:devm_iio_kfifo_free
industrialio

kernel/drivers/iio/industrialio.ko symbol:iio_bus_type symbol:iio_enum_read symbol:iio_device_alloc symbol:iio_device_unregister symbol:iio_enum_write symbol:devm_iio_device_free symbol:devm_iio_device_unregister symbol:iio_device_register symbol:iio_device_free symbol:devm_iio_device_alloc symbol:iio_str_to_fixpoint symbol:devm_iio_device_register symbol:iio_enum_available_read symbol:iio_read_const_attr symbol:iio_push_event symbol:iio_channel_get_all symbol:iio_convert_raw_to_processed symbol:iio_read_channel_raw symbol:iio_channel_release symbol:iio_map_array_register symbol:iio_get_channel_type symbol:iio_write_channel_raw symbol:iio_read_channel_scale symbol:iio_channel_get symbol:iio_read_channel_processed symbol:iio_channel_release_all symbol:iio_map_array_unregister symbol:iio_read_channel_average_raw symbol:iio_buffer_get symbol:iio_buffer_put symbol:iio_update_demux symbol:iio_scan_mask_query symbol:iio_update_buffers symbol:iio_buffer_init symbol:iio_validate_scan_mask_onehot symbol:iio_push_to_buffers

kernel/drivers/iio/adc/ti_am335x_adc.ko of:N*T*Cti,am3359_adc*
industrialio kfifo_buf ti_am335x_tscadc

kernel/drivers/hid/hid-generic.ko hid:b*g0001v*p*

kernel/drivers/hid/usbhid/usbkbd.ko usb:v*p*d*dc*dsc*dp*ic03isc01ip01in*
usbcore

kernel/drivers/hid/usbhid/usbhid.ko usb:v*p*d*dc*dsc*dp*ic03isc*ip*in* symbol:usbhid_lookup_quirk symbol:hiddev_hid_event
usbcore

kernel/drivers/hid/usbhid/usbmouse.ko usb:v*p*d*dc*dsc*dp*ic03isc01ip02in*
usbcore

kernel/drivers/memory/emif.ko platform:emif of:N*T*Cti,emif_4d5* of:N*T*Cti,emif_4d*

kernel/drivers/phy/phy-twl4030-usb.ko platform:twl4030_usb of:N*T*Cti,twl4030_usb*
omap2430

kernel/drivers/phy/phy-omap-usb2.ko platform:omap_usb2 of:N*T*Cti,am437x_usb2* of:N*T*Cti,dra7x_usb2* of:N*T*Cti,omap5_usb2* of:N*T*Cti,omap_usb2* symbol:omap_usb2_set_comparator

kernel/drivers/phy/phy-dm816x-usb.ko platform:dm816x_usb of:N*T*Cti,dm8168_usb_phy*

kernel/drivers/bluetooth/hci_uart.ko tty_ldisc_15 symbol:h4_recv_buf
bluetooth

kernel/drivers/bluetooth/hci_vhci.ko char_major_10_137 devname:vhci
bluetooth

kernel/drivers/bluetooth/btmrvl.ko symbol:btmrvl_pscan_window_reporting symbol:btmrvl_interrupt symbol:btmrvl_send_hscfg_cmd symbol:btmrvl_remove_card symbol:btmrvl_process_event symbol:btmrvl_send_module_cfg_cmd symbol:btmrvl_add_card symbol:btmrvl_enable_hs symbol:btmrvl_enable_ps symbol:btmrvl_register_hdev symbol:btmrvl_check_evtpkt
bluetooth

kernel/drivers/bluetooth/btusb.ko usb:v8087p0A5Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0930p*d*dc*dsc*dp*icFFisc01ip01in* usb:v13D3p*d*dc*dsc*dp*icFFisc01ip01in* usb:v050Dp*d*dc*dsc*dp*icFFisc01ip01in* usb:v0B05p*d*dc*dsc*dp*icFFisc01ip01in* usb:v0A5Cp*d*dc*dsc*dp*icFFisc01ip01in* usb:v04CAp*d*dc*dsc*dp*icFFisc01ip01in* usb:v0489p*d*dc*dsc*dp*icFFisc01ip01in* usb:v105BpE065d*dc*dsc*dp*ic*isc*ip*in* usb:v19FFp0239d*dc*dsc*dp*ic*isc*ip*in* usb:v413Cp8197d*dc*dsc*dp*ic*isc*ip*in* usb:v0C10p0000d*dc*dsc*dp*ic*isc*ip*in* usb:v0BDBp1002d*dc*dsc*dp*ic*isc*ip*in* usb:v044Ep3002d*dc*dsc*dp*ic*isc*ip*in* usb:v044Ep3001d*dc*dsc*dp*ic*isc*ip*in* usb:v04BFp030Ad*dc*dsc*dp*ic*isc*ip*in* usb:v057Cp3800d*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp8281d*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp821Ad*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp821Fd*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp821Bd*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp8218d*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp8215d*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp8213d*dc*dsc*dp*ic*isc*ip*in* usb:v0A5Cp21E1d*dc*dsc*dp*ic*isc*ip*in* usb:v0E8Dp763Fd*dc*dsc*dp*ic*isc*ip*in* usb:v05ACp*d*dc*dsc*dp*icFFisc01ip01in* usb:v*p*d*dc*dsc*dp*icE0isc01ip01in* usb:v*p*d*dcE0dsc01dp04ic*isc*ip*in* usb:v*p*d*dcE0dsc01dp01ic*isc*ip*in*
usbcore btintel btbcm btrtl bluetooth

kernel/drivers/bluetooth/bfusb.ko usb:v057Cp2200d*dc*dsc*dp*ic*isc*ip*in*
usbcore bluetooth

kernel/drivers/bluetooth/bcm203x.ko usb:v0A5Cp2033d*dc*dsc*dp*ic*isc*ip*in*
usbcore bluetooth

kernel/drivers/bluetooth/btintel.ko symbol:btintel_set_diag_mfg symbol:btintel_hw_error symbol:btintel_set_diag symbol:btintel_set_event_mask symbol:btintel_secure_send symbol:btintel_check_bdaddr symbol:btintel_regmap_init symbol:btintel_load_ddc_config symbol:btintel_set_event_mask_mfg symbol:btintel_version_info symbol:btintel_set_bdaddr
bluetooth

kernel/drivers/bluetooth/btrtl.ko symbol:btrtl_setup_realtek
bluetooth

kernel/drivers/bluetooth/btsdio.ko sdio:c09v*d* sdio:c03v*d* sdio:c02v*d*
bluetooth

kernel/drivers/bluetooth/bpa10x.ko usb:v08FDp0002d*dc*dsc*dp*ic*isc*ip*in*
bluetooth usbcore hci_uart

kernel/drivers/bluetooth/btbcm.ko symbol:btbcm_patchram symbol:btbcm_set_bdaddr symbol:btbcm_setup_apple symbol:btbcm_setup_patchram symbol:btbcm_check_bdaddr symbol:btbcm_initialize symbol:btbcm_finalize
bluetooth

kernel/drivers/bluetooth/btmrvl_sdio.ko sdio:c*v02DFd9142* sdio:c*v02DFd912E* sdio:c*v02DFd9136* sdio:c*v02DFd912A* sdio:c*v02DFd911B* sdio:c*v02DFd911A* sdio:c*v02DFd9105*
btmrvl bluetooth

kernel/drivers/misc/bmp085-i2c.ko i2c:bmp180 i2c:bmp085
bmp085

kernel/drivers/misc/bmp085.ko symbol:bmp085_regmap_config symbol:bmp085_remove symbol:bmp085_detect symbol:bmp085_probe

kernel/drivers/misc/lis3lv02d/lis3lv02d_i2c.ko of:N*T*Cst,lis3lv02d* i2c:lis331dlh i2c:lis3lv02d
lis3lv02d

kernel/drivers/misc/lis3lv02d/lis3lv02d.ko symbol:lis3lv02d_joystick_enable symbol:lis3lv02d_poweron symbol:lis3lv02d_poweroff symbol:lis3lv02d_remove_fs symbol:lis3lv02d_init_dt symbol:lis3lv02d_init_device symbol:lis3_dev symbol:lis3lv02d_joystick_disable
input_polldev

kernel/drivers/misc/tsl2550.ko i2c:tsl2550

kernel/drivers/video/fbdev/core/cfbfillrect.ko symbol:cfb_fillrect

kernel/drivers/video/fbdev/core/cfbcopyarea.ko symbol:cfb_copyarea

kernel/drivers/video/fbdev/core/cfbimgblt.ko symbol:cfb_imageblit

kernel/drivers/video/fbdev/omap2/dss/omapdss.ko of:N*T*Cti,dra7_dss* of:N*T*Cti,omap5_dss* of:N*T*Cti,omap4_dss* of:N*T*Cti,omap3_dss* of:N*T*Cti,omap2_dss* symbol:omapdss_get_version symbol:omapdss_get_default_display_name symbol:omapdss_is_initialized symbol:dss_feat_get_supported_color_modes symbol:dss_feat_get_num_ovls symbol:dss_feat_get_supported_displays symbol:dss_feat_get_supported_outputs symbol:dss_feat_get_num_mgrs symbol:dispc_mgr_set_lcd_config symbol:dispc_ovl_set_fifo_threshold symbol:dispc_runtime_put symbol:dispc_read_irqstatus symbol:dispc_mgr_go_busy symbol:dispc_ovl_enabled symbol:dispc_mgr_is_enabled symbol:dispc_mgr_get_sync_lost_irq symbol:dispc_write_irqenable symbol:dispc_ovl_set_channel_out symbol:dispc_mgr_go symbol:dispc_ovl_setup symbol:dispc_mgr_get_framedone_irq symbol:dispc_mgr_enable symbol:dispc_mgr_setup symbol:dispc_ovl_enable symbol:dispc_mgr_get_vsync_irq symbol:dispc_free_irq symbol:dispc_read_irqenable symbol:dispc_mgr_set_timings symbol:dispc_request_irq symbol:dispc_ovl_check symbol:dispc_clear_irqstatus symbol:dispc_ovl_compute_fifo_thresholds symbol:dispc_runtime_get symbol:omapdss_default_get_timings symbol:omapdss_register_display symbol:omap_dss_get_device symbol:omap_video_timings_to_videomode symbol:omapdss_default_get_recommended_bpp symbol:omap_dss_put_device symbol:omap_dss_get_next_device symbol:omapdss_default_get_resolution symbol:videomode_to_omap_video_timings symbol:omap_dss_find_device symbol:omapdss_unregister_display symbol:dss_uninstall_mgr_ops symbol:omapdss_output_unset_device symbol:dss_mgr_enable symbol:omap_dss_find_output symbol:dss_mgr_connect symbol:dss_mgr_register_framedone_handler symbol:omapdss_find_mgr_from_display symbol:dss_mgr_disable symbol:dss_install_mgr_ops symbol:omap_dss_get_output symbol:dss_mgr_unregister_framedone_handler symbol:omapdss_output_set_device symbol:omapdss_register_output symbol:dss_mgr_start_update symbol:omapdss_unregister_output symbol:omap_dss_find_output_by_port_node symbol:omapdss_find_output_from_display symbol:dss_mgr_set_timings symbol:dss_mgr_set_lcd_config symbol:dss_mgr_disconnect symbol:omapdss_of_get_next_endpoint symbol:omapdss_of_get_next_port symbol:omapdss_of_find_source_for_first_ep symbol:omapdss_of_get_first_endpoint symbol:omap_dss_get_num_overlay_managers symbol:omap_dss_get_overlay_manager symbol:omap_dss_get_overlay symbol:omap_dss_get_num_overlays symbol:omapdss_compat_uninit symbol:omapdss_compat_init symbol:omap_dispc_register_isr symbol:omap_dispc_unregister_isr symbol:omap_dss_ntsc_timings symbol:omap_dss_pal_timings

kernel/drivers/video/fbdev/omap2/omapfb/omapfb.ko platform:omapfb
omapdss cfbfillrect cfbimgblt cfbcopyarea

kernel/drivers/video/fbdev/omap2/displays-new/panel-lgphilips-lb035q02.ko spi:lgphilips,lb035q02 of:N*T*Comapdss,lgphilips,lb035q02*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/panel-nec-nl8048hl11.ko spi:nec,nl8048hl11 of:N*T*Comapdss,nec,nl8048hl11*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/connector-dvi.ko of:N*T*Comapdss,dvi_connector*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/panel-sharp-ls037v7dw01.ko of:N*T*Comapdss,sharp,ls037v7dw01*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/panel-dpi.ko of:N*T*Comapdss,panel_dpi*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/encoder-tfp410.ko of:N*T*Comapdss,ti,tfp410*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/panel-tpo-td043mtea1.ko spi:tpo,td043mtea1 of:N*T*Comapdss,tpo,td043mtea1*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/encoder-tpd12s015.ko of:N*T*Comapdss,ti,tpd12s015*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/connector-hdmi.ko of:N*T*Comapdss,hdmi_connector*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/panel-sony-acx565akm.ko of:N*T*Comapdss,sony,acx565akm*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/panel-dsi-cm.ko of:N*T*Comapdss,panel_dsi_cm*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/connector-analog-tv.ko of:N*T*Comapdss,composite_video_connector* of:N*T*Comapdss,svideo_connector*
omapdss

kernel/drivers/video/fbdev/omap2/displays-new/panel-tpo-td028ttec1.ko spi:toppoly,td028ttec1 of:N*T*Comapdss,toppoly,td028ttec1*
omapdss

kernel/drivers/video/backlight/gpio_backlight.ko platform:gpio_backlight of:N*T*Cgpio_backlight*

kernel/drivers/video/backlight/pandora_bl.ko platform:pandora_backlight

kernel/drivers/video/backlight/pwm_bl.ko platform:pwm_backlight of:N*T*Cpwm_backlight*

kernel/drivers/video/backlight/generic_bl.ko

kernel/sound/usb/snd-usb-audio.ko usb:v*p*d*dc*dsc*dp*ic01isc01ip*in* usb:v0D8Cp0103d*dc*dsc*dp*ic*isc*ip*in* usb:v*p*d*dc*dsc*dp*ic01isc03ip*in* usb:v1686p00DDd*dc*dsc*dp*ic*isc*ip*in* usb:v200Cp100Bd*dc*dsc*dp*ic*isc*ip*in* usb:v045Ep0283d*dc*dsc*dp*ic*isc*ip*in* usb:v0644p8021d*dc*dsc*dp*ic*isc*ip*in* usb:v0DBAp3000d*dc*dsc*dp*ic*isc*ip*in* usb:v0DBAp1000d*dc*dsc*dp*ic*isc*ip*in* usb:v05E1p0408d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7270d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7213d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7260d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p8200d*dc*dsc*dp*ic01isc01ip*in* usb:v05E1p0480d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7281d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7211d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7201d*dc*dsc*dp*ic01isc01ip*in* usb:v0FD9p0008d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7280d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p721Fd*dc*dsc*dp*ic01isc01ip*in* usb:v2040p721Ed*dc*dsc*dp*ic01isc01ip*in* usb:v2040p721Bd*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7217d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7210d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7240d*dc*dsc*dp*ic01isc01ip*in* usb:v2040p7200d*dc*dsc*dp*ic01isc01ip*in* usb:v7104p2202d*dc*dsc*dp*ic*isc*ip*in* usb:v4752p0011d*dc*dsc*dp*ic*isc*ip*in* usb:v1F38p0001d*dc*dsc*dp*ic*isc*ip*in* usb:v1A86p752Dd*dc*dsc*dp*ic*isc*ip*in* usb:v17CCp1020d*dc*dsc*dp*ic*isc*ip*in* usb:v17CCp1010d*dc*dsc*dp*ic*isc*ip*in* usb:v17CCp1000d*dc*dsc*dp*ic*isc*ip*in* usb:v13E5p0001d*dc*dsc*dp*ic*isc*ip*in* usb:v133Ep0815d*dc*dsc*dp*icFFisc*ip*in* usb:v1235p4661d*dc*dsc*dp*icFFisc*ip*in* usb:v1235p0018d*dc*dsc*dp*ic*isc*ip*in* usb:v1235p0010d*dc*dsc*dp*ic*isc*ip*in* usb:v1235p000Ed*dc*dsc*dp*ic*isc*ip*in* usb:v1235p000Ad*dc*dsc*dp*ic*isc*ip*in* usb:v1235p0002d*dc*dsc*dp*icFFisc*ip*in* usb:v1235p0001d*dc*dsc*dp*icFFisc*ip*in* usb:v103Dp0101d*dc*dsc*dp*ic*isc*ip*in* usb:v103Dp0100d*dc*dsc*dp*ic*isc*ip*in* usb:v0CCDp0035d*dc*dsc*dp*ic*isc*ip*in* usb:v0CCDp0028d*dc*dsc*dp*ic*isc*ip*in* usb:v0CCDp0014d*dc*dsc*dp*icFFisc*ip*in* usb:v0CCDp0013d*dc*dsc*dp*icFFisc*ip*in* usb:v0CCDp0012d*dc*dsc*dp*icFFisc*ip*in* usb:v0A4Ep4040d*dc*dsc*dp*icFFisc*ip*in* usb:v0A4Ep2040d*dc*dsc*dp*icFFisc*ip*in* usb:v09E8p0021d*dc*dsc*dp*ic*isc*ip*in* usb:v09E8p0062d*dc*dsc*dp*ic*isc*ip*in* usb:v0944p0201d*dc*dsc*dp*icFFisc*ip*in* usb:v0944p0200d*dc*dsc*dp*icFFisc*ip*in* usb:v086Ap0003d*dc*dsc*dp*ic*isc*ip*in* usb:v086Ap0002d*dc*dsc*dp*ic*isc*ip*in* usb:v086Ap0001d*dc*dsc*dp*ic*isc*ip*in* usb:v07FDp0001d*dc*dsc02dp*ic*isc*ip*in* usb:v07CFp6802d*dc*dsc*dp*ic*isc*ip*in* usb:v07CFp6801d*dc*dsc*dp*ic*isc*ip*in* usb:v0763p2081d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p2080d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p2031d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p2030d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p2019d*dc*dsc*dp*ic*isc*ip*in* usb:v0763p200Dd*dc*dsc*dp*icFFisc*ip*in* usb:v0763p2008d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p2003d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p2001d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p1041d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p1033d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p1031d010dc*dsc*dp*ic*isc*ip*in* usb:v0763p1021d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p1015d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p1011d*dc*dsc*dp*icFFisc*ip*in* usb:v0763p1002d*dc*dsc*dp*icFFisc*ip*in* usb:v06F8pB000d*dc*dsc*dp*icFFisc*ip*in* usb:v0582p*d*dc*dsc*dp*icFFisc*ip*in* usb:v0582p0159d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p012Fd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0120d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0113d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0108d*dc*dsc*dp*icFFisc*ip*in* usb:v0582p00E6d*dc*dsc*dp*icFFisc*ip*in* usb:v0582p00C4d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p00A3d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p008Bd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0080d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p007Ad*dc*dsc*dp*icFFisc*ip*in* usb:v0582p0075d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0074d*dc*dsc*dp*icFFisc*ip*in* usb:v0582p006Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0065d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0064d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0060d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0052d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0050d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p004Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p004Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0048d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0047d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0042d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0040d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p003Bd*dc*dsc*dp*icFFisc*ip*in* usb:v0582p0037d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0033d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p002Fd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p002Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p002Bd*dc*dsc*dp*icFFisc*ip*in* usb:v0582p0029d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0027d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0025d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0023d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p001Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p001Bd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0016d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0014d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0012d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0010d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p000Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p000Bd*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0009d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0008d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0007d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0005d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0004d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0003d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0002d*dc*dsc*dp*ic*isc*ip*in* usb:v0582p0000d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p*d*dc*dsc*dp*icFFisc*ip*in* usb:v0499p7010d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p7000d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p500Fd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p500Ed*dc*dsc*dp*ic*isc*ip*in* usb:v0499p500Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p500Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p500Bd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p500Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5009d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5008d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5007d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5006d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5005d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5004d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5003d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5002d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5001d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p5000d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p2003d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p2002d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p2001d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p2000d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p150Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p150Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1509d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1507d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1503d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p105Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p105Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p105Bd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p105Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1059d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1058d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1057d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1056d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1055d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1054d*dc*dsc*dp*icFFisc*ip*in* usb:v0499p1053d*dc*dsc*dp*icFFisc*ip*in* usb:v0499p1052d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1051d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1050d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p104Fd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p104Ed*dc*dsc*dp*icFFisc*ip*in* usb:v0499p1045d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1044d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1043d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1042d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1041d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1040d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p103Fd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p103Ed*dc*dsc*dp*ic*isc*ip*in* usb:v0499p103Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p103Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p103Bd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p103Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1039d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1038d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1037d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1036d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1035d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1034d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1033d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1032d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1031d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1030d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p102Ed*dc*dsc*dp*ic*isc*ip*in* usb:v0499p102Bd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p102Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1029d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1028d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1027d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1026d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1025d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1024d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1023d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1022d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1021d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1020d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p101Fd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p101Ed*dc*dsc*dp*ic*isc*ip*in* usb:v0499p101Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p101Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p101Bd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p101Ad*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1019d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1018d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1017d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1016d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1015d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1014d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1013d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1012d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1011d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1010d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p100Fd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p100Ed*dc*dsc*dp*ic*isc*ip*in* usb:v0499p100Dd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p100Cd*dc*dsc*dp*ic*isc*ip*in* usb:v0499p100Ad*dc*dsc*dp*icFFisc*ip*in* usb:v0499p1009d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1008d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1007d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1006d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1005d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1004d*dc*dsc*dp*icFFisc*ip*in* usb:v0499p1003d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1002d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1001d*dc*dsc*dp*ic*isc*ip*in* usb:v0499p1000d*dc*dsc*dp*ic*isc*ip*in* usb:v046Dp0990d*dc*dsc*dp*ic01isc01ip*in* usb:v046Dp08F6d*dc*dsc*dp*ic01isc01ip*in* usb:v046Dp08F5d*dc*dsc*dp*ic01isc01ip*in* usb:v046Dp08F0d*dc*dsc*dp*ic01isc01ip*in* usb:v046Dp08C6d*dc*dsc*dp*ic01isc01ip*in* usb:v046Dp08AEd*dc*dsc*dp*ic01isc01ip*in* usb:v046Dp0850d*dc*dsc*dp*ic01isc01ip*in* usb:v0424pB832d*dc*dsc*dp*ic*isc*ip*in* usb:v041Ep3F19d*dc*dsc*dp*ic*isc*ip*in* usb:v041Ep3F0Ad*dc*dsc*dp*ic*isc*ip*in* usb:v041Ep3F04d*dc*dsc*dp*ic*isc*ip*in* usb:v041Ep3F02d*dc*dsc*dp*ic*isc*ip*in* usb:v041Ep3048d*dc*dsc*dp*ic*isc*ip*in* usb:v041Ep3010d*dc*dsc*dp*ic*isc*ip*in* usb:v041Ep0005d*dc*dsc*dp*ic*isc*ip*in* usb:v0403pB8D8d*dc*dsc*dp*ic*isc*ip*in*
snd_usbmidi_lib snd_pcm snd usbcore snd_hwdep

kernel/sound/usb/snd-usbmidi-lib.ko symbol:snd_usbmidi_resume symbol:snd_usbmidi_input_start symbol:snd_usbmidi_disconnect symbol:snd_usbmidi_suspend symbol:snd_usbmidi_create symbol:snd_usbmidi_input_stop
usbcore snd_rawmidi snd

kernel/sound/core/snd-hwdep.ko symbol:snd_hwdep_new
snd

kernel/sound/core/snd-rawmidi.ko symbol:snd_rawmidi_input_params symbol:snd_rawmidi_set_ops symbol:snd_rawmidi_drain_input symbol:snd_rawmidi_drop_output symbol:snd_rawmidi_transmit_empty symbol:snd_rawmidi_kernel_release symbol:__snd_rawmidi_transmit_peek symbol:snd_rawmidi_transmit_peek symbol:snd_rawmidi_kernel_write symbol:snd_rawmidi_receive symbol:snd_rawmidi_transmit_ack symbol:snd_rawmidi_info_select symbol:snd_rawmidi_kernel_open symbol:snd_rawmidi_transmit symbol:snd_rawmidi_kernel_read symbol:snd_rawmidi_drain_output symbol:__snd_rawmidi_transmit_ack symbol:snd_rawmidi_output_params symbol:snd_rawmidi_new
snd

kernel/sound/core/snd-timer.ko devname:snd/timer char_major_116_33 symbol:snd_timer_stop symbol:snd_timer_new symbol:snd_timer_open symbol:snd_timer_global_free symbol:snd_timer_close symbol:snd_timer_interrupt symbol:snd_timer_global_new symbol:snd_timer_notify symbol:snd_timer_global_register symbol:snd_timer_continue symbol:snd_timer_pause symbol:snd_timer_resolution symbol:snd_timer_start
snd

kernel/sound/core/snd-pcm.ko symbol:snd_pcm_new_internal symbol:snd_pcm_new_stream symbol:snd_pcm_new symbol:snd_pcm_format_name symbol:snd_pcm_notify symbol:snd_pcm_stream_unlock_irq symbol:snd_pcm_stop symbol:snd_pcm_stream_lock_irq symbol:snd_pcm_stream_unlock symbol:_snd_pcm_stream_lock_irqsave symbol:snd_pcm_mmap_data symbol:snd_pcm_hw_refine symbol:snd_pcm_suspend symbol:snd_pcm_open_substream symbol:snd_pcm_release_substream symbol:snd_pcm_stream_unlock_irqrestore symbol:snd_pcm_kernel_ioctl symbol:snd_pcm_suspend_all symbol:snd_pcm_stream_lock symbol:snd_pcm_lib_default_mmap symbol:snd_pcm_stop_xrun symbol:snd_pcm_hw_rule_noresample symbol:snd_pcm_debug_name symbol:snd_pcm_hw_param_value symbol:snd_pcm_hw_param_first symbol:snd_pcm_hw_rule_add symbol:snd_pcm_hw_param_last symbol:snd_pcm_lib_ioctl symbol:snd_pcm_hw_constraint_list symbol:snd_interval_ranges symbol:snd_pcm_hw_constraint_step symbol:snd_interval_list symbol:_snd_pcm_hw_param_setempty symbol:snd_pcm_lib_read symbol:snd_pcm_hw_constraint_integer symbol:snd_pcm_alt_chmaps symbol:snd_pcm_hw_constraint_ratnums symbol:snd_pcm_std_chmaps symbol:snd_pcm_lib_write symbol:snd_pcm_hw_constraint_ratdens symbol:_snd_pcm_hw_params_any symbol:snd_pcm_hw_constraint_msbits symbol:snd_pcm_lib_writev symbol:snd_pcm_hw_constraint_pow2 symbol:snd_interval_refine symbol:snd_pcm_hw_constraint_mask64 symbol:snd_pcm_hw_constraint_minmax symbol:snd_pcm_set_ops symbol:snd_pcm_period_elapsed symbol:snd_pcm_set_sync symbol:snd_pcm_hw_constraint_ranges symbol:snd_pcm_add_chmap_ctls symbol:snd_pcm_lib_readv symbol:snd_interval_ratnum symbol:snd_pcm_format_signed symbol:snd_pcm_format_width symbol:snd_pcm_rate_mask_intersect symbol:snd_pcm_format_linear symbol:snd_pcm_format_little_endian symbol:snd_pcm_format_unsigned symbol:snd_pcm_format_physical_width symbol:snd_pcm_limit_hw_rates symbol:snd_pcm_format_set_silence symbol:snd_pcm_format_size symbol:snd_pcm_format_big_endian symbol:snd_pcm_rate_to_rate_bit symbol:snd_pcm_format_silence_64 symbol:snd_pcm_rate_bit_to_rate symbol:snd_pcm_lib_preallocate_free_for_all symbol:snd_pcm_lib_preallocate_pages symbol:snd_pcm_lib_preallocate_pages_for_all symbol:_snd_pcm_lib_alloc_vmalloc_buffer symbol:snd_pcm_lib_free_pages symbol:snd_pcm_lib_malloc_pages symbol:snd_pcm_lib_get_vmalloc_page symbol:snd_pcm_lib_free_vmalloc_buffer symbol:snd_dma_alloc_pages_fallback symbol:snd_free_pages symbol:snd_dma_alloc_pages symbol:snd_malloc_pages symbol:snd_dma_free_pages
snd snd_timer

kernel/sound/core/snd-pcm-dmaengine.ko symbol:snd_dmaengine_pcm_request_channel symbol:snd_dmaengine_pcm_close symbol:snd_dmaengine_pcm_close_release_chan symbol:snd_dmaengine_pcm_set_config_from_dai_data symbol:snd_dmaengine_pcm_pointer symbol:snd_dmaengine_pcm_trigger symbol:snd_dmaengine_pcm_open_request_chan symbol:snd_hwparams_to_dma_slave_config symbol:snd_dmaengine_pcm_pointer_no_residue symbol:snd_dmaengine_pcm_get_chan symbol:snd_dmaengine_pcm_open
snd_pcm

kernel/sound/core/snd.ko char_major_116_* symbol:snd_register_device symbol:snd_request_card symbol:snd_major symbol:snd_lookup_minor_data symbol:snd_unregister_device symbol:snd_ecards_limit symbol:snd_component_add symbol:snd_cards symbol:snd_card_register symbol:snd_card_file_remove symbol:snd_card_new symbol:snd_card_add_dev_attr symbol:snd_card_free_when_closed symbol:snd_power_wait symbol:snd_card_set_id symbol:snd_card_free symbol:snd_device_initialize symbol:snd_mixer_oss_notify_callback symbol:snd_card_file_add symbol:snd_card_disconnect symbol:copy_to_user_fromio symbol:copy_from_user_toio symbol:snd_ctl_new1 symbol:snd_ctl_boolean_stereo_info symbol:snd_ctl_unregister_ioctl symbol:snd_ctl_remove_id symbol:snd_ctl_replace symbol:snd_ctl_rename_id symbol:snd_ctl_remove symbol:snd_ctl_find_id symbol:snd_ctl_activate_id symbol:snd_ctl_register_ioctl symbol:snd_ctl_get_preferred_subdevice symbol:snd_ctl_enum_info symbol:snd_ctl_add symbol:snd_ctl_free_one symbol:snd_ctl_notify symbol:snd_ctl_find_numid symbol:snd_ctl_boolean_mono_info symbol:release_and_free_resource symbol:__snd_printk symbol:snd_device_register symbol:snd_device_disconnect symbol:snd_device_new symbol:snd_device_free symbol:snd_info_get_line symbol:snd_seq_root symbol:snd_info_create_module_entry symbol:snd_info_create_card_entry symbol:snd_info_get_str symbol:snd_info_register symbol:snd_info_free_entry symbol:snd_oss_info_register symbol:snd_unregister_oss_device symbol:snd_lookup_oss_minor_data symbol:snd_register_oss_device symbol:snd_jack_report symbol:snd_jack_set_parent symbol:snd_jack_add_new_kctl symbol:snd_jack_new symbol:snd_jack_set_key
soundcore

kernel/sound/core/oss/snd-pcm-oss.ko sound_service_?_12 sound_service_?_3
snd_pcm snd snd_mixer_oss

kernel/sound/core/oss/snd-mixer-oss.ko sound_service_?_0 symbol:snd_mixer_oss_ioctl_card
snd

kernel/sound/soc/codecs/snd-soc-dmic.ko platform:dmic_codec
snd_soc_core

kernel/sound/soc/codecs/snd-soc-twl4030.ko platform:twl4030_codec
snd_pcm snd_soc_core

kernel/sound/soc/codecs/snd-soc-twl6040.ko symbol:twl6040_get_clk_id symbol:twl6040_get_trim_value symbol:twl6040_get_hs_step_size symbol:twl6040_hs_jack_detect symbol:twl6040_get_dl1_gain
snd_soc_core snd_pcm

kernel/sound/soc/codecs/snd-soc-tlv320aic3x.ko i2c:tlv320aic3104 i2c:tlv320aic3106 i2c:tlv320aic3007 i2c:tlv320aic33 i2c:tlv320aic3x of:N*T*Cti,tlv320aic3104* of:N*T*Cti,tlv320aic3106* of:N*T*Cti,tlv320aic3007* of:N*T*Cti,tlv320aic33* of:N*T*Cti,tlv320aic3x*
snd_pcm snd_soc_core

kernel/sound/soc/snd-soc-core.ko platform:soc_audio symbol:snd_soc_of_parse_daifmt symbol:snd_soc_lookup_platform symbol:snd_soc_add_codec_controls symbol:snd_soc_of_parse_audio_simple_widgets symbol:snd_soc_component_exit_regmap symbol:snd_soc_add_platform symbol:snd_soc_add_card_controls symbol:snd_soc_of_parse_audio_prefix symbol:snd_soc_codec_set_pll symbol:snd_soc_card_get_kcontrol symbol:snd_soc_poweroff symbol:snd_soc_dai_set_sysclk symbol:snd_soc_add_dai_controls symbol:snd_soc_unregister_component symbol:snd_soc_of_parse_card_name symbol:snd_soc_dai_set_channel_map symbol:snd_soc_get_dai_substream symbol:snd_soc_cnew symbol:snd_soc_get_pcm_runtime symbol:snd_soc_suspend symbol:snd_soc_runtime_set_dai_fmt symbol:snd_soc_dai_set_tristate symbol:snd_soc_dai_digital_mute symbol:snd_soc_dai_set_pll symbol:snd_soc_of_parse_audio_routing symbol:snd_soc_of_get_dai_name symbol:snd_soc_of_get_dai_link_codecs symbol:snd_soc_dai_set_bclk_ratio symbol:snd_soc_add_platform_controls symbol:snd_soc_codec_set_sysclk symbol:snd_soc_of_parse_tdm_slot symbol:snd_soc_unregister_platform symbol:snd_soc_dai_set_tdm_slot symbol:snd_soc_dai_set_fmt symbol:snd_soc_dai_set_clkdiv symbol:snd_soc_component_init_regmap symbol:snd_soc_resume symbol:snd_soc_unregister_card symbol:snd_soc_pm_ops symbol:snd_soc_register_component symbol:snd_soc_unregister_codec symbol:snd_soc_add_component_controls symbol:snd_soc_register_card symbol:snd_soc_debugfs_root symbol:snd_soc_register_platform symbol:snd_soc_register_codec symbol:snd_soc_remove_platform symbol:snd_soc_dapm_get_pin_status symbol:snd_soc_dapm_disable_pin_unlocked symbol:snd_soc_dapm_disable_pin symbol:snd_soc_dapm_free symbol:snd_soc_dapm_force_bias_level symbol:dapm_mark_endpoints_dirty symbol:snd_soc_dapm_put_pin_switch symbol:snd_soc_dapm_weak_routes symbol:snd_soc_dapm_new_widgets symbol:dapm_regulator_event symbol:snd_soc_dapm_nc_pin symbol:snd_soc_dapm_add_routes symbol:snd_soc_dapm_enable_pin symbol:snd_soc_dapm_put_enum_double symbol:snd_soc_dapm_sync symbol:snd_soc_dapm_get_enum_double symbol:snd_soc_dapm_mixer_update_power symbol:snd_soc_dapm_nc_pin_unlocked symbol:snd_soc_dapm_kcontrol_widget symbol:snd_soc_dapm_put_volsw symbol:snd_soc_dapm_enable_pin_unlocked symbol:snd_soc_dapm_sync_unlocked symbol:snd_soc_dapm_new_controls symbol:snd_soc_dapm_kcontrol_dapm symbol:snd_soc_dapm_get_pin_switch symbol:snd_soc_dapm_mux_update_power symbol:snd_soc_dapm_get_volsw symbol:dapm_kcontrol_get_value symbol:dapm_clock_event symbol:snd_soc_dapm_force_enable_pin_unlocked symbol:snd_soc_dapm_del_routes symbol:snd_soc_dapm_ignore_suspend symbol:snd_soc_dapm_info_pin_switch symbol:snd_soc_dapm_force_enable_pin symbol:snd_soc_jack_get_type symbol:snd_soc_jack_add_gpiods symbol:snd_soc_jack_notifier_register symbol:snd_soc_jack_add_gpios symbol:snd_soc_card_jack_new symbol:snd_soc_jack_add_pins symbol:snd_soc_jack_notifier_unregister symbol:snd_soc_jack_add_zones symbol:snd_soc_jack_report symbol:snd_soc_jack_free_gpios symbol:snd_soc_params_to_frame_size symbol:snd_soc_calc_frame_size symbol:snd_soc_params_to_bclk symbol:snd_soc_calc_bclk symbol:snd_soc_dpcm_be_set_state symbol:snd_soc_dpcm_get_substream symbol:snd_soc_set_runtime_hwparams symbol:snd_soc_platform_trigger symbol:snd_soc_dpcm_can_be_params symbol:dpcm_be_dai_trigger symbol:snd_soc_dpcm_be_can_update symbol:snd_soc_dpcm_fe_can_update symbol:snd_soc_dpcm_be_get_state symbol:snd_soc_dpcm_can_be_free_stop symbol:snd_soc_component_update_bits symbol:snd_soc_platform_read symbol:snd_soc_component_update_bits_async symbol:snd_soc_update_bits symbol:snd_soc_component_write symbol:snd_soc_platform_write symbol:snd_soc_test_bits symbol:snd_soc_component_test_bits symbol:snd_soc_write symbol:snd_soc_component_async_complete symbol:snd_soc_read symbol:snd_soc_component_read symbol:devm_snd_soc_register_card symbol:devm_snd_soc_register_component symbol:devm_snd_soc_register_platform symbol:devm_snd_dmaengine_pcm_register symbol:snd_soc_info_volsw symbol:snd_soc_get_volsw_sx symbol:snd_soc_put_volsw_range symbol:snd_soc_get_volsw_range symbol:snd_soc_info_enum_double symbol:snd_soc_get_strobe symbol:snd_soc_put_strobe symbol:snd_soc_bytes_put symbol:snd_soc_bytes_get symbol:snd_soc_bytes_tlv_callback symbol:snd_soc_put_xr_sx symbol:snd_soc_put_volsw symbol:snd_soc_limit_volume symbol:snd_soc_bytes_info_ext symbol:snd_soc_put_enum_double symbol:snd_soc_get_xr_sx symbol:snd_soc_get_enum_double symbol:snd_soc_info_volsw_sx symbol:snd_soc_get_volsw symbol:snd_soc_info_volsw_range symbol:snd_soc_bytes_info symbol:snd_soc_info_xr_sx symbol:snd_soc_put_volsw_sx symbol:snd_dmaengine_pcm_unregister symbol:snd_dmaengine_pcm_register symbol:snd_dmaengine_pcm_prepare_slave_config
snd_pcm snd_pcm_dmaengine snd

kernel/sound/soc/omap/snd-soc-omap-mcpdm.ko platform:omap_mcpdm of:N*T*Cti,omap4_mcpdm* symbol:omap_mcpdm_configure_dn_offsets
snd_soc_core snd_soc_omap

kernel/sound/soc/omap/snd-soc-omap-twl4030.ko platform:omap_twl4030 of:N*T*Cti,omap_twl4030*
snd_soc_core

kernel/sound/soc/omap/snd-soc-omap-mcbsp.ko platform:omap_mcbsp of:N*T*Cti,omap4_mcbsp* of:N*T*Cti,omap3_mcbsp* of:N*T*Cti,omap2430_mcbsp* of:N*T*Cti,omap2420_mcbsp* symbol:omap_mcbsp_st_add_controls
snd_pcm snd_soc_core snd_soc_omap

kernel/sound/soc/omap/snd-soc-omap.ko symbol:omap_pcm_platform_register
snd_pcm_dmaengine snd_soc_core snd_pcm

kernel/sound/soc/omap/snd-soc-omap3pandora.ko
snd_soc_core

kernel/sound/soc/omap/snd-soc-omap-abe-twl6040.ko platform:omap_abe_twl6040 of:N*T*Cti,abe_twl6040*
snd_soc_core snd_soc_twl6040 snd_soc_omap_mcpdm

kernel/sound/soc/omap/snd-soc-omap-dmic.ko platform:omap_dmic of:N*T*Cti,omap4_dmic*
snd_soc_core snd_soc_omap

kernel/sound/soc/generic/snd-soc-simple-card.ko platform:asoc_simple_card of:N*T*Csimple_audio_card*
snd_soc_core

kernel/sound/soc/davinci/snd-soc-edma.ko symbol:edma_pcm_platform_register
snd_soc_core

kernel/sound/soc/davinci/snd-soc-evm.ko of:N*T*Cti,da830_evm_audio*
snd_soc_core

kernel/sound/soc/davinci/snd-soc-davinci-mcasp.ko of:N*T*Cti,dra7_mcasp_audio* of:N*T*Cti,am33xx_mcasp_audio* of:N*T*Cti,da830_mcasp_audio* of:N*T*Cti,dm646x_mcasp_audio*
snd_pcm snd_soc_edma snd_soc_core snd_soc_omap

kernel/sound/soundcore.ko char_major_14_* symbol:unregister_sound_special symbol:unregister_sound_dsp symbol:sound_class symbol:unregister_sound_midi symbol:register_sound_mixer symbol:register_sound_dsp symbol:register_sound_special_device symbol:register_sound_midi symbol:register_sound_special symbol:unregister_sound_mixer

