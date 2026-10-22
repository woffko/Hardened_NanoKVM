#include "system_ctrl.h"

using namespace maix;
using namespace maix::sys;

extern kvm_sys_state_t kvm_sys_state;
extern kvm_oled_state_t kvm_oled_state;

static int write_text_file(const char *path, const char *value)
{
	FILE *fp = fopen(path, "w");
	if(fp == NULL) return 0;
	if(value != NULL) fputs(value, fp);
	return fclose(fp) == 0;
}

void gen_hostapd_conf(char* ap_ssid)
{
	char file_data[512] = {0};
	snprintf(file_data, sizeof(file_data), "ctrl_interface=/var/run/hostapd\nctrl_interface_group=0\nssid=NanoKVM\nhw_mode=g\nchannel=1\nbeacon_int=100\ndtim_period=2\nmax_num_sta=255\nrts_threshold=-1\nfragm_threshold=-1\nmacaddr_acl=0\nauth_algs=3\nwpa=2\nwpa_passphrase=%s\nieee80211n=1\n", ap_ssid ? ap_ssid : "");
	write_text_file("/etc/hostapd.conf", file_data);
}

void gen_udhcpd_conf()
{
	char file_data[300] = {0};
	snprintf(file_data, sizeof(file_data), "start 10.10.10.100\nend 10.10.10.200\ninterface wlan0\npidfile /var/run/udhcpd.wlan0.pid\nlease_file /var/lib/misc/udhcpd.wlan0.leases\noption subnet 255.255.255.0\noption lease 864000\n");
	write_text_file("/etc/udhcpd.wlan0.conf", file_data);
}

void gen_dnsmasq_conf()
{
	char file_data[300] = {0};
	snprintf(file_data, sizeof(file_data), "bind-interfaces\ninterface=wlan0\ndhcp-range=10.10.10.2,10.10.10.254\naddress=/#/10.0.0.1\n");
	write_text_file("/etc/udhcpd.wlan0.conf", file_data);
}

uint8_t sta_connect_ap(void)
{
	uint8_t RW_Data[10] = {0};
	FILE *fp;
	fp = popen("hostapd_cli all sta | grep aid", "r");
	if(fp == NULL) return 0;
	if(fgets((char*)RW_Data, sizeof(RW_Data), fp) == NULL){
		pclose(fp);
		return 0;
	}
	pclose(fp);
	if(RW_Data[0] == 'a') return 1;
	else return 0;
}

uint8_t ssid_pass_ok(void)
{
	if(access("/kvmapp/kvm/wifi_try_connect", F_OK) == 0) return 1;
	else return 0;
}

uint8_t wifi_connected(void)
{
	uint8_t RW_Data[32] = {0};
	FILE *fp;
	fp = popen("wpa_cli -i wlan0 status | grep \"wpa_state\"", "r");
	if(fp == NULL) return 0;
	if(fgets((char*)RW_Data, sizeof(RW_Data), fp) == NULL){
		pclose(fp);
		return 0;
	}
	pclose(fp);
	return strstr((char*)RW_Data, "COMPLETED") != NULL;
}

void kvm_start_wifi_config_process(void)
{
	if(kvm_sys_state.wifi_config_process == -1){
		// printf("[kvmw]开始配置wifi\n");
		kvm_sys_state.wifi_config_process = 0;
		kvm_sys_state.sub_page = 0;
	}
}

void kvm_wifi_web_config_process()
{
	if(ssid_pass_ok()){
		unlink("/kvmapp/kvm/wifi_try_connect");
		system("/etc/init.d/S30wifi restart");
		kvm_sys_state.wifi_config_process = 3;
		// 尝试连接wifi
		if(kvm_sys_state.wifi_config_process == 3){
			// time::sleep_ms(WIFI_CONNECTION_DELAY);
			if(wifi_connected()){
				// 连上了
				kvm_sys_state.wifi_config_process = -1;
			} else {
				// 没连上
				kvm_sys_state.wifi_config_process = 0;
			}
		}
	}
}

void kvm_wifi_config_process()
{	
	switch(kvm_sys_state.wifi_config_process){
		case -1:
			// printf("[kvms]Not in the process of configuring WiFi\n");
			break;
		case 0: // 启动wifi
			// Every AP session gets a fresh CSPRNG key, stored 0600. Without
			// one the AP is not started; there is no weaker fallback.
			if(ap_key_generate(kvm_sys_state.wifi_ap_pass) != 0){
				printf("[kvms]WiFi AP not started: no random key\n");
				kvm_sys_state.wifi_config_process = -1;
				kvm_sys_state.sub_page = 6;
				break;
			}
			write_text_file("/kvmapp/kvm/ap.ssid", "NanoKVM\n");
			if(ap_key_store("/kvmapp/kvm/ap.pass", kvm_sys_state.wifi_ap_pass) != 0){
				printf("[kvms]WiFi AP not started: key not stored\n");
				memset(kvm_sys_state.wifi_ap_pass, 0, sizeof(kvm_sys_state.wifi_ap_pass));
				kvm_sys_state.wifi_config_process = -1;
				kvm_sys_state.sub_page = 6;
				break;
			}
			system("/etc/init.d/S30wifi ap");

			kvm_sys_state.wifi_config_process = 1;
			kvm_sys_state.sub_page = 1;
			break;
		case 1: // 等待设备连接
			if(sta_connect_ap()){
				kvm_sys_state.wifi_config_process = 2;
				kvm_sys_state.sub_page = 3;
			}
			break;
		case 2: // 等待输入帐号密码
			if(ssid_pass_ok()){
				unlink("/kvmapp/kvm/wifi_try_connect");
				system("/etc/init.d/S30wifi restart");
				kvm_sys_state.wifi_config_process = 3;
				kvm_sys_state.sub_page = 5;
			}
			break;
		case 3: // 尝试连接wifi
			time::sleep_ms(WIFI_CONNECTION_DELAY);
			if(wifi_connected()){
				// 连上了
				kvm_sys_state.wifi_config_process = -1;
				kvm_sys_state.page = 0;
				kvm_sys_state.sub_page = 0;
			} else {
				// 没连上
				kvm_sys_state.wifi_config_process = 0;
				kvm_sys_state.sub_page = 0;
			}
			break;
	}
}
