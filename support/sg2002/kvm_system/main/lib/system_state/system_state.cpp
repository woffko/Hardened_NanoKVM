#include "config.h"
#include "system_state.h"
#include "vi_state_shared.hpp"
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <time.h>
#include <string>

using namespace maix;
using namespace maix::sys;

extern kvm_sys_state_t kvm_sys_state;
extern kvm_oled_state_t kvm_oled_state;

#define RUST_HWMON_FLAG_PATH "/etc/kvm/rust_hwmon_enabled"
#define RUST_HWMON_STATE_PATH "/tmp/nanokvm-hwmon-state.json"
#define RUST_HWMON_MAX_AGE_SEC 20
#define RUST_HWMON_MAX_BYTES 8192

static int rust_hwmon_mode_reported = -1;

static void rust_hwmon_report_mode(int active)
{
	if(rust_hwmon_mode_reported == active) return;
	printf("[kvms]Rust hwmon passive state %s\r\n", active ? "active" : "fallback");
	fflush(stdout);
	rust_hwmon_mode_reported = active;
}

static int rust_hwmon_state_is_fresh(void)
{
	struct stat st;
	time_t now;

	if(stat(RUST_HWMON_STATE_PATH, &st) != 0) return 0;
	now = ::time(NULL);
	if(now == (time_t)-1) return 1;
	if(st.st_mtime > now) return 1;
	return (now - st.st_mtime) <= RUST_HWMON_MAX_AGE_SEC;
}

static int read_text_file(const char *path, char *buf, size_t buf_len)
{
	FILE *fp;
	size_t size;

	if(buf_len == 0) return 0;
	fp = fopen(path, "r");
	if(fp == NULL) return 0;
	size = fread(buf, 1, buf_len - 1, fp);
	if(ferror(fp)){
		fclose(fp);
		return 0;
	}
	fclose(fp);
	buf[size] = 0;
	return size > 0;
}

static int load_rust_hwmon_snapshot(char *buf, size_t buf_len)
{
	if(access(RUST_HWMON_FLAG_PATH, F_OK) != 0){
		rust_hwmon_mode_reported = -1;
		return 0;
	}
	if(!rust_hwmon_state_is_fresh()){
		rust_hwmon_report_mode(0);
		return 0;
	}
	if(!read_text_file(RUST_HWMON_STATE_PATH, buf, buf_len)){
		rust_hwmon_report_mode(0);
		return 0;
	}
	if(strstr(buf, "\"schema\": \"nanokvm-hwmon/v1\"") == NULL){
		rust_hwmon_report_mode(0);
		return 0;
	}
	return 1;
}

static const char *json_skip_ws(const char *p, const char *end)
{
	while(p < end && *p && isspace((unsigned char)*p)) p++;
	return p;
}

static const char *json_find_section_range(const char *range_start, const char *range_end, const char *section, const char **section_end)
{
	char pattern[64];
	const char *pos;
	const char *colon;
	const char *start;
	int depth = 0;

	snprintf(pattern, sizeof(pattern), "\"%s\"", section);
	pos = strstr(range_start, pattern);
	if(pos == NULL) return NULL;
	if(pos >= range_end) return NULL;
	colon = strchr(pos, ':');
	if(colon == NULL || colon >= range_end) return NULL;
	start = strchr(colon, '{');
	if(start == NULL || start >= range_end) return NULL;

	for(const char *p = start; *p && p < range_end; p++){
		if(*p == '{') depth++;
		else if(*p == '}'){
			depth--;
			if(depth == 0){
				*section_end = p;
				return start;
			}
		}
	}
	return NULL;
}

static const char *json_find_section(const char *json, const char *section, const char **section_end)
{
	return json_find_section_range(json, json + strlen(json), section, section_end);
}

static const char *json_find_key(const char *start, const char *end, const char *key)
{
	char pattern[64];
	const char *pos = start;

	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	while((pos = strstr(pos, pattern)) != NULL){
		if(pos >= end) return NULL;
		return pos;
	}
	return NULL;
}

static int json_bool_in_range(const char *start, const char *end, const char *key, int *out)
{
	const char *key_pos;
	const char *value;

	key_pos = json_find_key(start, end, key);
	if(key_pos == NULL) return 0;
	value = strchr(key_pos, ':');
	if(value == NULL || value >= end) return 0;
	value = json_skip_ws(value + 1, end);
	if(strncmp(value, "true", 4) == 0){
		*out = 1;
		return 1;
	}
	if(strncmp(value, "false", 5) == 0){
		*out = 0;
		return 1;
	}
	return 0;
}

static int json_bool_in_section(const char *json, const char *section, const char *key, int *out)
{
	const char *section_end;
	const char *section_start = json_find_section(json, section, &section_end);
	if(section_start == NULL) return 0;
	return json_bool_in_range(section_start, section_end, key, out);
}

static int json_i32_in_range(const char *start, const char *end, const char *key, long *out)
{
	const char *key_pos;
	const char *value;
	char *end_ptr;
	long parsed;

	key_pos = json_find_key(start, end, key);
	if(key_pos == NULL) return 0;
	value = strchr(key_pos, ':');
	if(value == NULL || value >= end) return 0;
	value = json_skip_ws(value + 1, end);
	if(strncmp(value, "null", 4) == 0) return 0;
	parsed = strtol(value, &end_ptr, 10);
	if(end_ptr == value) return 0;
	*out = parsed;
	return 1;
}

static int json_u32_in_range(const char *start, const char *end, const char *key, unsigned long *out)
{
	const char *key_pos;
	const char *value;
	char *end_ptr;
	unsigned long parsed;

	key_pos = json_find_key(start, end, key);
	if(key_pos == NULL) return 0;
	value = strchr(key_pos, ':');
	if(value == NULL || value >= end) return 0;
	value = json_skip_ws(value + 1, end);
	if(strncmp(value, "null", 4) == 0) return 0;
	parsed = strtoul(value, &end_ptr, 10);
	if(end_ptr == value) return 0;
	*out = parsed;
	return 1;
}

static int json_u32_in_section(const char *json, const char *section, const char *key, unsigned long *out)
{
	const char *section_end;
	const char *section_start = json_find_section(json, section, &section_end);
	if(section_start == NULL) return 0;
	return json_u32_in_range(section_start, section_end, key, out);
}

static int json_string_in_range(const char *start, const char *end, const char *key, char *out, size_t out_len)
{
	const char *key_pos;
	const char *value;
	size_t i = 0;

	if(out_len == 0) return 0;
	out[0] = 0;
	key_pos = json_find_key(start, end, key);
	if(key_pos == NULL) return 0;
	value = strchr(key_pos, ':');
	if(value == NULL || value >= end) return 0;
	value = json_skip_ws(value + 1, end);
	if(strncmp(value, "null", 4) == 0) return 0;
	if(value >= end || *value != '"') return 0;
	value++;
	while(value < end && *value && *value != '"'){
		if(*value == '\\' && *(value + 1)) value++;
		if(i + 1 < out_len) out[i++] = *value;
		value++;
	}
	out[i] = 0;
	return 1;
}

static int json_string_in_section(const char *json, const char *section, const char *key, char *out, size_t out_len)
{
	const char *section_end;
	const char *section_start = json_find_section(json, section, &section_end);
	if(section_start == NULL) return 0;
	return json_string_in_range(section_start, section_end, key, out, out_len);
}

static int8_t clamp_i8(unsigned long value)
{
	if(value > 127) return 127;
	return (int8_t)value;
}

static int16_t clamp_i16(unsigned long value)
{
	if(value > 32767) return 32767;
	return (int16_t)value;
}

static int stream_quality_bucket(unsigned long raw, int8_t stream_type)
{
	if(stream_type == KVM_TYPE_MJPG){
		if(raw < 60) return 1;
		if(raw < 75) return 2;
		if(raw < 90) return 3;
		return 4;
	}
	if(raw < 1500) return 1;
	if(raw < 2500) return 2;
	if(raw < 3500) return 3;
	return 4;
}

static void copy_state_string(uint8_t *dst, size_t dst_len, const char *src)
{
	if(dst_len == 0) return;
	memset(dst, 0, dst_len);
	if(src == NULL) return;
	strncpy((char*)dst, src, dst_len - 1);
}

static void trim_state_line(uint8_t *value, size_t value_len)
{
	for(size_t i = 0; i < value_len; i++){
		if(value[i] == '\r' || value[i] == '\n'){
			value[i] = 0;
			return;
		}
		if(value[i] == 0) return;
	}
	if(value_len > 0) value[value_len - 1] = 0;
}

static int state_string_is_ipv4(const uint8_t *value)
{
	size_t len = 0;
	for(; len < 16 && value[len] != 0; len++){
		if(!(isdigit(value[len]) || value[len] == '.')) return 0;
	}
	return len > 0 && len < 16;
}

static int copy_interface_ip(const char *interface_name, uint8_t *dst, size_t dst_len)
{
	std::string addr = ip_address()[interface_name];
	if(addr.empty()){
		printf("can`t get ip addr\r\n");
		copy_state_string(dst, dst_len, NULL);
		return 0;
	}
	if(strcmp(addr.c_str(), (char*)dst) != 0){
		copy_state_string(dst, dst_len, addr.c_str());
		printf("%s\r\n", (char*)dst);
	}
	return 1;
}

static int read_route_gateway(const char *cmd, uint8_t *dst, size_t dst_len)
{
	char value[32] = {0};
	FILE *fp;

	copy_state_string(dst, dst_len, NULL);
	fp = popen(cmd, "r");
	if(fp == NULL) return 0;
	if(fgets(value, sizeof(value), fp) == NULL){
		pclose(fp);
		return 0;
	}
	pclose(fp);
	trim_state_line((uint8_t*)value, sizeof(value));
	copy_state_string(dst, dst_len, value);
	return dst[0] != 0;
}

static int json_find_network_interface(const char *json, const char *name, const char **iface_start, const char **iface_end)
{
	const char *network_start;
	const char *network_end;
	const char *interfaces_start;
	const char *interfaces_end;

	network_start = json_find_section(json, "network", &network_end);
	if(network_start == NULL) return 0;
	interfaces_start = json_find_section_range(network_start, network_end, "interfaces", &interfaces_end);
	if(interfaces_start == NULL) return 0;
	*iface_start = json_find_section_range(interfaces_start, interfaces_end, name, iface_end);
	return *iface_start != NULL;
}

static int kvm_apply_rust_hwmon_eth_state(void)
{
	char json[RUST_HWMON_MAX_BYTES];
	char value[64];
	const char *eth_start;
	const char *eth_end;
	long state;

	if(!load_rust_hwmon_snapshot(json, sizeof(json))) return 0;
	if(!json_find_network_interface(json, "eth0", &eth_start, &eth_end)) return 0;
	if(!json_i32_in_range(eth_start, eth_end, "route_state", &state)) return 0;
	if(state < 0) state = 0;
	if(state > 3) state = 3;
	kvm_sys_state.eth_state = (int8_t)state;

	if(json_string_in_range(eth_start, eth_end, "primary_ipv4", value, sizeof(value))){
		copy_state_string(kvm_sys_state.eth_addr, sizeof(kvm_sys_state.eth_addr), value);
	} else {
		copy_state_string(kvm_sys_state.eth_addr, sizeof(kvm_sys_state.eth_addr), NULL);
	}
	if(json_string_in_range(eth_start, eth_end, "default_ipv4_gateway", value, sizeof(value))){
		copy_state_string(kvm_sys_state.eth_route, sizeof(kvm_sys_state.eth_route), value);
	} else {
		copy_state_string(kvm_sys_state.eth_route, sizeof(kvm_sys_state.eth_route), NULL);
	}
	return 1;
}

int get_nic_state(const char* interface_name)
{
	int sock;
	struct ifreq ifr;
	int ret = NIC_STATE_NO_EXIST;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return ret;
	}
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface_name);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		close(sock);
		return ret;
	}
	if (ifr.ifr_flags & IFF_UP) {
		if (ifr.ifr_flags & IFF_RUNNING) {
			ret = NIC_STATE_RUNNING;
		} else {
			ret = NIC_STATE_UP;
		}
	} else {
		ret = NIC_STATE_DOWN;
	}
	close(sock);
	return ret;
}

int get_ping_allow_state(void)
{
	if(access("/etc/kvm/stop_ping", F_OK) == 0) {
		kvm_sys_state.ping_allow = 0;
	} else {
		kvm_sys_state.ping_allow = 1;
	}
	return kvm_sys_state.ping_allow;
}

// net_port
int get_ip_addr(ip_addr_t ip_type)
{
	switch (ip_type){
		case NULL_IP:
			return 0;
		case ETH_IP: // eth_addr
			return copy_interface_ip("eth0", kvm_sys_state.eth_addr, sizeof(kvm_sys_state.eth_addr));
		case WiFi_IP: // wifi_addr
			return copy_interface_ip("wlan0", kvm_sys_state.wifi_addr, sizeof(kvm_sys_state.wifi_addr));
		case Tailscale_IP: // tail_addr
			return copy_interface_ip("tailscale0", kvm_sys_state.tail_addr, sizeof(kvm_sys_state.tail_addr));
		case RNDIS_IP: // rndis_addr
			return copy_interface_ip("usb0", kvm_sys_state.rndis_addr, sizeof(kvm_sys_state.rndis_addr));
		case ETH_ROUTE: // eth_route
			if(access("/etc/kvm/gateway", F_OK) != 0){
				return read_route_gateway("ip route | grep -i '^default' | grep -i 'eth0' | awk '{print $3}'", kvm_sys_state.eth_route, sizeof(kvm_sys_state.eth_route));
			} else {
				if(!read_text_file("/etc/kvm/gateway", (char*)kvm_sys_state.eth_route, sizeof(kvm_sys_state.eth_route))){
					copy_state_string(kvm_sys_state.eth_route, sizeof(kvm_sys_state.eth_route), NULL);
					return 0;
				}
				trim_state_line(kvm_sys_state.eth_route, sizeof(kvm_sys_state.eth_route));
				return kvm_sys_state.eth_route[0] != 0;
			}
		case WiFi_ROUTE: // wifi_route
			return read_route_gateway("ip route | grep -i '^default' | grep -i 'wlan0' | awk '{print $3}'", kvm_sys_state.wifi_route, sizeof(kvm_sys_state.wifi_route));
	}
	return 0;
}

int chack_net_state(ip_addr_t use_ip_type)
{
	char Cmd[100]={0};
	if(use_ip_type == ETH_ROUTE){
		if(!state_string_is_ipv4(kvm_sys_state.eth_route)) return 0;
		snprintf(Cmd, sizeof(Cmd), "ping -I eth0 -w 1 %s > /dev/null", kvm_sys_state.eth_route);
	}
	else if(use_ip_type == WiFi_ROUTE){
		if(!state_string_is_ipv4(kvm_sys_state.wifi_route)) return 0;
		snprintf(Cmd, sizeof(Cmd), "ping -I wlan0 -w 1 %s > /dev/null", kvm_sys_state.wifi_route);
	}
	else return -1;	// 不支持的端口
	if(system(Cmd) == 0){	// 256：不通； = 0：通
		return 1;
	}
	return 0;
}

void patch_eth_wifi(void)
{
	// system("ip link set eth0 down");
	// system("ip link set eth0 up");
	// system("udhcpc -i eth0 &");
}

int kvm_wifi_exist()
{
	if (get_nic_state("wlan0") == NIC_STATE_NO_EXIST) return 0;
	else return 1;
}

void kvm_update_usb_state()
{
	// usb_state, hid_state, rndis_state, udisk_state
	char RW_Data[10] = {0};
	if(!read_text_file("/sys/class/udc/4340000.usb/state", RW_Data, sizeof(RW_Data))){
		kvm_sys_state.usb_state = -1;
		kvm_sys_state.hid_state = 0;
		kvm_sys_state.udisk_state = 0;
		return;
	}
	if(RW_Data[0] == 'n') kvm_sys_state.usb_state = 0;
	else if(RW_Data[0] == 'c') kvm_sys_state.usb_state = 1;
	else kvm_sys_state.usb_state = -1;
	// hid_state & udisk_state (rndis_state单独处理)
	if(kvm_sys_state.usb_state == 1){
		kvm_sys_state.hid_state =
			(access("/sys/kernel/config/usb_gadget/g0/configs/c.1/hid.GS0", F_OK) == 0 ||
			 access("/sys/kernel/config/usb_gadget/g0/configs/c.1/hid.GS1", F_OK) == 0 ||
			 access("/sys/kernel/config/usb_gadget/g0/configs/c.1/hid.GS2", F_OK) == 0) ? 1 : 0;
		kvm_sys_state.udisk_state =
			access("/sys/kernel/config/usb_gadget/g0/configs/c.1/mass_storage.disk0", F_OK) == 0 ? 1 : 0;
	} else {
		kvm_sys_state.hid_state = 0;
		kvm_sys_state.udisk_state = 0;
	}
}

int kvm_update_passive_state_from_rust_hwmon(void)
{
	char json[RUST_HWMON_MAX_BYTES];
	char value[64];
	int bool_value;
	unsigned long number;
	int applied = 0;

	if(!load_rust_hwmon_snapshot(json, sizeof(json))) return 0;

	if(json_string_in_section(json, "usb", "udc_state", value, sizeof(value))){
		if(value[0] == 'n') kvm_sys_state.usb_state = 0;
		else if(value[0] == 'c') kvm_sys_state.usb_state = 1;
		else kvm_sys_state.usb_state = -1;
		applied = 1;
	}
	if(json_bool_in_section(json, "usb", "hid_enabled", &bool_value)){
		kvm_sys_state.hid_state = bool_value ? 1 : 0;
		applied = 1;
	}
	if(json_bool_in_section(json, "usb", "mass_storage_enabled", &bool_value)){
		kvm_sys_state.udisk_state = bool_value ? 1 : 0;
		applied = 1;
	}
	if(json_bool_in_section(json, "usb", "rndis_enabled", &bool_value)){
		kvm_sys_state.rndis_state = bool_value ? 1 : 0;
		applied = 1;
	}
	if(json_bool_in_section(json, "hdmi", "active", &bool_value)){
		kvm_sys_state.hdmi_state = bool_value ? 1 : 0;
		applied = 1;
	}
	if(json_string_in_section(json, "stream", "type", value, sizeof(value))){
		if(value[0] == 'm') kvm_sys_state.type = KVM_TYPE_MJPG;
		else if(value[0] == 'h') kvm_sys_state.type = KVM_TYPE_H264;
		else kvm_sys_state.type = KVM_TYPE_none;
		applied = 1;
	}
	if(json_u32_in_section(json, "stream", "now_fps", &number)){
		kvm_sys_state.now_fps = clamp_i8(number);
		applied = 1;
	}
	if(json_u32_in_section(json, "stream", "width", &number) ||
		json_u32_in_section(json, "hdmi", "width", &number)){
		kvm_sys_state.hdmi_width = clamp_i16(number);
		applied = 1;
	}
	if(json_u32_in_section(json, "stream", "height", &number) ||
		json_u32_in_section(json, "hdmi", "height", &number)){
		kvm_sys_state.hdmi_height = clamp_i16(number);
		applied = 1;
	}
	if(json_u32_in_section(json, "stream", "qlty", &number)){
		kvm_sys_state.qlty = stream_quality_bucket(number, kvm_sys_state.type);
		applied = 1;
	}

	if(applied) rust_hwmon_report_mode(1);
	else rust_hwmon_report_mode(0);
	return applied;
}

void kvm_update_hdmi_state()
{
	const uint32_t shared_state_ttl_ms = 30000U;
	const uint32_t fallback_state_ttl_ms = 10000U;
	static uint8_t check_times = 4;
	static vi_state_shared::State fallback_state = {};
	static uint32_t fallback_updated_ms = 0;
	static uint32_t fallback_attempted_ms = 0;
	static bool fallback_valid = false;
	static bool fallback_attempted = false;
	static bool shared_failure_logged = false;
	static bool fallback_failure_logged = false;
	if(++check_times > 5){
		check_times = 0;
		vi_state_shared::State state = {};
		vi_state_shared::ReadStatus status = vi_state_shared::read_state(&state, shared_state_ttl_ms);
		if (status == vi_state_shared::READ_OK) {
			kvm_sys_state.hdmi_state = state.fps == 0 ? 0 : 1;
			if (shared_failure_logged) {
				fprintf(stderr, "[kvm_system] VI shared state recovered\n");
			}
			shared_failure_logged = false;
			fallback_failure_logged = false;
			return;
		}

		if (!shared_failure_logged) {
			fprintf(stderr, "[kvm_system] VI shared state %s; using direct fallback\n",
				vi_state_shared::read_status_name(status));
			shared_failure_logged = true;
		}

		uint32_t now = vi_state_shared::monotonic_ms();
		if (!fallback_attempted || now - fallback_attempted_ms >= fallback_state_ttl_ms) {
			fallback_attempted_ms = now;
			fallback_attempted = true;
			uint32_t fields = vi_state_shared::FIELD_NONE;
			vi_state_shared::State direct_state = {};
			vi_state_shared::ProcReadStatus direct_status =
				vi_state_shared::read_proc_state(&direct_state, &fields);
			if (direct_status == vi_state_shared::PROC_READ_OK &&
				(fields & vi_state_shared::FIELD_FPS) != 0U) {
				fallback_state = direct_state;
				fallback_updated_ms = now;
				fallback_valid = true;
				if (fallback_failure_logged) {
					fprintf(stderr, "[kvm_system] direct VI fallback recovered\n");
				}
				fallback_failure_logged = false;
			} else {
				fallback_valid = false;
				if (!fallback_failure_logged) {
					fprintf(stderr, "[kvm_system] direct VI fallback unavailable\n");
					fallback_failure_logged = true;
				}
			}
		}

		if (fallback_valid && now - fallback_updated_ms <= fallback_state_ttl_ms) {
			kvm_sys_state.hdmi_state = fallback_state.fps == 0 ? 0 : 1;
		} else {
			kvm_sys_state.hdmi_state = -1;
		}
	}
}

void kvm_update_stream_fps(void)
{
	char RW_Data[10] = {0};

	// FPS
	if(read_text_file("/kvmapp/kvm/now_fps", RW_Data, sizeof(RW_Data))){
		kvm_sys_state.now_fps = atoi(RW_Data);
	}
}

void kvm_update_stream_type(void)
{
	char RW_Data[10] = {0};

	// type
	if(!read_text_file("/kvmapp/kvm/type", RW_Data, sizeof(RW_Data))) return;
	if(RW_Data[0] == 'm') 		kvm_sys_state.type = KVM_TYPE_MJPG;
	else if(RW_Data[0] == 'h') 	kvm_sys_state.type = KVM_TYPE_H264;
	else 						kvm_sys_state.type = KVM_TYPE_none;
}

void kvm_update_stream_qlty(void)
{
	char RW_Data[10] = {0};
	uint16_t tmp16;

	// QLTY
	if(!read_text_file("/kvmapp/kvm/qlty", RW_Data, sizeof(RW_Data))) return;
	tmp16 = atoi(RW_Data);
	if(kvm_sys_state.type == KVM_TYPE_MJPG){
		if(tmp16 < 60) 						 	kvm_sys_state.qlty = 1;
		else if(tmp16 >= 60 && tmp16 < 75) 	 	kvm_sys_state.qlty = 2;
		else if(tmp16 >= 75 && tmp16 < 90) 	 	kvm_sys_state.qlty = 3;
		else if(tmp16 >= 90 && tmp16 <= 100) 	kvm_sys_state.qlty = 4;
		else 									kvm_sys_state.qlty = 4;
	} else {
		if(tmp16 < 1500) 						kvm_sys_state.qlty = 1;
		else if(tmp16 >= 1500 && tmp16 < 2500) 	kvm_sys_state.qlty = 2;
		else if(tmp16 >= 2500 && tmp16 < 3500) 	kvm_sys_state.qlty = 3;
		else if(tmp16 >= 3500 && tmp16 <= 5000) kvm_sys_state.qlty = 4;
		else 									kvm_sys_state.qlty = 4;
	}
}

void kvm_update_hdmi_res(void)
{
	char RW_Data[10] = {0};
	// HDMI width
	if(read_text_file("/kvmapp/kvm/width", RW_Data, sizeof(RW_Data))){
		kvm_sys_state.hdmi_width = atoi(RW_Data);
	}
	// HDMI height
	if(read_text_file("/kvmapp/kvm/height", RW_Data, sizeof(RW_Data))){
		kvm_sys_state.hdmi_height = atoi(RW_Data);
	}
}

void kvm_update_eth_state(void)
{	
	static uint8_t nic_state = 0;

	if(kvm_apply_rust_hwmon_eth_state()) return;

	nic_state = get_nic_state("eth0");

	if(nic_state == NIC_STATE_RUNNING){
		// Get IP
		if(strcmp(ip_address()["eth0"].c_str(), (char*)kvm_sys_state.eth_addr) != 0){
			if(get_ip_addr(ETH_IP)){
				kvm_sys_state.eth_state = 2;
			} else {
				kvm_sys_state.eth_state = 1;
				return;
			}
		}
		if(kvm_sys_state.ping_allow){
			// ping route
			if(kvm_sys_state.eth_route[0] == 0){
				get_ip_addr(ETH_ROUTE);
			} else {
				if(chack_net_state(ETH_ROUTE)){
					// Ping successful
					kvm_sys_state.eth_state = 3;
				} else {
					kvm_sys_state.eth_state = 2;
				}
			}
		} else {
			// Consider the network to be connected
			kvm_sys_state.eth_state = 3;
		}

	} else {
		kvm_sys_state.eth_state = 0;
		patch_eth_wifi();
	}
}

static void persist_wifi_state_if_changed(int8_t state)
{
	static int8_t persisted_state = INT8_MIN;
	if (persisted_state == state) return;

	FILE *fp = fopen("/kvmapp/kvm/wifi_state", "w");
	if (!fp) return;
	bool written = fprintf(fp, "%d\n", state) > 0;
	if (fclose(fp) == 0 && written) persisted_state = state;
}

void kvm_update_wifi_state(void)
{	
	// No WiFi module (check for existence?) -> Module exists & not connected (check if connected) ->
	if(kvm_sys_state.wifi_state == -2) return;
	switch (kvm_sys_state.wifi_state){
		case -1:
		// Initial default value.
			if (kvm_wifi_exist()) {
				kvm_sys_state.wifi_state = 0;
				system("touch /etc/kvm/wifi_exist");
			}
			else {
				kvm_sys_state.wifi_state = -2; // WiFi module does not exist, exiting directly.
				system("rm /etc/kvm/wifi_exist");
				return;
			}
			// break;	// Start checking the connection directly.
		case 0:
		// WiFi is available but not connected.
			persist_wifi_state_if_changed(0);
			if (get_ip_addr(WiFi_IP) && get_ip_addr(WiFi_ROUTE)){
				// IP+Route has been acquired
				if(kvm_sys_state.ping_allow){
					if (chack_net_state(WiFi_ROUTE)){
						// Ping successful
						kvm_sys_state.wifi_state = 1;
					}
				} else {
					// Consider the network to be connected
					kvm_sys_state.wifi_state = 1;
				}
			}
			break;
		case 1:
		// Connected to the network & continuously checking if it can ping successfully.
			persist_wifi_state_if_changed(1);
			get_ip_addr(WiFi_IP);
			if(kvm_sys_state.ping_allow){
				if (kvm_sys_state.wifi_route[0] != 0){
					if (chack_net_state(WiFi_ROUTE) == 0){
						// Ping successful
						kvm_sys_state.wifi_state = 0;
					}
				}
			}
		// default:
		// 	kvm_sys_state.wifi_state = -1;
	}
}

void kvm_update_rndis_state(void)
{
	if (get_nic_state("usb0") == NIC_STATE_RUNNING) {
		if(kvm_sys_state.rndis_state != 1) {
			if (get_ip_addr(RNDIS_IP)) {
				kvm_sys_state.rndis_state = 1;
			}
		}
	}
	else kvm_sys_state.rndis_state = 0;
}

void kvm_update_tailscale_state(void)
{
	if (get_nic_state("tailscale0") == NIC_STATE_RUNNING) {
		if(kvm_sys_state.tail_state != 1){
			if (get_ip_addr(Tailscale_IP)) {
				kvm_sys_state.tail_state = 1;
			}
		}
	}
	else kvm_sys_state.tail_state = 0;
}

//============================================================================

uint8_t ion_free_space(void)
{
	//cat /sys/kernel/debug/ion/cvi_carveout_heap_dump/summary | grep "usage rate:" | awk '{print $2}'

	return 0;
}
