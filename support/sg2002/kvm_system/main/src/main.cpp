#include "config.h"
#include <errno.h>
#include <sys/stat.h>

using namespace maix;
using namespace maix::sys;
using namespace maix::peripheral;

kvm_sys_state_t kvm_sys_state;
kvm_oled_state_t kvm_oled_state;
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t shutdown_requested = 0;

static bool trusted_runtime_flag(const char* path)
{
	struct stat st;
	return lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
	       st.st_uid == 0 && (st.st_mode & 0022) == 0;
}

static void request_shutdown(int)
{
	shutdown_requested = 1;
}

void build_recovery(void)
{
	if (access("/recovery", F_OK) != 0) {
		printf("unexist /recovery\n");
		mkdir("/recovery", 0777);
	} else {
		printf("exist /recovery\n");

	}
}

void* thread_oled_handle(void * arg)
{
	OLED_Init();
	OLED_ColorTurn(0);		//0正常显示 1 反色显示
	OLED_DisplayTurn(0);	//0正常显示 1 屏幕翻转显示
	OLED_Clear();
	if(kvm_oled_state.ue_patch_state == 1){
		kvm_show_UE();
		while(kvm_sys_state.oled_thread_running && !shutdown_requested){
			time::sleep_ms(100);
		}
		OLED_Clear();
	}

    while(kvm_sys_state.oled_thread_running && !shutdown_requested)
    {
		pthread_mutex_lock(&state_mutex);
		oled_auto_sleep();
		// printf("[kvmd]thread_oled_handle - while\n");
		uint8_t page_changed = (kvm_oled_state.page == kvm_sys_state.page)? 0:1;
		uint8_t subpage_changed = (kvm_oled_state.sub_page == kvm_sys_state.sub_page)? 0:1;
		// printf("subpage_changed = %d", subpage_changed);
		// printf("kvm_oled_state.sub_page = %d", kvm_oled_state.sub_page);
		// printf("kvm_sys_state.sub_page = %d\n", kvm_sys_state.sub_page);
		kvm_oled_state.page = kvm_sys_state.page;
		kvm_oled_state.sub_page = kvm_sys_state.sub_page;


		switch(kvm_oled_state.page){
			case 0 : // main page
				kvm_main_ui_disp(page_changed, subpage_changed);
				break;
			case 1 : // wifi config page
				kvm_wifi_config_ui_disp(page_changed, subpage_changed);
				break;
		default:
				OLED_Clear();
		}
		pthread_mutex_unlock(&state_mutex);
		time::sleep_ms(OLED_DELAY);
    }
	OLED_Clear();
	kvm_sys_state.oled_thread_running = -1;
	return NULL;
}

void* thread_key_handle(void * arg)
{
	uint64_t press_time = 0;
	bool press_active = false;
	uint32_t press_cycle;
	int fd = open ("/dev/input/event0", O_RDONLY);
	if (fd == -1) {
		kvm_sys_state.key_thread_running = 0;
		return NULL;
	}
	struct input_event event;
	struct pollfd poll_fd = {fd, POLLIN, 0};

    while(kvm_sys_state.key_thread_running && !shutdown_requested)
    {
		int poll_res = poll(&poll_fd, 1, KEY_DELAY);
		if (poll_res < 0) {
			if (errno == EINTR) continue;
			break;
		}
		if (poll_res == 0 || !(poll_fd.revents & POLLIN)) continue;
		ssize_t read_size = read(fd, &event, sizeof(event));
		if (read_size != static_cast<ssize_t>(sizeof(event))) continue;
		if (event.type == EV_KEY) {
			if (event.value == 1){
				// printf ("[kvmk]按键按下\n");
				press_time = time::time_ms();
				press_active = true;
			} else if (event.value == 0){
				if (!press_active) continue;
				press_active = false;
				pthread_mutex_lock(&state_mutex);
				oled_auto_sleep_time_update();
				// printf ("[kvmk]按键抬起\n");
				press_cycle = time::time_ms() - press_time;
				if (press_cycle >= KEY_LONG_PRESS){
					// long
					// printf ("[kvmk]按键长按\n");
					// printf("[kvmk]wifi_state = %d\n", kvm_sys_state.wifi_state);
					if(kvm_sys_state.wifi_state == -2){
						kvm_sys_state.page = 0;
						kvm_sys_state.sub_page = 0;
						pthread_mutex_unlock(&state_mutex);
						continue;
					}
					switch(kvm_sys_state.page){
						case 0:	// main page
							kvm_sys_state.page = 1;
							kvm_sys_state.sub_page = 0;
							break;
						case 1:	// wifi coonfig page
							system("/etc/init.d/S30wifi restart");
							kvm_sys_state.page = 0;
							kvm_sys_state.sub_page = 0;
							kvm_sys_state.wifi_config_process = -1;
							break;
					}
				} else {
					// short
					// printf ("[kvmk]按键短按\n");
					// printf ("[kvmk]wifi_config_process = %d\n", kvm_sys_state.wifi_config_process);
					// printf ("[kvmk]page = %d\n", kvm_sys_state.page);
					// printf ("[kvmk]sub_page = %d\n", kvm_sys_state.sub_page);
					switch(kvm_sys_state.page){
						case 0:	// main page
							if(kvm_sys_state.sub_page == 0) kvm_sys_state.sub_page = 1;
							else kvm_sys_state.sub_page = 0;
							break;
						case 1:	// wifi coonfig page
							switch(kvm_sys_state.wifi_config_process){
								case 1:	// QR1<->TEXT2
									if(kvm_sys_state.sub_page == 1) kvm_sys_state.sub_page = 2;
									else kvm_sys_state.sub_page = 1;
									// printf("[kvmk]sub_page = %d\n", kvm_sys_state.sub_page);
									break;
								case 2:
									if(kvm_sys_state.sub_page == 1) kvm_sys_state.sub_page = 2;
									else if(kvm_sys_state.sub_page == 2) kvm_sys_state.sub_page = 3;
									else if(kvm_sys_state.sub_page == 3) kvm_sys_state.sub_page = 4;
									else kvm_sys_state.sub_page = 1;
									break;
							}
							break;
					}
				}
				pthread_mutex_unlock(&state_mutex);
			}
		}
    }
	close(fd);
	kvm_sys_state.key_thread_running = 0;
	return NULL;
}

void* thread_sys_handle(void * arg)
{
	get_ping_allow_state();
    while(kvm_sys_state.sys_thread_running && !shutdown_requested)
    {
		pthread_mutex_lock(&state_mutex);
		// net
		if(kvm_sys_state.page == 0){
			kvm_update_eth_state();
			kvm_update_wifi_state();
			// kvm_update_rndis_state();
			// kvm_update_tailscale_state();
			// sys_state
			if(!kvm_update_passive_state_from_rust_hwmon()){
				kvm_update_usb_state();
				kvm_update_hdmi_state();
				kvm_update_stream_fps();
				kvm_update_hdmi_res();
				kvm_update_stream_type();
				kvm_update_stream_qlty();
			}
			kvm_wifi_web_config_process();

		} else if(kvm_sys_state.page == 1){
			kvm_wifi_config_process();
		}
		pthread_mutex_unlock(&state_mutex);

		time::sleep_ms(STATE_DELAY);
    }
	kvm_sys_state.sys_thread_running = 0;
	return NULL;
}

int main(int argc, char* argv[])
{
	// Signal context only flips a sig_atomic_t flag; worker teardown happens below.
	signal(SIGINT, request_shutdown);
	signal(SIGTERM, request_shutdown);

	pthread_t sys_state_thread;
	pthread_t display_thread;
	pthread_t key_thread;
	bool sys_thread_started = false;
	bool display_thread_started = false;
	bool key_thread_started = false;

	// only for production testing
	if (trusted_runtime_flag("/run/nanokvm-production-test")){
		printf("Production testing patch\n");
		Production_testing_patch();
	}

	system("sync");

	OLED_state = oled_exist();
	if(OLED_state){
		printf("oled exist\r\n");
		system("touch /etc/kvm/oled_exist");
	} else {
		printf("oled not exist\r\n");
		system("rm /etc/kvm/oled_exist");
	}

	if(kvm_sys_state.sys_thread_running == 0){
		kvm_sys_state.sys_thread_running = 1;
		if (0 != pthread_create(&sys_state_thread, NULL, thread_sys_handle, NULL)) {
			kvm_sys_state.sys_thread_running = 0;
			printf("[kvms]create thread failed!\r\n");
		} else sys_thread_started = true;
	}
	if(OLED_state == 1 && kvm_sys_state.oled_thread_running == 0){
		kvm_sys_state.oled_thread_running = 1;
		if (0 != pthread_create(&display_thread, NULL, thread_oled_handle, NULL)) {
			kvm_sys_state.oled_thread_running = 0;
			printf("[kvms]create thread failed!\r\n");
		} else display_thread_started = true;
	}
	if(kvm_sys_state.key_thread_running == 0){
		kvm_sys_state.key_thread_running = 1;
		if (0 != pthread_create(&key_thread, NULL, thread_key_handle, NULL)) {
			kvm_sys_state.key_thread_running = 0;
			printf("[kvms]create thread failed!\r\n");
		} else key_thread_started = true;
	}

	if (sys_thread_started) {
		pthread_join(sys_state_thread, NULL);
	} else {
		shutdown_requested = 1;
	}
	if (display_thread_started) pthread_join(display_thread, NULL);
	if (key_thread_started) pthread_join(key_thread, NULL);
	kvm_sys_state.sys_thread_running = 0;
	kvm_sys_state.oled_thread_running = 0;
	kvm_sys_state.key_thread_running = 0;
	return 0;
}

