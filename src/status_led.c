#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/init.h>

static const struct gpio_dt_spec status_led =
    GPIO_DT_SPEC_GET(DT_NODELABEL(status_led), gpios);

static struct k_timer blink_timer;

static void blink_handler(struct k_timer *timer) {
    gpio_pin_toggle_dt(&status_led);
}

static int status_led_init(void) {
    if (!gpio_is_ready_dt(&status_led)) {
        return -ENODEV;
    }
    gpio_pin_configure_dt(&status_led, GPIO_OUTPUT_INACTIVE);
    k_timer_init(&blink_timer, blink_handler, NULL);
    k_timer_start(&blink_timer, K_SECONDS(3), K_SECONDS(3));
    return 0;
}

SYS_INIT(status_led_init, APPLICATION, 99);