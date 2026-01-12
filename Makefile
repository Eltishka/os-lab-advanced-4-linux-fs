# Имя модуля
MODULE_NAME = vtfs

# Пути
MOUNT_POINT = /mnt/vtfs
MOUNT_TOKEN = "vtfs-token"

# Настройки для сборки модуля ядра
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := source/vtfs.o source/http.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Основные цели
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "Module built successfully"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.ko *.o *.mod* modules.order Module.symvers .*.cmd
	rm -f source/*.o source/.*.cmd

# Работа с модулем
load: all
	sudo insmod $(MODULE_NAME).ko
	@echo "Module loaded. Check dmesg for output."

unload:
	@if lsmod | grep -q $(MODULE_NAME); then \
		sudo rmmod $(MODULE_NAME); \
		echo "Module unloaded."; \
	else \
		echo "Module is not loaded"; \
	fi

reload: unload load

# Монтирование файловой системы
mount-dir:
	sudo rmdir /mnt/vtfs
	@if [ ! -d $(MOUNT_POINT) ]; then \
		echo "Creating mount point $(MOUNT_POINT)"; \
		sudo mkdir -p $(MOUNT_POINT); \
		sudo chmod 777 $(MOUNT_POINT); \
	else \
		echo "Mount point $(MOUNT_POINT) already exists"; \
	fi

mount: umount unload load mount-dir
	@if mountpoint -q $(MOUNT_POINT); then \
		echo "Already mounted at $(MOUNT_POINT)"; \
	else \
		sudo mount -t $(MODULE_NAME) $(MOUNT_TOKEN) $(MOUNT_POINT); \
		echo "Filesystem mounted at $(MOUNT_POINT)"; \
	fi

umount:
	@if mountpoint -q $(MOUNT_POINT); then \
		sudo umount $(MOUNT_POINT); \
		echo "Filesystem unmounted from $(MOUNT_POINT)"; \
	else \
		echo "Filesystem is not mounted at $(MOUNT_POINT)"; \
	fi

remount: umount mount

# Полная установка (загрузка + монтирование)
install: mount

# Полное удаление (размонтирование + выгрузка)
uninstall: umount unload

# Работа с логами
logs:
	sudo dmesg | tail -20 | grep -i $(MODULE_NAME)

logs-all:
	sudo dmesg | grep -i $(MODULE_NAME)

# Информация
status:
	@echo "=== Module Status ==="
	@if lsmod | grep -q $(MODULE_NAME); then \
		echo "Module: LOADED"; \
		modinfo $(MODULE_NAME) | grep -E "filename|version|author|description"; \
	else \
		echo "Module: NOT LOADED"; \
	fi
	@echo ""
	@echo "=== Mount Status ==="
	@if mountpoint -q $(MOUNT_POINT); then \
		echo "Filesystem: MOUNTED at $(MOUNT_POINT)"; \
		mount | grep $(MOUNT_POINT); \
	else \
		echo "Filesystem: NOT MOUNTED at $(MOUNT_POINT)"; \
	fi
	@echo ""
	@echo "=== Files in mount point ==="
	@ls -la $(MOUNT_POINT) 2>/dev/null || echo "Mount point not accessible"

# Очистка логов
clear-logs:
	sudo dmesg -c > /dev/null
	echo "Kernel logs cleared"

# Перезапуск (полный цикл)
restart: uninstall install

# Помощь
help:
	@echo "Available targets:"
	@echo "  all           - Build the module"
	@echo "  clean         - Clean build files"
	@echo "  load          - Build and load module"
	@echo "  unload        - Unload module"
	@echo "  reload        - Reload module"
	@echo "  mount-dir     - Create mount directory"
	@echo "  mount         - Load module and mount filesystem"
	@echo "  umount        - Unmount filesystem"
	@echo "  remount       - Remount filesystem"
	@echo "  install       - Full installation (mount)"
	@echo "  uninstall     - Full removal (umount + unload)"
	@echo "  logs          - Show recent module logs"
	@echo "  logs-all      - Show all module logs"
	@echo "  status        - Show module and mount status"
	@echo "  clear-logs    - Clear kernel logs"
	@echo "  restart       - Complete restart"
	@echo "  help          - Show this help"

.PHONY: all clean load unload reload mount-dir mount umount remount \
	install uninstall logs logs-all status clear-logs restart help