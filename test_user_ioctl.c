#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>

#define CIOCCRYPT  0x20006401
#define CIOCXCRYPT 0x20006402

int main() {
	char *null_ptr;
	char *user_string;
	user_string = (char *)malloc(256);
	strcpy(user_string, "Hello World!");
	int fd = open("/dev/tty", O_RDWR);

	if (ioctl(fd, CIOCCRYPT, &user_string) == -1) {
        	perror("Encrypt Failed");
        	close(fd);
        	return EXIT_FAILURE;
    	}
	if (ioctl(fd, CIOCXCRYPT, &null_ptr) == -1) {
        	perror("Decrypt Failed");
        	close(fd);
        	return EXIT_FAILURE;
    	}
	free(user_string);
	close(fd);
   	return EXIT_SUCCESS;
}
