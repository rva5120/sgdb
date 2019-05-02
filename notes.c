#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAXSIZE 100000

int main() {

	// Variables
	char buffer[MAXSIZE];
	//char password[16] = "IloveCats";
	char password[16] = "h";
	char input_password[16];
  int i = 0;
  ssize_t size = 0;
	FILE *fPtr = 0;


	// Open notes file
	fPtr = fopen("user.db", "r");

	// Read the file contents into buffer
	// (read all characters until the null character)
  fscanf(fPtr, "%[^~]", buffer);

  printf("Buffer with contents: %x\n", buffer);
  printf("Contents:\n%c\n", buffer[0]);

	// Ask for password
	printf("Enter password to display notes: ");
	fgets(input_password, 16, stdin);
	printf("\n");

	// Check that they are the same
	while (i < strlen(password)) {
		if (password[i] != input_password[i]) {
			printf("ERROR! INVALID PASSWORD!\n");
			return 0;
		}
		i++;
	}
  
	// Password cleared
	//printf("Correct Password!\n\n");
	printf("%s\n", buffer);

	// Close the file
	fclose(fPtr);

	return 0;

}
