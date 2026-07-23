#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <shadow.h>
#include <sys/types.h>
#include <unistd.h>
#include <crypt.h>
#include <sys/wait.h>

/* hardening (C6): run a program via an explicit argv (NO shell) and capture its
 * first line of stdout. Replaces popen() so an attacker-supplied password/salt
 * can never be parsed as a shell command. Returns 1 if a line was read. Mirrors
 * run_capture_line() added to shared/misc.c for the asus_openssl_crypt() twin. */
static int run_capture_line(char *const argv[], char *out, size_t out_sz)
{
	int pipefd[2];
	pid_t pid;

	if(out == NULL || out_sz == 0)
		return 0;
	out[0] = '\0';
	if(pipe(pipefd) != 0)
		return 0;

	pid = fork();
	if(pid < 0){
		close(pipefd[0]);
		close(pipefd[1]);
		return 0;
	}
	if(pid == 0){				/* child */
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execvp(argv[0], argv);
		_exit(127);
	}
	/* parent */
	close(pipefd[1]);
	{
		FILE *fp = fdopen(pipefd[0], "r");
		if(fp != NULL){
			if(fgets(out, out_sz, fp) == NULL)
				out[0] = '\0';
			fclose(fp);
		}else
			close(pipefd[0]);
	}
	waitpid(pid, NULL, 0);
	return out[0] != '\0';
}

static int asus_libpasswd_openssl_crypt(char *key, char *salt, char *out, int out_len)
{
	dbg("asus_openssl_crypt: check toolchain crypt() support\n");
	int scheme_id = 0, ret = 0;
	char crypt_buf[256] = {0};

	if(salt && strlen(salt) > 4){
		if(!strncmp(salt, "$1$", 3))
			scheme_id = 1;
		else if(!strncmp(salt, "$5$", 3))
			scheme_id = 5;
		else
			return ret;
	}else
		return ret;

	{
		char scheme_arg[8];
		char *argv[7];
		snprintf(scheme_arg, sizeof(scheme_arg), "-%d", scheme_id);
		argv[0] = "openssl";
		argv[1] = "passwd";
		argv[2] = scheme_arg;
		argv[3] = "-salt";
		argv[4] = salt + 3;
		argv[5] = key;
		argv[6] = NULL;
		/* hardening (C6): argv exec (no shell) instead of popen() with the
		 * password/salt embedded in a shell command string. */
		if(run_capture_line(argv, crypt_buf, sizeof(crypt_buf))){
			if(strlen(crypt_buf) > 0 && crypt_buf[strlen(crypt_buf)-1] == '\n')
				crypt_buf[strlen(crypt_buf)-1] = '\0';
		}
	}

	if(crypt_buf[0] != '\0'){
		if(!strncmp(crypt_buf, salt, strlen(salt))){
			strlcpy(out, crypt_buf, out_len);
			ret = 1;
		}
	}

	return ret;
}

int compare_passwd_in_shadow(const char *username, const char *passwd)
{
	char *salt, *correct, *p, *supplied;
	struct spwd *shadow_entry;
	char crypt_buf[256] = {0};

	if(!username || !passwd)
		return 0;

	shadow_entry = getspnam(username);

	if(!shadow_entry)
		return 0;

	correct = shadow_entry->sp_pwdp;
	
	salt = strdup(correct);

	if (salt == NULL) 
		goto ERROR;
	
	p = strchr(salt + 1, '$');
	if (p == NULL) 
		goto ERROR;
	
	p = strchr(p + 1, '$');
	if (p == NULL) 
		goto ERROR;
	p[1] = 0;	

	supplied = crypt(passwd, salt);
	
	if (supplied == NULL) {
		asus_libpasswd_openssl_crypt(passwd, salt, crypt_buf, sizeof(crypt_buf));
		supplied = crypt_buf;
	}
	if(supplied == NULL || *supplied == '\0')
		goto ERROR;

	free(salt);
	return !strcmp(supplied, correct);
	
ERROR:
	if(salt)
		free(salt);
	return 0;
}



