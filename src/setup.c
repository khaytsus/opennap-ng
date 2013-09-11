/* Copyright (C) 2000-1 drscholl@users.sourceforge.net
This is free software distributed under the terms of the
GNU Public License.  See the file COPYING for details.

$Id: setup.c 430 2006-07-29 20:22:19Z reech $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#ifndef WIN32
#include <unistd.h>
#define MKDIR(a,b) mkdir(a,b)
#define DIRSEP '/'
#else
#include "win32-support.h"
#include <direct.h>
#include <io.h>
#define mkdir(a,b) _mkdir(a)
#define strdup _strdup
#define F_OK 00
#define DIRSEP '\\'
#endif


# define DIR_SEP  '/'


/* opennap installation program */

#if WIN32
#define EXT ".exe"
#include "opennap.h"
#else
#define EXT ""
#endif /* WIN32 */

static void
usage (void)
{
    printf ("usage: setup%s [ -h ] [ -v ]\n", EXT);
    puts ("  -h     display this help message");
    puts ("  -d     create other config/log dir");
    puts ("  -v     display the version\n");
    exit (0);
}

static void
version (void)
{
    printf ("%s setup%s %s\n", PACKAGE, EXT, VERSION);
    exit (0);
}

static void
prompt (const char *str, const char *def, char *buf, int buflen)
{
    char   *p;

    buf[buflen - 1] = 0;
    while (1)
    {
        printf ("%s? [%s]: ", str, def ? def : "<no default>");
        fflush (stdout);
        if (!fgets (buf, buflen - 1, stdin))
        {
            puts ("EOF");
            exit (1);
        }
        if (buf[0] == '\n' || buf[0] == '\r')
        {
            if (def)
            {
                strncpy (buf, def, buflen - 1);
                return;
            }
        }
        else
        {
            p = strpbrk (buf, " \r\n");
            *p = 0;
            if (buf[0])
            {
                return;
            }
        }
    }
}

static int
directory_exists(char *dir) {
    struct stat st;

    if (stat(dir, &st) < 0) return 0;
    else return 1;
}

int create_dir(char *dir) {
    char *pos;
    char *slash;

    if (!dir) return 0;
    if (directory_exists(dir)) return 1;

    slash = dir;
    while ((pos = strchr(slash + 1, DIR_SEP)) != NULL) {
        pos[0] = 0;
        if (!directory_exists(dir)) {
            if (mkdir(dir, 7 * 64 + 5 * 8 + 5)) {
                printf("Could not create folder [%s]\n", dir);
                return 0;
            }
        }
        pos[0] = DIR_SEP;
        slash = pos;
    }
    if (!directory_exists(dir)) {
        if (mkdir(dir, 7 * 64 + 5 * 8 + 5)) {
            printf("Could not create folder [%s]\n", dir);
            return 0;
        }
    }
    return 1;
}

int create_configlog_dir(void) 
{

    int     fd;
    char    path[256];
    char    path2[256];
    char    buf[256];
    char    nick[64];
    char    pass[64];
    char    email[64];
    char    str[2048];
    char   *config_dir;
    FILE   *fp;

    /* ensure that the configuration directory exists */
    strcpy (path, SHAREDIR);

    printf("Add Opennap config\n");
    do
    {
        prompt ("Where should I install OpenNap configuration", SHAREDIR, path,
            sizeof (path));

        config_dir = strdup(path);

        snprintf(str, sizeof(str), "%s", config_dir);
        create_dir(str);
        /*
        if (MKDIR (path, S_IRWXU))
        perror (path);
        */
    }
    while (access (path, F_OK));
    printf ("Created %s\n", path);


    /* ensure that the log directory exists */
    strcpy (path2, VARDIR);

    printf("Add Opennap database\n");
    do
    {
        prompt ("Where should I install OpenNap database", VARDIR, path2,
            sizeof (path2));

        config_dir = strdup(path2);
        snprintf(str, sizeof(str), "%s", config_dir);
        create_dir(str);
        /*
        if (MKDIR (path2, S_IRWXU))
        perror (path2);
        */
    }
    while (access (path2, F_OK));
    printf ("Created %s\n", path2);

    /* directory is created at this point */
    /* check to see if the users file exists */
    puts ("Checking for OpenNap user database...");
    snprintf (buf, sizeof (buf), "%s%cusers", path2, DIRSEP);
    if (access (buf, F_OK))
    {
        if (errno != ENOENT)
        {
            perror (buf);
            exit (1);
        }
        /* prompt the user for the elite login */
        prompt ("Enter nickname for server owner (elite)", 0, nick,
            sizeof (nick));
        prompt ("Enter password for nickname", 0, pass, sizeof (pass));
        prompt ("Enter email address", "email@here.com", email,
            sizeof (email));
        /* write out the file */
        fd = open (buf, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd < 0)
        {
            perror ("open");
            exit (1);
        }
        fp = fdopen (fd, "w");
        if (!fp)
        {
            perror (buf);
            exit (1);
        }
        fprintf (fp, "%s %s %s Elite 0 0\n", nick, pass, email);
        if (fclose (fp))
        {
            perror ("fclose");
            exit (1);
        } 
        printf ("Created %s\n", path2);
    }
    /* if opennap is installed other than in the default location, set
    up a config file with the proper config_dir variable */
    if (strcmp (path, SHAREDIR) != 0)
    {
        snprintf (buf, sizeof (buf), "%s%cconfig", path, DIRSEP);
        if (access (buf, F_OK))
        {
            if (errno != ENOENT)
            {
                perror (buf);
                exit (1);
            }
            fd = open (buf, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
            if (fd < 0)
            {
                perror ("open");
                exit (1);
            }
            fp = fdopen (fd, "w");
            if (!fp)
            {
                perror ("fdopen");
                exit (1);
            }
            fprintf (fp, "# auto generated by %s setup%s %s\n\n", PACKAGE,
                EXT, VERSION);
            fprintf (fp, "# package was configured to install in %s\n",
                VARDIR);
            fprintf (fp, "# but OpenNap is installed here:\n");
            fprintf (fp, "config_dir %s\n", path);
            fclose (fp);
            printf ("Created %s\n", buf);
        }

#if WIN32
        /* create a batch file to easily launch the server */
        snprintf (buf, sizeof (buf), "%s\\launch.bat", path);
        fp = fopen (buf, "w");
        if (!fp)
        {
            perror (buf);
            exit (1);
        }
        fprintf (fp, "%s\\opennap.exe -c %s\\config", path, path);
        fclose (fp);
        printf ("Created %s\n", buf);
        printf ("You can start the server by running %s\\launch.bat\n", path);
#endif /* WIN32 */
    }
    else
        puts
        ("OpenNap is installed in default directory, no config file created");
    puts ("Congratulations!  OpenNap is now installed");

    exit (0);
}

int
main (int argc, char **argv)
{
    int     i;
    int     fd;
    char    path[256];
    char    path2[256];
    char    buf[256];
    char    nick[64];
    char    pass[64];
    char    email[64];
    char    str[2048];
    char   *config_dir;
    FILE   *fp;

    while ((i = getopt (argc, argv, "dhv")) != -1)
    {
        switch (i)
        {
        case 'v':
            version ();
            break;
        case 'd':
            create_configlog_dir ();
            break;
        case 'h':
        default:
            usage ();
        }
    }

    /* ensure that the configuration directory exists */
    strcpy (path, SHAREDIR);
    puts ("Checking for OpenNap configuration directory...");
    if (access (path, F_OK))
    {
        if (errno != ENOENT)
            perror (path);
        do
        {
            prompt ("Where should I install OpenNap configuration", SHAREDIR, path,
                sizeof (path));

            config_dir = strdup(path);

            snprintf(str, sizeof(str), "%s", config_dir);
            create_dir(str);
            /*
            if (MKDIR (path, S_IRWXU))
            perror (path);
            */
        }
        while (access (path, F_OK));
        printf ("Created %s\n", path);
    }

    /* ensure that the log directory exists */
    strcpy (path2, VARDIR);
    puts ("Checking for OpenNap database directory...");
    if (access (path2, F_OK))
    {
        if (errno != ENOENT)
            perror (path2);
        do
        {
            prompt ("Where should I install OpenNap database", VARDIR, path2,
                sizeof (path2));

            config_dir = strdup(path2);
            snprintf(str, sizeof(str), "%s", config_dir);
            create_dir(str);
            /*
            if (MKDIR (path2, S_IRWXU))
            perror (path2);
            */
        }
        while (access (path2, F_OK));
        printf ("Created %s\n", path2);
    }
    /* directory is created at this point */
    /* check to see if the users file exists */
    puts ("Checking for OpenNap user database...");
    snprintf (buf, sizeof (buf), "%s%cusers", path2, DIRSEP);
    if (access (buf, F_OK))
    {
        if (errno != ENOENT)
        {
            perror (buf);
            exit (1);
        }
        /* prompt the user for the elite login */
        prompt ("Enter nickname for server owner (elite)", 0, nick,
            sizeof (nick));
        prompt ("Enter password for nickname", 0, pass, sizeof (pass));
        prompt ("Enter email address", "email@here.com", email,
            sizeof (email));
        /* write out the file */
        fd = open (buf, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd < 0)
        {
            perror ("open");
            exit (1);
        }
        fp = fdopen (fd, "w");
        if (!fp)
        {
            perror (buf);
            exit (1);
        }
        fprintf (fp, "%s %s %s Elite 0 0\n", nick, pass, email);
        if (fclose (fp))
        {
            perror ("fclose");
            exit (1);
        } 
        printf ("Created %s\n", path2);
    }
    /* if opennap is installed other than in the default location, set
    up a config file with the proper config_dir variable */
    if (strcmp (path, SHAREDIR) != 0)
    {
        snprintf (buf, sizeof (buf), "%s%cconfig", path, DIRSEP);
        if (access (buf, F_OK))
        {
            if (errno != ENOENT)
            {
                perror (buf);
                exit (1);
            }
            fd = open (buf, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
            if (fd < 0)
            {
                perror ("open");
                exit (1);
            }
            fp = fdopen (fd, "w");
            if (!fp)
            {
                perror ("fdopen");
                exit (1);
            }
            fprintf (fp, "# auto generated by %s setup%s %s\n\n", PACKAGE,
                EXT, VERSION);
            fprintf (fp, "# package was configured to install in %s\n",
                VARDIR);
            fprintf (fp, "# but OpenNap is installed here:\n");
            fprintf (fp, "config_dir %s\n", path);
            fclose (fp);
            printf ("Created %s\n", buf);
        }

#if WIN32
        /* create a batch file to easily launch the server */
        snprintf (buf, sizeof (buf), "%s\\launch.bat", path);
        fp = fopen (buf, "w");
        if (!fp)
        {
            perror (buf);
            exit (1);
        }
        fprintf (fp, "%s\\opennap.exe -c %s\\config", path, path);
        fclose (fp);
        printf ("Created %s\n", buf);
        printf ("You can start the server by running %s\\launch.bat\n", path);
#endif /* WIN32 */
    }
    else
        puts
        ("OpenNap is installed in default directory, no config file created");
    puts ("Congratulations!  OpenNap is now installed");

    exit (0);
}
