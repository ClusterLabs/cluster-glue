#ifndef RACOMMON_H
#define RACOMMON_H

extern const int RA_MAX_NAME_LENGTH;
extern const int RA_MAX_DIRNAME_LENGTH;
extern const int RA_MAX_BASENAME_LENGTH;

typedef struct {
	gchar * rsc_type;
	/* As for version, no definite definition yet */
	gchar * version;
} rsc_info_t;

void get_ra_pathname(const char* class_path, const char* type, const char* provider, char pathname[]);
gboolean filtered(char * file_name);
int get_providers(const char* class_path, const char* op_type, GList ** providers);
int get_ra_list(const char* class_path, GList ** rsc_info);

#endif /* RACOMMON_H */
