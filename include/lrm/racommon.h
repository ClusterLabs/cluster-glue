#ifndef RACOMMON_H
#define RACOMMON_H

void get_ra_pathname(const char* class_path, const char* type, const char* provider, char pathname[]);
gboolean filtered(char * file_name);
int get_runnable_list(const char* class_path, GList ** rsc_info);

#endif /* RACOMMON_H */
