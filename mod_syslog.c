#include "apr_hooks.h"
#include "ap_config.h"

#include "mod_log_config.h"

#include "http_config.h"

#include <sys/syslog.h>

module AP_MODULE_DECLARE_DATA syslog_module;

static const char syslog_filter_name[] = "LOG_SYSLOG";

static APR_OPTIONAL_FN_TYPE(ap_log_set_writer_init) *set_writer_init;
static APR_OPTIONAL_FN_TYPE(ap_log_set_writer)      *set_writer;

static ap_log_writer_init *prev_log_writer_init = NULL;
static ap_log_writer      *prev_log_writer      = NULL;

typedef struct syslog_config_t {
} syslog_config_t;

char dummy[16];

#define PREFIX_SYSLOG   "syslog:"
#define PREFIX_SYSLOG_LENGTH    7

static void *
ap_syslog_writer_init(apr_pool_t *p, server_rec *s,
                      const char* name)
{
    syslog(LOG_DEBUG, "%s: prev_log_writer_init = %p, name = %s", __func__, prev_log_writer_init, name);
    
    if (strncasecmp(PREFIX_SYSLOG, name, PREFIX_SYSLOG_LENGTH) == 0) {
        return &dummy[0];
    }

    if (prev_log_writer_init) {
        return prev_log_writer_init(p, s, name);
    }

    return NULL;
}

static apr_status_t
ap_syslog_writer(request_rec *r,
                 void *handle,
                 const char **strs,
                 int *strl,
                 int nelts,
                 apr_size_t len)
{
    if (handle == dummy) {
        char *str;
        char *s;
        int i;
        apr_status_t rv;

        str = apr_palloc(r->pool, len + 1);

        for (i = 0, s = str; i < nelts; ++i) {
            memcpy(s, strs[i], strl[i]);
            s += strl[i];
        }
        str[len] = '\0';

        syslog(LOG_INFO, "%s", str);
        return OK;
    }

    if (prev_log_writer) {
        return prev_log_writer(r, handle, strs, strl, nelts, len);
    }

    return OK;
}


static int syslog_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    if (!set_writer_init) {
        set_writer_init = APR_RETRIEVE_OPTIONAL_FN(ap_log_set_writer_init);
        set_writer      = APR_RETRIEVE_OPTIONAL_FN(ap_log_set_writer);
    }

    syslog(LOG_DEBUG, "%s: >>> p = %p, plog = %p, ptemp = %p", __func__, p, plog, ptemp);
    syslog(LOG_DEBUG, "%s: >>> prev_log_writer_init = %p / ap_syslog_writer_init = %p", __func__, prev_log_writer_init, ap_syslog_writer_init);

    if (!prev_log_writer_init) {
        void* f;

        f = set_writer_init(ap_syslog_writer_init);
        if (f != ap_syslog_writer_init) {
            prev_log_writer_init = f;
        } else {
            syslog(LOG_ALERT, ">>> f = %p", f);
        }
        f = set_writer(ap_syslog_writer);
        if (f != ap_syslog_writer) {
            prev_log_writer = f;
        }
    }

    syslog(LOG_DEBUG, "%s: <<< prev_log_writer_init = %p / ap_syslog_writer_init = %p", __func__, prev_log_writer_init, ap_syslog_writer_init);

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    static const char *pre[] = { "mod_log_config.c", NULL };

    openlog(NULL, LOG_PID, LOG_USER);

    syslog(LOG_DEBUG, "%s: prev_log_writer_init = %p / p = %p", __func__, prev_log_writer_init, p);
    syslog(LOG_DEBUG, "%s: ap_syslog_writer_init = %p", __func__, ap_syslog_writer_init);

    ap_hook_pre_config(syslog_pre_config, pre, NULL, APR_HOOK_REALLY_LAST);
}

module AP_MODULE_DECLARE_DATA syslog_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
