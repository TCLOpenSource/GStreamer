/********************************************************************************
** Copyright (C), 2014-2020, TCL Corp., Ltd
** VENDOR_EDIT, All rights reserved.
**
** File: - gstnfssrc.h
** Description:
**
**
** --------------------Revision History: ------------------------
** <author>           <date>         <version>            <desc>
** --------------------------------------------------------------
**                    2024-6-18       1.0            add init version.
*******************************************************************************/


#ifndef __GST_SMB_SRC_H__
#define __GST_SMB_SRC_H__

#include <sys/types.h>

#include <gst/gst.h>
#include <gst/base/gstbasesrc.h>

G_BEGIN_DECLS

#define GST_TYPE_SMB_SRC \
  (gst_smb_src_get_type())
#define GST_SMB_SRC(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_SMB_SRC,GstSmbSrc))
#define GST_SMB_SRC_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_SMB_SRC,GstSmbSrcClass))
#define GST_IS_SMB_SRC(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_SMB_SRC))
#define GST_IS_SMB_SRC_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_SMB_SRC))
#define GST_SMB_SRC_CAST(obj) ((GstSmbSrc*) obj)

typedef struct _GstSmbSrc GstSmbSrc;
typedef struct _GstSmbSrcClass GstSmbSrcClass;

/**
 * GstSmbSrc:
 *
 * Opaque #GstSmbSrc structure.
 */
struct _GstSmbSrc {
  GstBaseSrc element;

  /*< private >*/
  gchar *url;           /* caching the URI */
  gint fd;              /* open file descriptor */
  guint64 read_position; /* position of fd */

  gboolean seekable;                    /* whether the file is seekable */

  gint64 start_offset;
  gint64 length;
  char* username;
  char* password;
  void * smb_ctx;
  uint64_t last_read_time;
  guint64 last_read_size;

  gboolean cancel_download;
  gboolean stoped;
  gboolean is_seek;
  guint64 seek_start_pos;
  guint64 consume_len;
  guint64 download_len;
  GstFlowReturn ret;

  GstTask *download_task;
  GRecMutex download_tasklock;
  gboolean downloadloopRun;
  gboolean read_err;

  GMutex queue_lock;
  GCond  queue_cond;
  GQueue *queue;

  guint64 queue_len;
  gboolean use_backup;
  guint fill_queue_times;

  GMutex backup_queue_lock;
  GQueue *backup_queue;
  guint64 backup_consume_len;
  guint64 backup_download_len;
};

struct _GstSmbSrcClass {
  GstBaseSrcClass parent_class;
};

G_GNUC_INTERNAL GType gst_smb_src_get_type (void);

G_END_DECLS

#endif /* __GST_SMB_SRC_H__ */
