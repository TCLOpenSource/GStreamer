/********************************************************************************
** Copyright (C), 2014-2020, TCL Corp., Ltd
** VENDOR_EDIT, All rights reserved.
**
** File: - GstSmbSrc.c
** Description:
**
**
** --------------------Revision History: ------------------------
** <author>           <date>         <version>            <desc>
** --------------------------------------------------------------
**                    2024-6-18       1.0            add init version.
*******************************************************************************/


#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <gst/gst.h>
#include <glib/gstdio.h>
#include "gstsmbsrc.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#include <errno.h>
#include <string.h>
#include "smb_interface.h"
#include <unistd.h>
#include <inttypes.h>

static GstStaticPadTemplate srctemplate = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

#undef LOG_TAG
#define LOG_TAG "UniPlayer+smbsrc"

GST_DEBUG_CATEGORY_STATIC (smb_src_debug);
#define GST_CAT_DEFAULT smb_src_debug

#define SMB_DEFAULT_BLOCKSIZE       (512*1024)
#define MAX_READ_BUFSIZE        (512 * 1024)
#define MSG_QUEUE_MAX_SIZE (40*1024*1024)


#ifndef U32
typedef unsigned int   U32;
#endif


enum
{
  PROP_0,
  PROP_LENGTH,
  PROP_CANCEL_DOWNLOAD,
  PROP_USE_BACKUP,
};

static void gst_smb_src_finalize (GObject * object);

static void gst_smb_src_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec);
static void gst_smb_src_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec);

static gboolean gst_smb_src_start (GstBaseSrc * basesrc);
static gboolean gst_smb_src_stop (GstBaseSrc * basesrc);

static gboolean gst_smb_src_is_seekable (GstBaseSrc * src);
static gboolean gst_smb_src_get_size (GstBaseSrc * src, guint64 * size);
static GstFlowReturn gst_smb_src_fill (GstBaseSrc * src, guint64 offset,
    guint length, GstBuffer * buf);

static void gst_smb_src_uri_handler_init (gpointer g_iface,
    gpointer iface_data);

static void gst_smb_src_download_loop(GstSmbSrc * src);
static GstFlowReturn gst_smb_src_download_data(GstSmbSrc *src, GstBuffer **outbuf, guint size);

static gboolean gst_smb_src_do_seek (GstSmbSrc *src, guint64 offset);

static void gst_smb_src_download_pause(GstSmbSrc * src);

static void gst_smb_src_push_data_to_queue(GstSmbSrc * src,GstBuffer* data);
static void gst_smb_src_pop_data_from_queue(GstSmbSrc * src,GstBuffer** outdata);
static void gst_smb_src_clear_queue(GstSmbSrc * src);

static GstFlowReturn gst_smb_src_fill_from_backup (GstSmbSrc * src, guint64 offset, guint length, GstBuffer * buf);
static void gst_smb_src_clear_backup_queue(GstSmbSrc * src);


#define GST_SMB_GET_DATA_QUEUE_LOCK(src) (&((GstSmbSrc*)(src))->queue_lock)
#define GST_SMB_SRC_DATA_QUEUE_LOCK(src) (g_mutex_lock(GST_SMB_GET_DATA_QUEUE_LOCK(src)))
#define GST_SMB_SRC_DATA_QUEUE_UNLOCK(src) (g_mutex_unlock(GST_SMB_GET_DATA_QUEUE_LOCK(src)))
#define GST_SMB_GET_DATA_QUEUE_COND(src) (&((GstSmbSrc*)(src))->queue_cond)
#define GST_SMB_SRC_DATA_QUEUE_COND_WAIT(src) g_cond_wait(GST_SMB_GET_DATA_QUEUE_COND(src), GST_SMB_GET_DATA_QUEUE_LOCK(src))
#define GST_SMB_SRC_DATA_QUEUE_COND_SIGNAL(src) g_cond_signal(GST_SMB_GET_DATA_QUEUE_COND(src))

#define GST_SMB_GET_DATA_BACKUP_QUEUE_LOCK(src) (&((GstSmbSrc*)(src))->backup_queue_lock)
#define GST_SMB_SRC_DATA_BACKUP_QUEUE_LOCK(src) (g_mutex_lock(GST_SMB_GET_DATA_BACKUP_QUEUE_LOCK(src)))
#define GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src) (g_mutex_unlock(GST_SMB_GET_DATA_BACKUP_QUEUE_LOCK(src)))


#define gst_smb_src_parent_class parent_class
G_DEFINE_TYPE_WITH_CODE (GstSmbSrc, gst_smb_src, GST_TYPE_BASE_SRC,
    G_IMPLEMENT_INTERFACE (GST_TYPE_URI_HANDLER,
        gst_smb_src_uri_handler_init));


static void
gst_smb_src_class_init (GstSmbSrcClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;
  GstBaseSrcClass *gstbasesrc_class;

  gobject_class = G_OBJECT_CLASS (klass);
  gstelement_class = GST_ELEMENT_CLASS (klass);
  gstbasesrc_class = GST_BASE_SRC_CLASS (klass);

  gobject_class->set_property = gst_smb_src_set_property;
  gobject_class->get_property = gst_smb_src_get_property;

  g_object_class_install_property (gobject_class, PROP_LENGTH,
        g_param_spec_int64 ("length", "Length",
            "Length for file to read", G_MININT64, G_MAXINT64, 0,
            G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property(gobject_class, PROP_CANCEL_DOWNLOAD,
        g_param_spec_boolean("cancel-download", "cancel download",
            "cancel download loop", FALSE,
            G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class,
        PROP_USE_BACKUP,
        g_param_spec_boolean ("use-backup", "use backup",
             "use backup queue",
             FALSE,
             G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  gobject_class->finalize = gst_smb_src_finalize;

  gst_element_class_set_static_metadata (gstelement_class,
      "File Source",
      "Source/File",
      "Read from arbitrary point in a file",
      "Erik Walthinsen <omega@cse.ogi.edu>");
  gst_element_class_add_static_pad_template (gstelement_class, &srctemplate);

  gstbasesrc_class->start = GST_DEBUG_FUNCPTR (gst_smb_src_start);
  gstbasesrc_class->stop = GST_DEBUG_FUNCPTR (gst_smb_src_stop);
  gstbasesrc_class->is_seekable = GST_DEBUG_FUNCPTR (gst_smb_src_is_seekable);
  gstbasesrc_class->get_size = GST_DEBUG_FUNCPTR (gst_smb_src_get_size);
  gstbasesrc_class->fill = GST_DEBUG_FUNCPTR (gst_smb_src_fill);

  if (sizeof (off_t) < 8) {
    GST_LOG ("No large file support, sizeof (off_t) = %" G_GSIZE_FORMAT "!",
        sizeof (off_t));
  }
}

static void
gst_smb_src_init (GstSmbSrc * src)
{
  UNILOGI("[in]");
  src->fd = -1;
  src->url = NULL;
  src->start_offset = 0;
  src->length = 0;
  src->smb_ctx = NULL;
  src->read_position = 0;
  src->seekable = TRUE;
  src->username = NULL;
  src->password = NULL;
  src->last_read_time = 0;
  src->last_read_size = 0;

  src->cancel_download = FALSE;
  src->stoped = FALSE;
  src->is_seek = FALSE;
  src->seek_start_pos = 0;
  src->consume_len = 0;
  src->download_len = 0;
  src->ret = GST_FLOW_OK;

  g_rec_mutex_init (&src->download_tasklock);
  src->download_task = gst_task_new  ((GstTaskFunction) gst_smb_src_download_loop, src, NULL);
  gst_task_set_lock (src->download_task, &src->download_tasklock);
  src->downloadloopRun = FALSE;

  g_mutex_init(&src->queue_lock);
  g_cond_init(&src->queue_cond);
  src->queue = g_queue_new ();

  src->queue_len = 0;
  src->use_backup = FALSE;
  src->fill_queue_times = 0;

  g_mutex_init(&src->backup_queue_lock);
  src->backup_queue = NULL;
  src->backup_consume_len = 0;
  src->backup_download_len = 0;
  src->read_err = FALSE;

  gst_base_src_set_blocksize (GST_BASE_SRC (src), SMB_DEFAULT_BLOCKSIZE * 1024);
  UNILOGI("[out]");
}

static void
gst_smb_src_finalize (GObject * object)
{
  GstSmbSrc *src;
  UNILOGI("[in]");
  src = GST_SMB_SRC (object);
  if (!src)
      return;

  src->stoped = TRUE;
  src->downloadloopRun = FALSE;

  gst_task_stop(src->download_task);
  UNILOGI("stop download_task");
  gst_task_join (src->download_task);
  gst_object_unref (src->download_task);
  g_rec_mutex_clear (&src->download_tasklock);
  UNILOGI("clear download_task end");

  gst_smb_src_clear_queue(src);
  gst_smb_src_clear_backup_queue(src);
  UNILOGI("clear queue end");
  g_mutex_clear(&src->backup_queue_lock);
  g_mutex_clear(&src->queue_lock);
  g_cond_clear(&src->queue_cond);
  UNILOGI("clear lock end");
  if (src->queue) {
      g_queue_free (src->queue);
      src->queue = NULL;
  }
  if (src->backup_queue) {
      g_queue_free (src->backup_queue);
      src->backup_queue = NULL;
  }

  if (src->url) {
    g_free (src->url);
    src->url = NULL;
  }
  if (src->username) {
     g_free (src->username);
     src->username = NULL;
  }

  if (src->password) {
     g_free (src->password);
     src->password = NULL;
  }

  if (src->fd > 0) {
     libsmbc_close(src->fd);
     src->fd = -1;
  }
  UNILOGI("[out]");
  libsmbc_free_ctx();
  G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
gst_smb_src_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstSmbSrc *src;

  g_return_if_fail (GST_IS_SMB_SRC (object));

  src = GST_SMB_SRC (object);

  switch (prop_id) {
    case PROP_LENGTH:
    {
      gint64 length = g_value_get_int64 (value);
      GST_INFO("length = %"PRId64"",length);
      if (length != 0) {
        src->length = length;
      }
      break;
    }
    case PROP_CANCEL_DOWNLOAD:
    {
        gboolean cancel = g_value_get_boolean(value);
        src->cancel_download = cancel;
        GST_SMB_SRC_DATA_QUEUE_COND_SIGNAL(src);
        GST_WARNING_OBJECT(src, "set PROP_CANCEL_DOWNLOAD cancel = %d", cancel);
        break;
    }
    case PROP_USE_BACKUP:
    {
        gboolean use_backup = g_value_get_boolean(value);
        GST_WARNING_OBJECT(src, "set PROP_USE_BACKUP use_backup = %d", use_backup);
        src->use_backup = use_backup;
        break;
    }
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_smb_src_get_property (GObject * object, guint prop_id, GValue * value,
    GParamSpec * pspec)
{
  GstSmbSrc *src;

  g_return_if_fail (GST_IS_SMB_SRC (object));

  src = GST_SMB_SRC (object);

  switch (prop_id) {
    case PROP_LENGTH:
      g_value_set_int (value, src->length);
      break;
    case PROP_CANCEL_DOWNLOAD:
      g_value_set_boolean (value, src->cancel_download);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static uint64_t
gst_get_running_time()
{
    struct timespec cur_time    = {0, 0};
    uint64_t        timeMs     = 0;

    clock_gettime(CLOCK_MONOTONIC_RAW, &cur_time);
    timeMs = ((uint64_t)cur_time.tv_sec * 1000) + ((uint64_t)cur_time.tv_nsec / 1000000);
    return timeMs;
}

static GstFlowReturn gst_smb_src_download_data(GstSmbSrc *src, GstBuffer **outbuf, guint size)
{
  GstFlowReturn ret = GST_FLOW_OK;
  guint to_read, bytes_read;
  GstMapInfo info;
  guint8 *data;
  GstBuffer *buf;
  int retry = 10;
  guint64 offset = src->read_position;

  GST_DEBUG_OBJECT (src, "start Reading %d from offset:%"PRId64"", size, offset);
  buf = gst_buffer_new_allocate (NULL, size, NULL);
  if (G_UNLIKELY (buf == NULL))
    goto alloc_failed;

  if (!gst_buffer_map (buf, &info, GST_MAP_WRITE))
    goto buffer_read_error;

  data = info.data;
  bytes_read = 0;

  to_read = size;
  if (src->last_read_time == 0) {
    src->last_read_time = gst_get_running_time();
  }

  while (to_read > 0 && !src->cancel_download) {
    ret = libsmbc_read(src->fd, data + bytes_read, to_read);

    if (G_UNLIKELY (ret < 0)) {
      usleep(1000);
      if(retry > 0) {
        GST_ERROR_OBJECT (src, "retry %d  offset:%"PRId64", read_pos:%"PRId64" ", retry, offset, offset+bytes_read);
        src->fd = libsmbc_retry_open_and_seek(src->fd, offset+bytes_read, src->url);
        retry--;
        continue;
      }
      goto could_not_read;
    }

    if (G_UNLIKELY (ret == 0)) {
      if (bytes_read > 0)
        break;
      goto eos;
    }

    to_read -= ret;
    bytes_read += ret;
  }

  uint64_t cur_time = gst_get_running_time();
  src->last_read_size += bytes_read;
  if (src->last_read_time > 0 && (cur_time - src->last_read_time) > 1000) {
    UNILOGI ("download %"PRIu64" bytes use %"PRId64" ms, file_offset: %"PRId64"", src->last_read_size, cur_time - src->last_read_time, offset + bytes_read);
    src->last_read_size = 0;
    src->last_read_time = cur_time;
  }
  src->read_position += bytes_read;

  gst_buffer_unmap (buf, &info);
  if (bytes_read != size)
    gst_buffer_resize (buf, 0, bytes_read);

  GST_BUFFER_OFFSET (buf) = offset;
  GST_BUFFER_OFFSET_END (buf) = offset + bytes_read;
  *outbuf = buf;
  GST_DEBUG_OBJECT (src, "end to read total length:%u, bytes_read:%d, read_pos:%"PRId64"", size, bytes_read, src->read_position);
  return GST_FLOW_OK;
/* ERROR */
could_not_read:
  {
    GST_ELEMENT_ERROR (src, RESOURCE, READ, (NULL), GST_ERROR_SYSTEM);
    gst_buffer_unmap (buf, &info);
    gst_buffer_unref (buf);
    return GST_FLOW_CUSTOM_SUCCESS;
  }
eos:
  {
    GST_DEBUG ("EOS");
    gst_buffer_unmap (buf, &info);
    gst_buffer_unref (buf);
    GST_SMB_SRC_DATA_QUEUE_COND_SIGNAL(src);
    return GST_FLOW_EOS;
  }
alloc_failed:
  {
    GST_ERROR_OBJECT (src, "Failed to allocate %u bytes", size);
    return GST_FLOW_CUSTOM_SUCCESS;
  }
buffer_read_error:
  {
    GST_ERROR_OBJECT (src, "Can't map buffer");
    gst_buffer_unref (buf);
    return GST_FLOW_CUSTOM_SUCCESS;
  }
}

static void gst_smb_src_download_loop(GstSmbSrc * src){
    GError *err = NULL;
    GstMessage *msg = NULL;
    char tname[32] = {0};
    sprintf(tname, "smb_download(%d)", getpid());
    prctl(PR_SET_NAME, (unsigned long)tname);
    //GST_DEBUG_OBJECT (src, "downloadloopRun in :%d, %d %d", src->downloadloopRun, src->stoped, src->cancel_download);
    while (src->downloadloopRun && !src->cancel_download && !src->read_err) {

        GstBuffer *data = NULL;

        if (src->is_seek) {
            if (!gst_smb_src_do_seek(src, src->seek_start_pos)) {
                src->is_seek = FALSE;
                src->read_err = TRUE;
                goto download_error;
            }
            src->is_seek = FALSE;
            src->seek_start_pos = 0;
        }
        if (src->read_position == src->length || src->stoped) {
            usleep(1000);
            continue;
        }

        while (src->download_len - src->consume_len > MSG_QUEUE_MAX_SIZE && (!src->is_seek && src->downloadloopRun && !src->read_err)) {
            usleep(1000);
            continue;
        }

        src->ret = gst_smb_src_download_data(src, &data, SMB_DEFAULT_BLOCKSIZE);
        if (src->ret == GST_FLOW_OK) {
            if (src->is_seek) {
                if (data != NULL) {
                    gst_buffer_unref (data);
                    data = NULL;
                }
                GST_SMB_SRC_DATA_QUEUE_COND_SIGNAL(src);
            }
            else{
              src->download_len = src->read_position;
              gst_smb_src_push_data_to_queue(src, data);
            }//usleep(500);
        } else if (src->ret != GST_FLOW_EOS){
          src->read_err = TRUE;
          GST_SMB_SRC_DATA_QUEUE_COND_SIGNAL(src);
          goto download_error;
        }
    }
    //GST_DEBUG_OBJECT (src, "downloadloopRun exit :%d, %d %d", src->downloadloopRun, src->stoped, src->cancel_download);
    return;
download_error:
      GST_ERROR_OBJECT (src, "downloadloopRun exit :%d, %d %d", src->downloadloopRun, src->stoped, src->cancel_download);
      err = g_error_new (GST_RESOURCE_ERROR, GST_RESOURCE_ERROR_OPEN_READ, "Failed to download smb data");
      msg = gst_message_new_error (GST_OBJECT_CAST (src), err, "smb download failed");
      gst_element_post_message (GST_ELEMENT_CAST (src), msg);
      g_error_free (err);
}

static void gst_smb_src_push_data_to_queue(GstSmbSrc * src,GstBuffer* data)
{
    GST_DEBUG_OBJECT(src,"in, buf_str=%"PRId64", buf_end=%"PRId64", size=%zu", GST_BUFFER_OFFSET (data), GST_BUFFER_OFFSET_END (data), gst_buffer_get_size(data));
    GST_SMB_SRC_DATA_QUEUE_LOCK(src);
    g_queue_push_tail(src->queue,data);
    src->queue_len += gst_buffer_get_size(data);
    GST_SMB_SRC_DATA_QUEUE_COND_SIGNAL(src);
    GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
    GST_DEBUG_OBJECT(src,"out");
}


static void gst_smb_src_pop_data_from_queue(GstSmbSrc * src,GstBuffer** outdata) {
    U32 data_len = 0;
    GST_ERROR_OBJECT(src,"in");
    GST_SMB_SRC_DATA_QUEUE_LOCK(src);
    while(g_queue_is_empty (src->queue) && src->ret == GST_FLOW_OK)
    {
        GST_SMB_SRC_DATA_QUEUE_COND_WAIT(src);
    }
    if(!src->stoped && !src->is_seek && src->ret == GST_FLOW_OK)
    {
        GstBuffer *buf = g_queue_pop_head (src->queue);
        if(buf)
        {
            *outdata = buf;
            data_len = gst_buffer_get_size(*outdata);
            src->consume_len += data_len;
        }
    }

    GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
    GST_ERROR_OBJECT(src,"out");
}
static void gst_smb_src_clear_queue(GstSmbSrc * src) {
    GstBuffer* tmp = NULL;
    GST_ERROR_OBJECT(src,"in");
    GST_SMB_SRC_DATA_QUEUE_LOCK(src);
    while ((tmp = g_queue_pop_head (src->queue))) {
        gst_buffer_unref (tmp);
        tmp = NULL;
    }
    GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
    GST_ERROR_OBJECT(src,"out");
}

static void gst_smb_src_clear_backup_queue(GstSmbSrc * src)
{
    GstBuffer* tmp = NULL;
    GST_ERROR_OBJECT(src,"in");
    GST_SMB_SRC_DATA_BACKUP_QUEUE_LOCK(src);
    while ((tmp = g_queue_pop_head (src->backup_queue))) {
        gst_buffer_unref (tmp);
        tmp = NULL;
    }
    GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
    GST_ERROR_OBJECT(src,"out");
}

static GstFlowReturn gst_smb_src_fill_from_backup (GstSmbSrc * src, guint64 offset,
                                                                guint length, GstBuffer * buf) {

    guint to_read = length;
    guint bytes_read = 0;
    GstMapInfo dist_info;
    guint8 *dist_data = NULL;
    GstBuffer *src_buffer = NULL;
    GstMapInfo src_info;
    guint8 *src_data = NULL;
    guint64 buffer_offset = 0;

    GST_SMB_SRC_DATA_BACKUP_QUEUE_LOCK(src);
    if (!src->backup_queue) {
        GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
        return GST_FLOW_ERROR;
    }

    if (offset < src->backup_consume_len || offset >= src->backup_download_len ||
        offset + length > src->backup_download_len) {
        GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
        return GST_FLOW_ERROR;
    }

    GST_INFO_OBJECT(src, "offset = %"PRId64", backup_consume_len = %"PRId64", backup_download_len = %"PRId64", length = %d",
                           offset, src->backup_consume_len, src->backup_download_len, length);
    if (!gst_buffer_map (buf, &dist_info, GST_MAP_WRITE)) {
        GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
        return GST_FLOW_ERROR;
    }
    dist_data = dist_info.data;

    buffer_offset = src->backup_consume_len;
    U32 index = 0;
    for (index = 0; index < g_queue_get_length(src->backup_queue); index ++) {
        src_buffer = g_queue_peek_nth(src->backup_queue, index);

        U32 buff_len = gst_buffer_get_size(src_buffer);
        GST_DEBUG_OBJECT(src, "buffer_offset = %"PRId64", buff_len = %d, offset = %"PRId64", bytes_read = %d", buffer_offset, buff_len, offset, bytes_read);
        if (buffer_offset + buff_len <= offset + bytes_read) { //offset 不在 buffer中，跳过该buffer
            buffer_offset = buffer_offset + buff_len;
        } else { // offset 在buffer中。
            U32 drop_len = 0;
            if (bytes_read == 0 && buffer_offset < offset) { //第一个buffer，要把offset之前数据忽略
                drop_len = offset - buffer_offset;
                GST_INFO_OBJECT(src, "drop_len = %d", drop_len);
                buff_len = gst_buffer_get_size(src_buffer) - drop_len;
            }
            if (buff_len <= to_read) { // buffer 的长度小于要被读取的长度，把整个buffer读完
                if (!gst_buffer_map (src_buffer, &src_info, GST_MAP_READ)) {
                    GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
                    GST_INFO_OBJECT(src, "goto read_end");
                    goto read_end;
                }
                src_data = src_info.data;

                memcpy(dist_data + bytes_read, src_data + drop_len, buff_len);
                to_read = to_read - buff_len;
                bytes_read = bytes_read + buff_len ;
                gst_buffer_unmap (src_buffer, &src_info);
                if (bytes_read == length) {
                    GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
                    GST_INFO_OBJECT(src, "goto read_end");
                    goto read_end;
                }
            } else { // buffer 的长度大于要被读取的长度，
                if (!gst_buffer_map (src_buffer, &src_info, GST_MAP_READ)) {
                    GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
                    GST_INFO_OBJECT(src, "goto read_end");
                    goto read_end;
                }
                src_data = src_info.data;

                memcpy(dist_data + bytes_read, src_data + drop_len, to_read);
                bytes_read = bytes_read + to_read;
                gst_buffer_unmap (src_buffer, &src_info);
                to_read = 0;
                GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
                GST_INFO_OBJECT(src, "goto read_end");
                goto read_end;
            }
            buffer_offset = buffer_offset + gst_buffer_get_size(src_buffer);
        }
    }
    GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
read_end:
    {
        gst_buffer_unmap (buf, &dist_info);
        if (bytes_read != length) {
            return GST_FLOW_ERROR;
        }
        GST_BUFFER_OFFSET (buf) = offset;
        GST_BUFFER_OFFSET_END (buf) = offset + bytes_read;

        return GST_FLOW_OK;
    }

}

/***
 * read code below
 * that is to say, you shouldn't read the code below, but the code that reads
 * stuff is below.  Well, you shouldn't not read the code below, feel free
 * to read it of course.  It's just that "read code below" is a pretty crappy
 * documentation string because it sounds like we're expecting you to read
 * the code to understand what it does, which, while true, is really not
 * the sort of attitude we want to be advertising.  No sir.
 *
 */
 #if 0
static GstFlowReturn
gst_smb_src_fill (GstBaseSrc * basesrc, guint64 offset, guint length,
    GstBuffer * buf)
{
  GstSmbSrc *src;
  guint to_read, bytes_read, read_size;
  int ret = 0;
  GstMapInfo info;
  guint8 *data;
  int retry = 10;

  src = GST_SMB_SRC_CAST (basesrc);
  GST_DEBUG_OBJECT (src, "Reading %d  offset:%"PRId64", read_pos:%"PRId64"", length, offset, src->read_position);
  if (G_UNLIKELY (offset != -1 && src->read_position != offset)) {
    off_t res = 0;
    res = libsmbc_lseek(src->fd, offset, SEEK_SET);
    if (G_UNLIKELY (res < 0 || res != (offset +src->start_offset)))
      goto seek_failed;

    src->read_position = offset;
  }

  if (!gst_buffer_map (buf, &info, GST_MAP_WRITE))
    goto buffer_write_fail;
  data = info.data;

  bytes_read = 0;
  to_read = length;
  if (src->last_read_time == 0) {
    src->last_read_time = gst_get_running_time();
  }
  while (to_read > 0) {
    read_size = length - bytes_read;

    if (read_size == 0)
    {
        break;
    }
    if (read_size > MAX_READ_BUFSIZE)
    {
        read_size = MAX_READ_BUFSIZE;
    }
    GST_DEBUG_OBJECT (src, "to read total length:%u, bytes_read:%d, read_size:%d", length, bytes_read, read_size);
    ret = libsmbc_read(src->fd, data + bytes_read, read_size);

    if (G_UNLIKELY (ret < 0)) {
      usleep(1000);
      GST_ERROR_OBJECT (src, "retry %d  offset:%"PRId64", read_pos:%"PRId64" ", retry, offset, offset+bytes_read);
      if(retry > 0) {
          //GST_ERROR_OBJECT (src, "retry %d  offset:%"PRId64", read_pos:%"PRId64" ", retry, offset, offset+bytes_read);
          src->fd = libsmbc_retry_open_and_seek(src->fd, offset+bytes_read, src->url);
          retry--;
          continue;
      }
        goto could_not_read;
      }

    /* files should eos if they read 0 and more was requested */
    if (G_UNLIKELY (ret == 0)) {
      /* .. but first we should return any remaining data */
      if (bytes_read > 0)
        break;
      goto eos;
    }

    to_read -= ret;
    bytes_read += ret;

    src->read_position += ret;
    if (bytes_read >= length) {
      break;
    }
  }
  GST_DEBUG_OBJECT (src, "to read total length:%u, bytes_read:%d", length, bytes_read);
  uint64_t cur_time = gst_get_running_time();
  src->last_read_size += bytes_read;
  if (src->last_read_time > 0 && (cur_time - src->last_read_time) > 1000) {
    UNILOGI ("download %"PRIu64" bytes use %"PRId64" ms, file_offset: %"PRId64"", src->last_read_size, cur_time - src->last_read_time, offset + bytes_read);
    src->last_read_size = 0;
    src->last_read_time = cur_time;
  }
  gst_buffer_unmap (buf, &info);
  if (bytes_read != length)
    gst_buffer_resize (buf, 0, bytes_read);

  GST_BUFFER_OFFSET (buf) = offset;
  GST_BUFFER_OFFSET_END (buf) = offset + bytes_read;

  return GST_FLOW_OK;

  /* ERROR */
seek_failed:
  {
    GST_ELEMENT_ERROR (src, RESOURCE, READ, (NULL), GST_ERROR_SYSTEM);
    return GST_FLOW_ERROR;
  }
could_not_read:
  {
    GST_ELEMENT_ERROR (src, RESOURCE, READ, (NULL), GST_ERROR_SYSTEM);
    gst_buffer_unmap (buf, &info);
    gst_buffer_resize (buf, 0, 0);
    return GST_FLOW_ERROR;
  }
eos:
  {
    GST_DEBUG ("EOS");
    gst_buffer_unmap (buf, &info);
    gst_buffer_resize (buf, 0, 0);
    return GST_FLOW_EOS;
  }
buffer_write_fail:
  {
    GST_ELEMENT_ERROR (src, RESOURCE, WRITE, (NULL), ("Can't write to buffer"));
    return GST_FLOW_ERROR;
  }
}
#endif

static gboolean gst_smb_src_do_seek (GstSmbSrc *src, guint64 offset) {
  gint64 res;

  GST_ERROR_OBJECT(src,"enter  offset: %"PRIu64", cur_ %"PRId64"",offset, src->read_position);

  /* No need to seek to the current position */
  if (offset == src->read_position)
    return TRUE;

  res = libsmbc_lseek(src->fd, offset, SEEK_SET);
  if (G_UNLIKELY (res < 0 || res != offset))
    goto seek_failed;

  src->read_position = offset;
  gst_smb_src_clear_queue(src);
  src->consume_len = offset;
  src->queue_len = offset;
  src->download_len = offset;
  return TRUE;

seek_failed:
  GST_ERROR_OBJECT (src, "lseek returned offset:%"PRIu64" %"PRId64"", offset, res);
  return FALSE;
}

static GstFlowReturn gst_smb_src_fill (GstBaseSrc * bsrc, guint64 offset,
                                                    guint length, GstBuffer * buf) {

    GstSmbSrc *src = NULL;
    GstFlowReturn ret = GST_FLOW_OK;
    guint to_read = length;
    guint bytes_read = 0;
    GstMapInfo dist_info;
    guint8 *dist_data = NULL;
    GstBuffer *src_buffer = NULL;
    GstMapInfo src_info;
    guint8 *src_data = NULL;
    guint64 buffer_offset = 0;
    GstBuffer *data = NULL;

    src = GST_SMB_SRC_CAST(bsrc);

    if (src->ret == GST_FLOW_CUSTOM_SUCCESS) {
        goto buffer_write_fail;
    }

    if(src->read_err) goto buffer_write_fail;

    if (src->use_backup) {
        ret = gst_smb_src_fill_from_backup(src, offset, length, buf);
        if (ret == GST_FLOW_OK) {
            src->fill_queue_times = 0;
            return ret;
        }
    }

    if (!gst_buffer_map (buf, &dist_info, GST_MAP_WRITE)) {
        goto buffer_write_fail;
    }
    dist_data = dist_info.data;

    GST_SMB_SRC_DATA_QUEUE_LOCK(src);
    GST_DEBUG_OBJECT(src, "strat offset = %"PRId64", consume_len = %"PRId64", download_len = %"PRId64", queue_len = %"PRId64",length = %d",
                           offset, src->consume_len, src->download_len, src->queue_len, length);
    if (offset < src->consume_len || offset > src->download_len + MSG_QUEUE_MAX_SIZE / 4) {
        if (src->use_backup) {
            gst_smb_src_clear_backup_queue(src);
            GST_SMB_SRC_DATA_BACKUP_QUEUE_LOCK(src);
            if (src->backup_queue) {
                g_queue_free(src->backup_queue);
            }
            src->backup_queue = src->queue;
            src->backup_consume_len = src->consume_len;
            src->backup_download_len = src->queue_len;
            GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
            src->queue = g_queue_new ();
        }
        GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
        GST_INFO("call gst_http_pull_src_do_seek");
        src->is_seek = TRUE;
        src->seek_start_pos = offset;
        while(src->is_seek && !src->cancel_download && src->downloadloopRun == TRUE)
        {
            UNILOGI("wait src->is_seek offset:%"PRId64"", offset);
            usleep(1000);
        }
        src->fill_queue_times = 0;
    } else {
        src->fill_queue_times ++;
        if (src->fill_queue_times > 100 && src->backup_queue) {
            //连续100次都是直接queue里面去读数据，backup queue可以清掉释放内存
            gst_smb_src_clear_backup_queue(src);
            GST_SMB_SRC_DATA_BACKUP_QUEUE_LOCK(src);
            if (src->backup_queue) {
                g_queue_free(src->backup_queue);
                src->backup_queue = NULL;
            }
            GST_SMB_SRC_DATA_BACKUP_QUEUE_UNLOCK(src);
            src->fill_queue_times = 0;
        }
        GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
    }

    GST_SMB_SRC_DATA_QUEUE_LOCK(src);
    while ((src_buffer = g_queue_peek_head (src->queue))) {
        U32 len = gst_buffer_get_size(src_buffer);
        if (len + src->consume_len + MSG_QUEUE_MAX_SIZE / 4 < offset) { // offset 之前的10数据清掉
            src_buffer = g_queue_pop_head (src->queue);
            gst_buffer_unref (src_buffer);
            src_buffer = NULL;
            src->consume_len = src->consume_len + len;
        } else {
            break;
        }
    }
    buffer_offset = src->consume_len;
    U32 index = 0;
    U32 guess_index = 0;
    U32 queue_length = g_queue_get_length(src->queue);
    if (queue_length > 1) {
        guint64 data_offset = offset - src->consume_len - SMB_DEFAULT_BLOCKSIZE;
        if (offset > src->consume_len && offset < src->download_len && data_offset > 0) {
            guess_index = data_offset / SMB_DEFAULT_BLOCKSIZE;
            if (guess_index > 0 && guess_index < queue_length){
                data = g_queue_peek_nth(src->queue, guess_index);
                guint64 buffer_start = GST_BUFFER_OFFSET (data);
                guint64 buffer_end = GST_BUFFER_OFFSET_END (data);
                //GST_INFO_OBJECT(src, "guesss OK index = %d, buffer_start:%"PRId64" buffer_end:%"PRId64"", guess_index, buffer_start,buffer_end);
                if ((buffer_start <= offset && offset < buffer_end) || offset >= buffer_end) {
                    index = guess_index;
                    buffer_offset = buffer_start;
                    GST_INFO_OBJECT(src, "guesss OK, index = %d, buffer_start:%"PRId64"", index, buffer_offset);
                }
            }
        } else if (offset > src->download_len) {
            data = g_queue_peek_nth(src->queue, queue_length - 1);
            if (data) {
                buffer_offset = GST_BUFFER_OFFSET (data);
                index = queue_length - 1;
            }
        }
    }

    GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
need_more_buff:
    {
        if (src->ret == GST_FLOW_CUSTOM_SUCCESS || src->read_err) {
            gst_buffer_unmap (buf, &dist_info);
            goto buffer_write_fail;
        }

        if (src->cancel_download) {
            GST_WARNING_OBJECT(src, "goto eos");
            goto eos;
        }
        GST_SMB_SRC_DATA_QUEUE_LOCK(src);

        for (;index < g_queue_get_length(src->queue); index ++) {
            src_buffer = g_queue_peek_nth(src->queue, index);
            //if (GST_BUFFER_RESERVERD1(src_buffer) == TRUE) {
               // GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
               // GST_WARNING_OBJECT(src, "goto eos");
               // goto eos;
           // }

            U32 buff_len = gst_buffer_get_size(src_buffer);
            GST_DEBUG_OBJECT(src, "buffer_offset = %"PRId64", buff_len = %d, offset = %"PRId64", bytes_read = %d", buffer_offset, buff_len, offset, bytes_read);
            if (buffer_offset + buff_len <= offset + bytes_read) { //offset 不在 buffer中，跳过该buffer
                buffer_offset = buffer_offset + buff_len;
            } else { // offset 在buffer中。
                U32 drop_len = 0;
                if (bytes_read == 0 && buffer_offset < offset) { //第一个buffer，要把offset之前数据忽略
                    drop_len = offset - buffer_offset;
                    GST_INFO_OBJECT(src, "drop_len = %d", drop_len);
                    buff_len = gst_buffer_get_size(src_buffer) - drop_len;
                }
                if (buff_len <= to_read) { // buffer 的长度小于要被读取的长度，把整个buffer读完
                    if (!gst_buffer_map (src_buffer, &src_info, GST_MAP_READ)) {
                        GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
                        GST_INFO_OBJECT(src, "goto read_end");
                        goto read_end;
                    }
                    src_data = src_info.data;

                    memcpy(dist_data + bytes_read, src_data + drop_len, buff_len);
                    to_read = to_read - buff_len;
                    bytes_read = bytes_read + buff_len ;
                    gst_buffer_unmap (src_buffer, &src_info);
                    if (bytes_read == length) {
                        GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
                        GST_INFO_OBJECT(src, "goto read_end bytes_read:%d", bytes_read);
                        goto read_end;
                    }
                } else { // buffer 的长度大于要被读取的长度，
                    if (!gst_buffer_map (src_buffer, &src_info, GST_MAP_READ)) {
                        GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
                        GST_INFO_OBJECT(src, "goto read_end bytes_read:%d", bytes_read);
                        goto read_end;
                    }
                    src_data = src_info.data;

                    memcpy(dist_data + bytes_read, src_data + drop_len, to_read);
                    bytes_read = bytes_read + to_read;
                    gst_buffer_unmap (src_buffer, &src_info);
                    to_read = 0;
                    GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
                    GST_INFO_OBJECT(src, "goto read_end bytes_read:%d", bytes_read);
                    goto read_end;
                }
                buffer_offset = buffer_offset + gst_buffer_get_size(src_buffer);
            }
        }
    }

    if ((bytes_read + offset) == src->length) {
        GST_WARNING_OBJECT(src, "goto eos, bytes_read:%d,offset:%"PRId64",file length:%"PRId64"", bytes_read, offset, src->length);
        GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
        goto eos;
    }
    if (bytes_read < length && !src->cancel_download && !src->read_err) {
        GST_SMB_SRC_DATA_QUEUE_COND_WAIT(src);
        GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
        GST_INFO_OBJECT(src, "goto need_more_buff");
        goto need_more_buff;
    } else {
        GST_SMB_SRC_DATA_QUEUE_UNLOCK(src);
    }
read_end:
    {
        gst_buffer_unmap (buf, &dist_info);
        if (bytes_read != length)
            gst_buffer_resize (buf, 0, bytes_read);

        GST_BUFFER_OFFSET (buf) = offset;
        GST_BUFFER_OFFSET_END (buf) = offset + bytes_read;

        return GST_FLOW_OK;
    }
eos:
    {
        gst_buffer_unmap (buf, &dist_info);
        if (bytes_read != length)
            gst_buffer_resize (buf, 0, bytes_read);

        GST_BUFFER_OFFSET (buf) = offset;
        GST_BUFFER_OFFSET_END (buf) = offset + bytes_read;

        return GST_FLOW_EOS;
    }

buffer_write_fail:
    {
        GST_ELEMENT_ERROR (src, RESOURCE, WRITE, (NULL), ("Can't write to buffer"));
        return GST_FLOW_ERROR;
    }
}

static gboolean
gst_smb_src_is_seekable (GstBaseSrc * basesrc)
{
  //GstSmbSrc *src = GST_SMB_SRC (basesrc);

  return TRUE;
}

static gboolean
gst_smb_src_get_size (GstBaseSrc * basesrc, guint64 * size)
{
  GstSmbSrc *src = GST_SMB_SRC (basesrc);
  if (!src->seekable) {
    /* If it isn't seekable, we won't know the length (but fstat will still
     * succeed, and wrongly say our length is zero. */
    return FALSE;
  }

  if (src->length <= 0)
  {
     return FALSE;
  }
  *size = src->length;

  GST_INFO_OBJECT(src, "*size=%"PRId64"", *size);

  return TRUE;
}

/* open the file, necessary to go to READY state */
static gboolean
gst_smb_src_start (GstBaseSrc * basesrc)
{
  GError *err = NULL;
  GstMessage *msg = NULL;

  UNILOGI("[in]");
  GstSmbSrc *src = GST_SMB_SRC (basesrc);
  if (src->cancel_download) {
    GST_WARNING_OBJECT(src, "src->cancel_download is true, so return");
    return TRUE;
  }

  if (src->read_err) {
    GST_WARNING_OBJECT(src, "src->read_err is true, so return");
    return TRUE;
  }

  if (src->url)
    GST_ERROR_OBJECT (src, "opening file %s", src->url);

  if (src->smb_ctx == NULL) {
    src->smb_ctx = libsmbc_new_ctx();
    if (src->smb_ctx == NULL) {
      UNILOGI("Smb_New_Ctx fail");
      return FALSE;
    }
  }

  if (src->fd <= 0) {
    src->fd = libsmbc_open(src->url, O_RDONLY, 0666);
    if (src->fd < 0) {
      src->read_err = TRUE;
      goto error;
    }
  }

  if (src->length <= 0) {
    int64_t file_size = libsmbc_getsize(src->fd);
    basesrc->segment.duration = src->length = file_size;
  }
  if(src->length <= 0) {
    goto error;
  }
  src->downloadloopRun = TRUE;
  src->stoped = FALSE;
  UNILOGI("task state = %d", GST_TASK_STATE(src->download_task));

  if(GST_TASK_STATE(src->download_task) != GST_TASK_STARTED)
  {
      GST_TASK_SIGNAL(src->download_task);
      UNILOGI("start doenload task");
      gst_task_start(src->download_task);
  }

  gst_element_post_message(GST_ELEMENT(src), gst_message_new_duration_changed(GST_OBJECT(src)));
  gst_element_post_message(GST_ELEMENT(src), gst_message_new_custom(GST_MESSAGE_MSG_DOWNLOAD_BEGIN, GST_OBJECT(src), NULL));

  UNILOGI("[out] fd %d read_position %"PRId64", duration:%"PRId64"", src->fd, src->read_position, src->length);
  return TRUE;

error:
  err = g_error_new (GST_RESOURCE_ERROR, GST_RESOURCE_ERROR_OPEN_READ, "Failed to init or open smb client");
  msg = gst_message_new_error (GST_OBJECT_CAST (src), err, "smb url invalid or open failed");
  gst_element_post_message (GST_ELEMENT_CAST (src), msg);
  g_error_free (err);
  UNILOGI("[out] error close");
  return FALSE;
}

static void gst_smb_src_download_pause(GstSmbSrc * src)
{
   UNILOGI("[in]");
   if(GST_TASK_STATE(src->download_task) != GST_TASK_STOPPED)
   {
      GST_TASK_SIGNAL(src->download_task);
      gst_task_pause(src->download_task);
   }
   UNILOGI("[out]");
}

/* unmap and close the file */
static gboolean
gst_smb_src_stop (GstBaseSrc * basesrc)
{
  UNILOGI("[in]");
  GstSmbSrc *src = GST_SMB_SRC (basesrc);
  src->stoped = TRUE;
  gst_smb_src_download_pause(src);
  UNILOGI("task state = %d", GST_TASK_STATE(src->download_task));
  UNILOGI("[out]");
  return TRUE;
}

/*** GSTURIHANDLER INTERFACE *************************************************/

static guint
gst_smb_src_uri_get_type (GType type)
{
    return GST_URI_SRC;
}

static const gchar *const *
gst_smb_src_uri_get_protocols (GType type)
{
    UNILOGI("gst_smb_src_uri_get_protocols");
    static const gchar *protocols[] = {"smb", "samba", NULL };

    return protocols;
}

static gchar *
gst_smb_src_uri_get_uri (GstURIHandler * handler)
{
    GstSmbSrc *src = GST_SMB_SRC (handler);

    /* FIXME: make thread-safe */
    return g_strdup (src->url);
}

static gboolean
gst_smb_src_uri_set_uri (GstURIHandler * handler, const gchar * uri,
    GError ** error)
{
    GstSmbSrc *src = GST_SMB_SRC (handler);
    UNILOGI("gst_smb_src_uri_get_protocols url %s",uri);
    if (src->url) {
        g_free(src->url);
        src->url = NULL;
    }

    if (uri == NULL)
        return FALSE;

    char user[128] = {0}; // 初始化数组以避免未定义的内容
    char password[128] = {0}; // 初始化数组以避免未定义的内容
    char* result = NULL;
    result = libsmbc_extract_userinfo(uri, user, sizeof(user), password, sizeof(password));
    if (src->username) {
        g_free(src->username);
        src->username = NULL;
    }
    if (src->password) {
        g_free(src->password);
        src->password = NULL;
    }
    if (result) {
        GST_DEBUG_OBJECT(src, "U: %s", user);
        GST_DEBUG_OBJECT(src, "P: %s", password);
        src->username = g_strdup (user);
        src->password = g_strdup (password);
    } else {
        src->username = g_strdup ("guest");
        src->url = g_strdup (uri);
        libsmbc_set_credential(src->url, src->username, src->password);
        GST_ERROR_OBJECT(src, "guest mode, No password");
        return TRUE;
    }
    // 构造新的URL（不包括用户名和密码）
    src->url = libsmbc_construct_new_url(uri);
    if (src->url == NULL) {
        return FALSE;
    }
    libsmbc_set_credential(src->url, src->username, src->password);
    GST_INFO_OBJECT(src, "new url: %s",src->url);

    return TRUE;
}

static void
gst_smb_src_uri_handler_init (gpointer g_iface, gpointer iface_data)
{
  GstURIHandlerInterface *iface = (GstURIHandlerInterface *) g_iface;

  iface->get_type = gst_smb_src_uri_get_type;
  iface->get_protocols = gst_smb_src_uri_get_protocols;
  iface->get_uri = gst_smb_src_uri_get_uri;
  iface->set_uri = gst_smb_src_uri_set_uri;
}

static gboolean
plugin_init (GstPlugin * plugin)
{
    gst_element_register (plugin, "smbsrc", GST_RANK_PRIMARY + 1,
        GST_TYPE_SMB_SRC);
    GST_DEBUG_CATEGORY_INIT (smb_src_debug, "smbsrc", 0, "Smb src");

    return TRUE;
}

#define PACKAGE "gstreamer"

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    smbsrc,
    "smb client src/sink",
    plugin_init,
    "1.0",
    "GPL",
    "GStreamer",
    "http://gstreamer.net/")

