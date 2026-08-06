/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "channels/cliprdr.h"
#include "client.h"
#include "common/clipboard.h"
#include "common/iconv.h"
#include "config.h"
#include "plugins/channels.h"
#include "rdp.h"

#include <freerdp/client/cliprdr.h>
#include <freerdp/channels/cliprdr.h>
#include <freerdp/event.h>
#include <freerdp/freerdp.h>
#include <guacamole/client.h>
#include <guacamole/mem.h>
#include <guacamole/protocol.h>
#include <guacamole/socket.h>
#include <guacamole/stream.h>
#include <guacamole/string.h>
#include <guacamole/user.h>
#include <winpr/wtsapi.h>
#include <winpr/wtypes.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef FREERDP_CLIPRDR_CALLBACKS_REQUIRE_CONST
/**
 * FreeRDP 2.0.0-rc4 and newer requires the final argument for all CLIPRDR
 * callbacks to be const.
 */
#define CLIPRDR_CONST const
#else
/**
 * FreeRDP 2.0.0-rc3 and older requires the final argument for all CLIPRDR
 * callbacks to NOT be const.
 */
#define CLIPRDR_CONST
#endif

/**
 * Sends a Format List PDU to the RDP server containing the formats of
 * clipboard data supported. This PDU is used both to indicate the general
 * clipboard formats supported at the begining of an RDP session and to inform
 * the RDP server that new clipboard data is available within the listed
 * formats.
 *
 * @param cliprdr
 *     The CliprdrClientContext structure used by FreeRDP to handle the
 *     CLIPRDR channel for the current RDP session.
 *
 * @return
 *     CHANNEL_RC_OK (zero) if the Format List PDU was sent successfully, an
 *     error code (non-zero) otherwise.
 */
static UINT guac_rdp_cliprdr_send_format_list(CliprdrClientContext* cliprdr) {

    /* This function is only invoked within FreeRDP-specific handlers for
     * CLIPRDR, which are not assigned, and thus not callable, until after the
     * relevant guac_rdp_clipboard structure is allocated and associated with
     * the CliprdrClientContext */
    guac_rdp_clipboard* clipboard = (guac_rdp_clipboard*) cliprdr->custom;
    assert(clipboard != NULL);

    guac_client* client = clipboard->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;

    /* We support CP-1252 and UTF-16 text */
    CLIPRDR_FORMAT_LIST format_list = {
#ifdef HAVE_CLIPRDR_HEADER
        .common = {
            .msgType = CB_FORMAT_LIST
        },
#else
        .msgType = CB_FORMAT_LIST,
#endif
        .formats = (CLIPRDR_FORMAT[]) {
            { .formatId = CF_TEXT },
            { .formatId = CF_UNICODETEXT }
        },
        .numFormats = 2
    };

    guac_client_log(client, GUAC_LOG_TRACE, "CLIPRDR: Sending format list");

    pthread_mutex_lock(&(rdp_client->message_lock));
    int retval = cliprdr->ClientFormatList(cliprdr, &format_list);
    pthread_mutex_unlock(&(rdp_client->message_lock));
    return retval;

}

/**
 * Sends a Clipboard Capabilities PDU to the RDP server describing the features
 * of the CLIPRDR channel that are supported by the client.
 *
 * @param cliprdr
 *     The CliprdrClientContext structure used by FreeRDP to handle the
 *     CLIPRDR channel for the current RDP session.
 *
 * @return
 *     CHANNEL_RC_OK (zero) if the Clipboard Capabilities PDU was sent
 *     successfully, an error code (non-zero) otherwise.
 */
static UINT guac_rdp_cliprdr_send_capabilities(CliprdrClientContext* cliprdr) {

    /* This function is only invoked within FreeRDP-specific handlers for
     * CLIPRDR, which are not assigned, and thus not callable, until after the
     * relevant guac_rdp_clipboard structure is allocated and associated with
     * the CliprdrClientContext */
    guac_rdp_clipboard* clipboard = (guac_rdp_clipboard*) cliprdr->custom;
    assert(clipboard != NULL);

    guac_client* client = clipboard->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;

    /* We support CP-1252 and UTF-16 text */
    CLIPRDR_GENERAL_CAPABILITY_SET cap_set = {
        .capabilitySetType = CB_CAPSTYPE_GENERAL, /* CLIPRDR specification requires that this is CB_CAPSTYPE_GENERAL, the only defined set type */
        .capabilitySetLength = 12, /* The size of the capability set within the PDU - for CB_CAPSTYPE_GENERAL, this is ALWAYS 12 bytes */
        .version = CB_CAPS_VERSION_2, /* The version of the CLIPRDR specification supported */
        .generalFlags = CB_USE_LONG_FORMAT_NAMES | CB_STREAM_FILECLIP_ENABLED | CB_FILECLIP_NO_FILE_PATHS /* Bitwise OR of all supported feature flags */
    };

    CLIPRDR_CAPABILITIES caps = {
        .cCapabilitiesSets = 1,
        .capabilitySets = (CLIPRDR_CAPABILITY_SET*) &cap_set
    };

    pthread_mutex_lock(&(rdp_client->message_lock));
    int retval = cliprdr->ClientCapabilities(cliprdr, &caps);
    pthread_mutex_unlock(&(rdp_client->message_lock));

    return retval;

}

/**
 * Callback invoked by the FreeRDP CLIPRDR plugin for received Monitor Ready
 * PDUs. The Monitor Ready PDU is sent by the RDP server only during
 * initialization of the CLIPRDR channel. It is part of the CLIPRDR channel
 * handshake and indicates that the RDP server's handling of clipboard
 * redirection is ready to proceed.
 *
 * @param cliprdr
 *     The CliprdrClientContext structure used by FreeRDP to handle the CLIPRDR
 *     channel for the current RDP session.
 *
 * @param monitor_ready
 *     The CLIPRDR_MONITOR_READY structure representing the Monitor Ready PDU
 *     that was received.
 *
 * @return
 *     CHANNEL_RC_OK (zero) if the PDU was handled successfully, an error code
 *     (non-zero) otherwise.
 */
static UINT guac_rdp_cliprdr_monitor_ready(CliprdrClientContext* cliprdr,
        CLIPRDR_CONST CLIPRDR_MONITOR_READY* monitor_ready) {

    /* FreeRDP-specific handlers for CLIPRDR are not assigned, and thus not
     * callable, until after the relevant guac_rdp_clipboard structure is
     * allocated and associated with the CliprdrClientContext */
    guac_rdp_clipboard* clipboard = (guac_rdp_clipboard*) cliprdr->custom;
    assert(clipboard != NULL);

    guac_client_log(clipboard->client, GUAC_LOG_TRACE, "CLIPRDR: Received "
            "monitor ready.");

    /* Respond with capabilities ... */
    int status = guac_rdp_cliprdr_send_capabilities(cliprdr);
    if (status != CHANNEL_RC_OK)
        return status;

    /* ... and supported format list */
    return guac_rdp_cliprdr_send_format_list(cliprdr);

}

/**
 * Sends a Format Data Request PDU to the RDP server, requesting that available
 * clipboard data be sent to the client in the specified format. This PDU is
 * sent when the server indicates that clipboard data is available via a Format
 * List PDU.
 *
 * @param client
 *     The guac_client associated with the current RDP session.
 *
 * @param format
 *     The clipboard format to request. This format must be one of the
 *     documented values used by the CLIPRDR channel for clipboard format IDs.
 *
 * @return
 *     CHANNEL_RC_OK (zero) if the PDU was handled successfully, an error code
 *     (non-zero) otherwise.
 */
static UINT guac_rdp_cliprdr_send_format_data_request(
        CliprdrClientContext* cliprdr, UINT32 format) {

    /* FreeRDP-specific handlers for CLIPRDR are not assigned, and thus not
     * callable, until after the relevant guac_rdp_clipboard structure is
     * allocated and associated with the CliprdrClientContext */
    guac_rdp_clipboard* clipboard = (guac_rdp_clipboard*) cliprdr->custom;
    assert(clipboard != NULL);

    guac_client* client = clipboard->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;

    /* Create new data request */
    CLIPRDR_FORMAT_DATA_REQUEST data_request = {
        .requestedFormatId = format
    };

    /* Note the format we've requested for reference later when the requested
     * data is received via a Format Data Response PDU */
    clipboard->requested_format = format;

    guac_client_log(client, GUAC_LOG_TRACE, "CLIPRDR: Sending format data request.");

    /* Send request */
    pthread_mutex_lock(&(rdp_client->message_lock));
    int retval = cliprdr->ClientFormatDataRequest(cliprdr, &data_request);
    pthread_mutex_unlock(&(rdp_client->message_lock));

    return retval;

}

/**
 * Returns whether the given Format List PDU indicates support for the given
 * clipboard format.
 *
 * @param format_list
 *     The CLIPRDR_FORMAT_LIST structure representing the Format List PDU
 *     being tested.
 *
 * @param format_id
 *     The ID of the clipboard format to test, such as CF_TEXT or
 *     CF_UNICODETEXT.
 *
 * @return
 *     Non-zero if the given Format List PDU indicates support for the given
 *     clipboard format, zero otherwise.
 */
static int guac_rdp_cliprdr_format_supported(const CLIPRDR_FORMAT_LIST* format_list,
        UINT format_id) {

    /* Search format list for matching ID */
    for (int i = 0; i < format_list->numFormats; i++) {
        if (format_list->formats[i].formatId == format_id)
            return 1;
    }

    /* If no matching ID, format is not supported */
    return 0;

}

typedef struct guac_rdp_clipboard_download {
    int fd;
    uint64_t offset;
    uint64_t size;
    char path[PATH_MAX];
} guac_rdp_clipboard_download;

static void sanitize_filename(char* filename) {
    char safe[GUAC_RDP_CLIPBOARD_MAX_FILENAME];
    size_t length = 0;
    const unsigned char* input = (const unsigned char*) filename;
    while (*input != '\0' && length < sizeof(safe) - 1) {
        unsigned char c = *(input++);
        if (c < 0x20 || c == 0x7F || c == '/' || c == '\\' || c == ':')
            c = '_';
        safe[length++] = (char) c;
    }
    safe[length] = '\0';
    if (length == 0 || !strcmp(safe, ".") || !strcmp(safe, ".."))
        guac_strlcpy(safe, "clipboard-file.bin", sizeof(safe));
    guac_strlcpy(filename, safe, GUAC_RDP_CLIPBOARD_MAX_FILENAME);
}

static int filename_from_descriptor(const FILEDESCRIPTORW* descriptor,
        char* filename, size_t filename_size) {
    size_t characters = 0;
    WCHAR descriptor_filename[261] = { 0 };
    while (characters < 260 && descriptor->cFileName[characters] != 0)
        characters++;
     if (!characters || filename_size < 2)
        return 0;
    memcpy(descriptor_filename, descriptor->cFileName,
            characters * sizeof(WCHAR));
    descriptor_filename[characters] = 0;
    const char* input = (const char*) descriptor_filename;
    char* output = filename;
    if (!guac_iconv(GUAC_READ_UTF16, &input,
            (int) ((characters + 1) * sizeof(WCHAR)), GUAC_WRITE_UTF8,
            &output, (int) filename_size - 1))
        return 0;
    *output = '\0';
    sanitize_filename(filename);
    return filename[0] != '\0';
}

static void cleanup_clipboard_file(guac_rdp_clipboard* clipboard) {
    if (clipboard->file_fd >= 0) {
        close(clipboard->file_fd);
        clipboard->file_fd = -1;
    }
    if (clipboard->file_path[0] != '\0') {
        unlink(clipboard->file_path);
        clipboard->file_path[0] = '\0';
    }
    clipboard->requested_file_descriptor = 0;
    clipboard->file_active = 0;
    clipboard->file_waiting_for_size = 0;
    clipboard->file_size_known = 0;
    clipboard->file_download_active = 0;
    clipboard->file_stream_id = 0;
    clipboard->file_list_index = 0;
    clipboard->file_requested_bytes = 0;
    clipboard->file_size = 0;
    clipboard->file_received = 0;
    clipboard->file_name[0] = '\0';
}

static int write_clipboard_at(int fd, const BYTE* data, size_t length,
        uint64_t offset) {
    size_t written = 0;
    while (written < length) {
        ssize_t result = pwrite(fd, data + written, length - written,
                (off_t) (offset + written));
        if (result <= 0)
            return 0;
        written += (size_t) result;
    }
    return 1;
}

static void cleanup_download(guac_rdp_clipboard_download* download) {
    if (download->fd >= 0)
        close(download->fd);
    if (download->path[0] != '\0')
        unlink(download->path);
    guac_mem_free(download);
}

static int clipboard_download_ack(guac_user* user, guac_stream* stream,
        char* message, guac_protocol_status status) {
    guac_rdp_clipboard_download* download = stream->data;
    if (!download)
        return 0;
    if (status != GUAC_PROTOCOL_STATUS_SUCCESS) {
        guac_user_log(user, GUAC_LOG_WARNING,
                "RDP clipboard file download rejected by browser client.");
        guac_user_free_stream(user, stream);
        cleanup_download(download);
        return 0;
    }
    if (download->offset < download->size) {
        char buffer[65536];
        uint64_t remaining = download->size - download->offset;
        size_t requested = remaining < sizeof(buffer) ? (size_t) remaining : sizeof(buffer);
        ssize_t count = pread(download->fd, buffer, requested,
                (off_t) download->offset);
        if (count > 0) {
            download->offset += (uint64_t) count;
            guac_protocol_send_blob(user->socket, stream, buffer, (int) count);
            guac_socket_flush(user->socket);
            return 0;
        }
        guac_user_log(user, GUAC_LOG_ERROR,
                "Unable to read RDP clipboard file for browser download: %s",
                count < 0 ? strerror(errno) : "unexpected end of file");
    }
    guac_protocol_send_end(user->socket, stream);
    guac_socket_flush(user->socket);
    guac_user_free_stream(user, stream);
    cleanup_download(download);
    return 0;
}

static void* start_clipboard_download(guac_user* user, void* data) {
    guac_rdp_clipboard* clipboard = data;
    if (!user || !clipboard || !clipboard->file_active
            || clipboard->file_download_active || !clipboard->file_path[0])
        return NULL;
    int fd = open(clipboard->file_path, O_RDONLY);
    if (fd < 0) {
        cleanup_clipboard_file(clipboard);
        return NULL;
    }
    guac_rdp_clipboard_download* download =
            guac_mem_zalloc(sizeof(guac_rdp_clipboard_download));
    download->fd = fd;
    download->size = clipboard->file_size;
    guac_strlcpy(download->path, clipboard->file_path, sizeof(download->path));
    guac_stream* stream = guac_user_alloc_stream(user);
    stream->data = download;
    stream->ack_handler = clipboard_download_ack;
    clipboard->file_download_active = 1;
    if (guac_protocol_send_file(user->socket, stream,
            "application/octet-stream", clipboard->file_name)) {
        guac_user_free_stream(user, stream);
        cleanup_download(download);
        cleanup_clipboard_file(clipboard);
        return NULL;
    }
    guac_client_log(clipboard->client, GUAC_LOG_DEBUG,
            "RDP clipboard file queued for browser download.");
    guac_socket_flush(user->socket);
    return stream;
}

static void complete_clipboard_file(guac_rdp_clipboard* clipboard) {
    if (clipboard->file_fd >= 0) {
        close(clipboard->file_fd);
        clipboard->file_fd = -1;
    }
    if (!guac_client_for_owner(clipboard->client,
            start_clipboard_download, clipboard))
        cleanup_clipboard_file(clipboard);
}

static UINT request_clipboard_file_contents(guac_rdp_clipboard* clipboard,
        int request_size) {
    if (!clipboard->cliprdr || !clipboard->file_active)
        return CHANNEL_RC_OK;
    CLIPRDR_FILE_CONTENTS_REQUEST request = { 0 };
#ifdef HAVE_CLIPRDR_HEADER
    request.common.msgType = CB_FILECONTENTS_REQUEST;
    request.common.msgFlags = 0;
    request.common.dataLen = 0;
#else
    request.msgType = CB_FILECONTENTS_REQUEST;
    request.msgFlags = 0;
    request.dataLen = 0;
#endif
    request.streamId = clipboard->file_stream_id;
    request.listIndex = clipboard->file_list_index;
    request.dwFlags = request_size ? FILECONTENTS_SIZE : FILECONTENTS_RANGE;
    request.nPositionLow = (UINT32) clipboard->file_received;
    request.nPositionHigh = (UINT32) (clipboard->file_received >> 32);
    request.cbRequested = request_size ? sizeof(uint64_t) :
        (clipboard->file_size - clipboard->file_received > 1024 * 1024
            ? 1024 * 1024
            : (UINT32) (clipboard->file_size - clipboard->file_received));
    request.haveClipDataId = FALSE;
    clipboard->file_waiting_for_size = request_size;
    clipboard->file_requested_bytes = request.cbRequested;
    guac_rdp_client* rdp_client = clipboard->client->data;
    pthread_mutex_lock(&(rdp_client->message_lock));
    UINT result = clipboard->cliprdr->ClientFileContentsRequest(
            clipboard->cliprdr, &request);
    pthread_mutex_unlock(&(rdp_client->message_lock));
    if (result != CHANNEL_RC_OK)
        cleanup_clipboard_file(clipboard);
    return result;
}

static UINT receive_clipboard_descriptor(guac_rdp_clipboard* clipboard,
        const BYTE* data, UINT32 data_length) {
    if (!data || !data_length || data_length > 1024 * 1024)
        return CHANNEL_RC_OK;
    FILEDESCRIPTORW* descriptors = NULL;
    UINT32 descriptor_count = 0;
    UINT result = cliprdr_parse_file_list(data, data_length,
            &descriptors, &descriptor_count);
    if (result != CHANNEL_RC_OK || !descriptors || !descriptor_count) {
        free(descriptors);
        return CHANNEL_RC_OK;
    }
    if (descriptor_count > GUAC_RDP_CLIPBOARD_MAX_FILES) {
        free(descriptors);
        return CHANNEL_RC_OK;
    }
    FILEDESCRIPTORW* descriptor = &descriptors[0];
    if (descriptor->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        free(descriptors);
        return CHANNEL_RC_OK;
    }
    cleanup_clipboard_file(clipboard);
    char filename_template[] = "/tmp/guac-rdp-clipboard-XXXXXX";
    clipboard->file_fd = mkstemp(filename_template);
    if (clipboard->file_fd < 0) {
        free(descriptors);
        return CHANNEL_RC_OK;
    }
    guac_strlcpy(clipboard->file_path, filename_template,
            sizeof(clipboard->file_path));
    if (!filename_from_descriptor(descriptor, clipboard->file_name,
            sizeof(clipboard->file_name)))
        guac_strlcpy(clipboard->file_name, "clipboard-file.bin",
                sizeof(clipboard->file_name));
    clipboard->file_active = 1;
    clipboard->file_download_active = 0;
    clipboard->file_stream_id = 1;
    clipboard->file_list_index = 0;
    clipboard->file_received = 0;
    clipboard->file_size = ((uint64_t) descriptor->nFileSizeHigh << 32)
        | descriptor->nFileSizeLow;
    clipboard->file_size_known = (descriptor->dwFlags & FD_FILESIZE) != 0;
    free(descriptors);
    if (clipboard->file_size_known
            && clipboard->file_size > GUAC_RDP_CLIPBOARD_MAX_FILE_SIZE) {
        cleanup_clipboard_file(clipboard);
        return CHANNEL_RC_OK;
    }
    if (!clipboard->file_size_known)
        return request_clipboard_file_contents(clipboard, 1);
    if (!clipboard->file_size) {
        complete_clipboard_file(clipboard);
        return CHANNEL_RC_OK;
    }
    return request_clipboard_file_contents(clipboard, 0);
}

static UINT receive_clipboard_file_contents(CliprdrClientContext* cliprdr,
        CLIPRDR_CONST CLIPRDR_FILE_CONTENTS_RESPONSE* response) {
    guac_rdp_clipboard* clipboard = cliprdr->custom;
    if (!clipboard || !clipboard->file_active
            || response->streamId != clipboard->file_stream_id)
        return CHANNEL_RC_OK;
    if (response->msgFlags & CB_RESPONSE_FAIL) {
        cleanup_clipboard_file(clipboard);
        return CHANNEL_RC_OK;
    }
    UINT32 length = response->cbRequested;
    if (clipboard->file_waiting_for_size) {
        if (!response->requestedData || length != sizeof(uint64_t)) {
            cleanup_clipboard_file(clipboard);
            return CHANNEL_RC_OK;
        }
        const BYTE* size_data = response->requestedData;
        clipboard->file_size = ((uint64_t) size_data[0])
            | ((uint64_t) size_data[1] << 8)
            | ((uint64_t) size_data[2] << 16)
            | ((uint64_t) size_data[3] << 24)
            | ((uint64_t) size_data[4] << 32)
            | ((uint64_t) size_data[5] << 40)
            | ((uint64_t) size_data[6] << 48)
            | ((uint64_t) size_data[7] << 56);
        clipboard->file_size_known = 1;
        clipboard->file_waiting_for_size = 0;
        if (clipboard->file_size > GUAC_RDP_CLIPBOARD_MAX_FILE_SIZE) {
            cleanup_clipboard_file(clipboard);
            return CHANNEL_RC_OK;
        }
        if (!clipboard->file_size) {
            complete_clipboard_file(clipboard);
            return CHANNEL_RC_OK;
        }
        return request_clipboard_file_contents(clipboard, 0);
    }
    if (!response->requestedData
            || length > clipboard->file_requested_bytes
            || clipboard->file_received > clipboard->file_size
            || length > clipboard->file_size - clipboard->file_received
            || (!length && clipboard->file_received < clipboard->file_size)
            || !write_clipboard_at(clipboard->file_fd, response->requestedData,
                length, clipboard->file_received)) {
        cleanup_clipboard_file(clipboard);
        return CHANNEL_RC_OK;
    }
    clipboard->file_received += length;
    if (clipboard->file_received == clipboard->file_size)
        complete_clipboard_file(clipboard);
    else
        request_clipboard_file_contents(clipboard, 0);
    return CHANNEL_RC_OK;
}

/**
 * Callback invoked by the FreeRDP CLIPRDR plugin for received Format List
 * PDUs. The Format List PDU is sent by the RDP server to indicate that new
 * clipboard data has been copied and is available for retrieval in the formats
 * listed. A client wishing to retrieve that data responds with a Format Data
 * Request PDU.
 *
 * @param cliprdr
 *     The CliprdrClientContext structure used by FreeRDP to handle the CLIPRDR
 *     channel for the current RDP session.
 *
 * @param format_list
 *     The CLIPRDR_FORMAT_LIST structure representing the Format List PDU that
 *     was received.
 *
 * @return
 *     CHANNEL_RC_OK (zero) if the PDU was handled successfully, an error code
 *     (non-zero) otherwise.
 */
static UINT guac_rdp_cliprdr_format_list(CliprdrClientContext* cliprdr,
        CLIPRDR_CONST CLIPRDR_FORMAT_LIST* format_list) {

    /* FreeRDP-specific handlers for CLIPRDR are not assigned, and thus not
     * callable, until after the relevant guac_rdp_clipboard structure is
     * allocated and associated with the CliprdrClientContext */
    guac_rdp_clipboard* clipboard = (guac_rdp_clipboard*) cliprdr->custom;
    assert(clipboard != NULL);

    guac_client* client = clipboard->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;

    guac_client_log(client, GUAC_LOG_TRACE, "CLIPRDR: Received format list.");

    CLIPRDR_FORMAT_LIST_RESPONSE format_list_response = {
#ifdef HAVE_CLIPRDR_HEADER
        .common = {
            .msgType = CB_FORMAT_LIST_RESPONSE,
            .msgFlags = CB_RESPONSE_OK
        }
#else
        .msgFlags = CB_RESPONSE_OK
#endif
    };
    /* Report successful processing of format list */
    pthread_mutex_lock(&(rdp_client->message_lock));
    cliprdr->ClientFormatListResponse(cliprdr, &format_list_response);
    pthread_mutex_unlock(&(rdp_client->message_lock));

    /* Prefer the Windows file clipboard over text. */
    for (int i = 0; i < format_list->numFormats; i++) {
        CLIPRDR_FORMAT* format = &(format_list->formats[i]);
        if (format->formatName != NULL
                && strcmp(format->formatName, "FileGroupDescriptorW") == 0) {
            clipboard->requested_file_descriptor = 1;
            return guac_rdp_cliprdr_send_format_data_request(
                    cliprdr, format->formatId);
        }
    }

    clipboard->requested_file_descriptor = 0;

    /* Prefer Unicode (in this case, UTF-16) */
    if (guac_rdp_cliprdr_format_supported(format_list, CF_UNICODETEXT))
        return guac_rdp_cliprdr_send_format_data_request(cliprdr, CF_UNICODETEXT);

    /* Use Windows' CP-1252 if Unicode unavailable */
    if (guac_rdp_cliprdr_format_supported(format_list, CF_TEXT))
        return guac_rdp_cliprdr_send_format_data_request(cliprdr, CF_TEXT);

    guac_client_log(client, GUAC_LOG_DEBUG, "Ignoring unsupported clipboard "
            "data. Only Unicode, text, and FileGroupDescriptorW formats are "
            "currently supported.");
    return CHANNEL_RC_OK;

}

/**
 * Callback invoked by the FreeRDP CLIPRDR plugin for received Format Data
 * Request PDUs. The Format Data Request PDU is sent by the RDP server when
 * requesting that clipboard data be sent, in response to a received Format
 * List PDU. The client is required to respond with a Format Data Response PDU
 * containing the requested data.
 *
 * @param cliprdr
 *     The CliprdrClientContext structure used by FreeRDP to handle the CLIPRDR
 *     channel for the current RDP session.
 *
 * @param format_data_request
 *     The CLIPRDR_FORMAT_DATA_REQUEST structure representing the Format Data
 *     Request PDU that was received.
 *
 * @return
 *     CHANNEL_RC_OK (zero) if the PDU was handled successfully, an error code
 *     (non-zero) otherwise.
 */
static UINT guac_rdp_cliprdr_format_data_request(CliprdrClientContext* cliprdr,
        CLIPRDR_CONST CLIPRDR_FORMAT_DATA_REQUEST* format_data_request) {

    /* FreeRDP-specific handlers for CLIPRDR are not assigned, and thus not
     * callable, until after the relevant guac_rdp_clipboard structure is
     * allocated and associated with the CliprdrClientContext */
    guac_rdp_clipboard* clipboard = (guac_rdp_clipboard*) cliprdr->custom;
    assert(clipboard != NULL);

    guac_client* client = clipboard->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;
    guac_rdp_settings* settings = rdp_client->settings;

    guac_client_log(client, GUAC_LOG_TRACE, "CLIPRDR: Received format data request.");

    guac_iconv_write* remote_writer;
    const char* input = clipboard->clipboard->buffer;
    char* output = guac_mem_alloc(GUAC_COMMON_CLIPBOARD_MAX_LENGTH);

    /* Map requested clipboard format to a guac_iconv writer */
    switch (format_data_request->requestedFormatId) {

        case CF_TEXT:
            remote_writer = settings->clipboard_crlf ? GUAC_WRITE_CP1252_CRLF : GUAC_WRITE_CP1252;
            break;

        case CF_UNICODETEXT:
            remote_writer = settings->clipboard_crlf ? GUAC_WRITE_UTF16_CRLF : GUAC_WRITE_UTF16;
            break;

        /* Warn if clipboard data cannot be sent as intended due to a violation
         * of the CLIPRDR spec */
        default:
            guac_client_log(client, GUAC_LOG_WARNING, "Received clipboard "
                    "data cannot be sent to the RDP server because the RDP "
                    "server has requested a clipboard format which was not "
                    "declared as available. This violates the specification "
                    "for the CLIPRDR channel.");
            guac_mem_free(output);
            return CHANNEL_RC_OK;

    }

    /* Send received clipboard data to the RDP server in the format
     * requested */
    BYTE* start = (BYTE*) output;
    guac_iconv_read* local_reader = settings->normalize_clipboard ? GUAC_READ_UTF8_NORMALIZED : GUAC_READ_UTF8;
    guac_iconv(local_reader, &input, clipboard->clipboard->length,
            remote_writer, &output, GUAC_COMMON_CLIPBOARD_MAX_LENGTH);

    CLIPRDR_FORMAT_DATA_RESPONSE data_response = {
        .requestedFormatData = (BYTE*) start,
#ifdef HAVE_CLIPRDR_HEADER
        .common = {
            .msgType = CB_FORMAT_DATA_RESPONSE,
            .msgFlags = CB_RESPONSE_OK,
            .dataLen = ((BYTE*) output) - start,
        }
#else
        .dataLen = ((BYTE*) output) - start,
        .msgFlags = CB_RESPONSE_OK
#endif
    };

    guac_client_log(client, GUAC_LOG_TRACE, "CLIPRDR: Sending format data response.");

    pthread_mutex_lock(&(rdp_client->message_lock));
    UINT result = cliprdr->ClientFormatDataResponse(cliprdr, &data_response);
    pthread_mutex_unlock(&(rdp_client->message_lock));

    guac_mem_free(start);
    return result;

}

/**
 * Callback invoked by the FreeRDP CLIPRDR plugin for received Format Data
 * Response PDUs. The Format Data Response PDU is sent by the RDP server when
 * fulfilling a request for clipboard data received via a Format Data Request
 * PDU.
 *
 * @param cliprdr
 *     The CliprdrClientContext structure used by FreeRDP to handle the CLIPRDR
 *     channel for the current RDP session.
 *
 * @param format_data_response
 *     The CLIPRDR_FORMAT_DATA_RESPONSE structure representing the Format Data
 *     Response PDU that was received.
 *
 * @return
 *     CHANNEL_RC_OK (zero) if the PDU was handled successfully, an error code
 *     (non-zero) otherwise.
 */
static UINT guac_rdp_cliprdr_format_data_response(CliprdrClientContext* cliprdr,
        CLIPRDR_CONST CLIPRDR_FORMAT_DATA_RESPONSE* format_data_response) {

    /* FreeRDP-specific handlers for CLIPRDR are not assigned, and thus not
     * callable, until after the relevant guac_rdp_clipboard structure is
     * allocated and associated with the CliprdrClientContext */
    guac_rdp_clipboard* clipboard = (guac_rdp_clipboard*) cliprdr->custom;
    assert(clipboard != NULL);

    guac_client* client = clipboard->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;
    guac_rdp_settings* settings = rdp_client->settings;

    guac_client_log(client, GUAC_LOG_TRACE, "CLIPRDR: Received format data response.");

    /* Ignore received data if copy has been disabled */
    if (settings->disable_copy) {
        guac_client_log(client, GUAC_LOG_DEBUG, "Ignoring received clipboard "
                "data as copying from within the remote desktop has been "
                "explicitly disabled.");
        return CHANNEL_RC_OK;
    }

    int data_len;
#ifdef HAVE_CLIPRDR_HEADER
    data_len = format_data_response->common.dataLen;
#else
    data_len = format_data_response->dataLen;
#endif

    if (clipboard->requested_file_descriptor) {
        clipboard->requested_file_descriptor = 0;
        return receive_clipboard_descriptor(clipboard,
                format_data_response->requestedFormatData, data_len);
    }

    char received_data[GUAC_COMMON_CLIPBOARD_MAX_LENGTH];

    guac_iconv_read* remote_reader;
    const char* input = (char*) format_data_response->requestedFormatData;
    char* output = received_data;

    /* Find correct source encoding */
    switch (clipboard->requested_format) {

        /* Non-Unicode (Windows CP-1252) */
        case CF_TEXT:
            remote_reader = settings->normalize_clipboard ? GUAC_READ_CP1252_NORMALIZED : GUAC_READ_CP1252;
            break;

        /* Unicode (UTF-16) */
        case CF_UNICODETEXT:
            remote_reader = settings->normalize_clipboard ? GUAC_READ_UTF16_NORMALIZED : GUAC_READ_UTF16;
            break;

        /* If the format ID stored within the guac_rdp_clipboard structure is actually
         * not supported here, then something has been implemented incorrectly.
         * Either incorrect values are (somehow) being stored, or support for
         * the format indicated by that value is incomplete and must be added
         * here. The values which may be stored within requested_format are
         * completely within our control. */
        default:
            guac_client_log(client, GUAC_LOG_DEBUG, "Requested clipboard data "
                    "in unsupported format (0x%X).", clipboard->requested_format);
            return CHANNEL_RC_OK;

    }

    /* Convert, store, and forward the clipboard data received from RDP
     * server */
    if (guac_iconv(remote_reader, &input, data_len,
            GUAC_WRITE_UTF8, &output, sizeof(received_data))) {
        int length = strnlen(received_data, sizeof(received_data));
        guac_common_clipboard_reset(clipboard->clipboard, "text/plain");
        guac_common_clipboard_append(clipboard->clipboard, received_data, length);
        guac_common_clipboard_send(clipboard->clipboard, client);
    }

    return CHANNEL_RC_OK;

}

/**
 * Callback which associates handlers specific to Guacamole with the
 * CliprdrClientContext instance allocated by FreeRDP to deal with received
 * CLIPRDR (clipboard redirection) messages.
 *
 * This function is called whenever a channel connects via the PubSub event
 * system within FreeRDP, but only has any effect if the connected channel is
 * the CLIPRDR channel. This specific callback is registered with the PubSub
 * system of the relevant rdpContext when guac_rdp_clipboard_load_plugin() is
 * called.
 *
 * @param context
 *     The rdpContext associated with the active RDP session.
 *
 * @param args
 *     Event-specific arguments, mainly the name of the channel, and a
 *     reference to the associated plugin loaded for that channel by FreeRDP.
 */
static void guac_rdp_cliprdr_channel_connected(rdpContext* context,
        ChannelConnectedEventArgs* args) {

    guac_client* client = ((rdp_freerdp_context*) context)->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;
    guac_rdp_clipboard* clipboard = rdp_client->clipboard;

    /* FreeRDP-specific handlers for CLIPRDR are not assigned, and thus not
     * callable, until after the relevant guac_rdp_clipboard structure is
     * allocated and associated with the guac_rdp_client */
    assert(clipboard != NULL);

    /* Ignore connection event if it's not for the CLIPRDR channel */
    if (strcmp(args->name, CLIPRDR_SVC_CHANNEL_NAME) != 0)
        return;

    /* The structure pointed to by pInterface is guaranteed to be a
     * CliprdrClientContext if the channel is CLIPRDR */
    CliprdrClientContext* cliprdr = (CliprdrClientContext*) args->pInterface;

    /* Associate FreeRDP CLIPRDR context and its Guacamole counterpart with
     * eachother */
    cliprdr->custom = clipboard;
    clipboard->cliprdr = cliprdr;

    cliprdr->MonitorReady = guac_rdp_cliprdr_monitor_ready;
    cliprdr->ServerFormatList = guac_rdp_cliprdr_format_list;
    cliprdr->ServerFormatDataRequest = guac_rdp_cliprdr_format_data_request;
    cliprdr->ServerFormatDataResponse = guac_rdp_cliprdr_format_data_response;
    cliprdr->ServerFileContentsResponse = receive_clipboard_file_contents;

    guac_client_log(client, GUAC_LOG_DEBUG, "CLIPRDR (clipboard redirection) "
            "channel connected.");

}

/**
 * Callback which disassociates Guacamole from the CliprdrClientContext
 * instance that was originally allocated by FreeRDP and is about to be
 * deallocated.
 *
 * This function is called whenever a channel disconnects via the PubSub event
 * system within FreeRDP, but only has any effect if the disconnected channel
 * is the CLIPRDR channel. This specific callback is registered with the PubSub
 * system of the relevant rdpContext when guac_rdp_clipboard_load_plugin() is
 * called.
 *
 * @param context
 *     The rdpContext associated with the active RDP session.
 *
 * @param args
 *     Event-specific arguments, mainly the name of the channel, and a
 *     reference to the associated plugin loaded for that channel by FreeRDP.
 */
static void guac_rdp_cliprdr_channel_disconnected(rdpContext* context,
        ChannelDisconnectedEventArgs* args) {

    guac_client* client = ((rdp_freerdp_context*) context)->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;
    guac_rdp_clipboard* clipboard = rdp_client->clipboard;

    /* FreeRDP-specific handlers for CLIPRDR are not assigned, and thus not
     * callable, until after the relevant guac_rdp_clipboard structure is
     * allocated and associated with the guac_rdp_client */
    assert(clipboard != NULL);

    /* Ignore disconnection event if it's not for the CLIPRDR channel */
    if (strcmp(args->name, CLIPRDR_SVC_CHANNEL_NAME) != 0)
        return;

    /* Channel is no longer connected */
    clipboard->cliprdr = NULL;
    cleanup_clipboard_file(clipboard);

    guac_client_log(client, GUAC_LOG_DEBUG, "CLIPRDR (clipboard redirection) "
            "channel disconnected.");

}

guac_rdp_clipboard* guac_rdp_clipboard_alloc(guac_client* client) {

    /* Allocate clipboard and underlying storage */
    guac_rdp_clipboard* clipboard = guac_mem_zalloc(sizeof(guac_rdp_clipboard));
    clipboard->client = client;
    clipboard->clipboard = guac_common_clipboard_alloc();
    clipboard->requested_format = CF_TEXT;
    clipboard->file_fd = -1;

    return clipboard;

}

void guac_rdp_clipboard_load_plugin(guac_rdp_clipboard* clipboard,
        rdpContext* context) {

    /* Attempt to load FreeRDP support for the CLIPRDR channel */
    if (guac_freerdp_channels_load_plugin(context, "cliprdr", NULL)) {
        guac_client_log(clipboard->client, GUAC_LOG_WARNING,
                "Support for the CLIPRDR channel (clipboard redirection) "
                "could not be loaded. This support normally takes the form of "
                "a plugin which is built into FreeRDP. Lacking this support, "
                "clipboard will not work.");
        return;
    }

    /* Complete RDP side of initialization when channel is connected */
    PubSub_SubscribeChannelConnected(context->pubSub,
            (pChannelConnectedEventHandler) guac_rdp_cliprdr_channel_connected);

    /* Clean up any RDP-specific resources when channel is disconnected */
    PubSub_SubscribeChannelDisconnected(context->pubSub,
            (pChannelDisconnectedEventHandler) guac_rdp_cliprdr_channel_disconnected);

    guac_client_log(clipboard->client, GUAC_LOG_DEBUG, "Support for CLIPRDR "
            "(clipboard redirection) registered. Awaiting channel "
            "connection.");

}

void guac_rdp_clipboard_free(guac_rdp_clipboard* clipboard) {

    /* Do nothing if the clipboard is not actually allocated */
    if (clipboard == NULL)
        return;

    cleanup_clipboard_file(clipboard);

    /* Free clipboard and underlying storage */
    guac_common_clipboard_free(clipboard->clipboard);
    guac_mem_free(clipboard);

}

int guac_rdp_clipboard_handler(guac_user* user, guac_stream* stream,
        char* mimetype) {

    guac_client* client = user->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;

    /* Ignore stream creation if no clipboard structure is available to handle
     * received data */
    guac_rdp_clipboard* clipboard = rdp_client->clipboard;
    if (clipboard == NULL)
        return 0;

    /* Handle any future "blob" and "end" instructions for this stream with
     * handlers that are aware of the RDP clipboard state */
    stream->blob_handler = guac_rdp_clipboard_blob_handler;
    stream->end_handler = guac_rdp_clipboard_end_handler;

    /* Clear any current contents, assigning the mimetype the data which will
     * be received */
    guac_common_clipboard_reset(clipboard->clipboard, mimetype);
    return 0;

}

int guac_rdp_clipboard_blob_handler(guac_user* user, guac_stream* stream,
        void* data, int length) {

    guac_client* client = user->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;

    /* Ignore received data if no clipboard structure is available to handle
     * that data */
    guac_rdp_clipboard* clipboard = rdp_client->clipboard;
    if (clipboard == NULL)
        return 0;

    /* Append received data to current clipboard contents */
    guac_common_clipboard_append(clipboard->clipboard, (char*) data, length);
    return 0;

}

int guac_rdp_clipboard_end_handler(guac_user* user, guac_stream* stream) {

    guac_client* client = user->client;
    guac_rdp_client* rdp_client = (guac_rdp_client*) client->data;

    /* Ignore end of stream if no clipboard structure is available to handle
     * the data that was received */
    guac_rdp_clipboard* clipboard = rdp_client->clipboard;
    if (clipboard == NULL)
        return 0;

    /* Terminate clipboard data with NULL */
    guac_common_clipboard_append(clipboard->clipboard, "", 1);

    /* Notify RDP server of new data, if connected */
    if (clipboard->cliprdr != NULL) {
        guac_client_log(client, GUAC_LOG_DEBUG, "Clipboard data received. "
                "Reporting availability of clipboard data to RDP server.");
        guac_rdp_cliprdr_send_format_list(clipboard->cliprdr);
    }
    else
        guac_client_log(client, GUAC_LOG_DEBUG, "Clipboard data has been "
                "received, but cannot be sent to the RDP server because the "
                "CLIPRDR channel is not yet connected.");

    return 0;

}
