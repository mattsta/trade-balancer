#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* ioctl */
#include <sys/ioctl.h>

/* DBL_MIN / DBL_MAX */
#include <float.h>

/* all this just for 'open()' */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* waitpid */
#include <sys/wait.h>

/* gettimeofday */
#include <sys/time.h>

/* aio_write()  (*cough* garbage *cough*) */
// #include <aio.h>

#include "fastmod.h"
#include "tls.h"

/* we can receive TLS control messages / alerts from the kernel,
 * but when we receive an alert all we can do is reconnect anyway.
 * if we don't listen for control messages, the kernel will just
 * return I/O Error on our regular recv() which has the same effect as
 * reading the alert and reconnecting ourselves. */
#define READ_TLS_CONTROL_MESSAGES 0

#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

/* so child process can inherit our environment */
extern char **environ;

// #define DBG_READ_TIME 1
// #define printf(...)
int tls_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

static inline uint64_t timeUS(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    uint64_t us = (uint64_t)tv.tv_sec * 1000000;
    us += tv.tv_usec;

    return us;
}

static inline uint32_t hash_fnv1a_until(const void *const ibuf,
                                        const char until) {
    /* https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#The_hash
     */
    static const uint64_t prime = 0x100000001b3ULL;
    const uint8_t *input = ibuf;

    /* starting basis value */
    uint64_t hash = 0xcbf29ce484222325ULL;
    size_t len = 0;

#pragma GCC unroll 4
    while (*input != until) {
        hash ^= *input;
        hash *= prime;

        input++;
        len++;
    }

    return (uint32_t)(hash >> 32);
}

static inline uint32_t hash_djb2(const void *const ibuf, const char until) {
    /* Adapted from: http://www.cse.yorku.ca/~oz/hash.html */
    const uint8_t *input = ibuf;

    /* starting basis value */
    uint32_t hash = 5381;

#pragma GCC unroll 4
    while (*input != until) {
#if 0
        hash = ((hash << 5) + hash) + *input;
#else
        hash = (hash * 33) ^ *input;
#endif
        input++;
    }

    return hash;
}

typedef enum frameType {
    F_CONT = 0x00,
    F_TEXT = 0x01,
    F_BINARY = 0x02,
    F_CLOSE = 0x08,
    F_PING = 0x09,
    F_PONG = 0x0A
} frameType;

/* Framing docs:
 * https://tools.ietf.org/html/rfc6455#section-5 */
typedef struct frameHeader {
    uint16_t fin : 1;
    uint16_t rsv1 : 1;
    uint16_t rsv2 : 1;
    uint16_t rsv3 : 1;
    uint16_t opcode : 4;
    uint16_t masked : 1;
    uint16_t payloadLengthSwitcher : 7;
    /* don't get clever and try to add a union for the u16/u64
     * length extenions here because apparently unions inside
     * scalar reordered structs don't work? At least I could
     * never get them to show memory from the underlying fh unions. */
} __attribute__((scalar_storage_order("big-endian"))) frameHeader;

static inline int writeCheck(const int sock, const void *ibuf,
                             const size_t len) {
    const uint8_t *buf = (const uint8_t *)ibuf;
    int wrote = 0;

    assert(buf[0] >> 4 == 0x8);
    do {
        const int writeDid = write(sock, buf + wrote, len - wrote);

        if (writeDid == -1) {
            printf("[%.5f] Write failed? %s\n", timeUS() / 1000000.0,
                   strerror(errno));
            return -1;
        }

        if (writeDid < len) {
            printf("[%.5f] Wrote less than expected! wrote %d but wanted %lu, "
                   "writing again!\n",
                   timeUS() / 1000000.0, writeDid, len);
        }

        wrote += writeDid;
    } while (wrote < len);

    return wrote;
}

size_t genPong(void *ibuf, const void *data, const size_t dataLen) {
    uint8_t *buf = (uint8_t *)ibuf;

    /* don't send us large pings, okay? */
    assert(dataLen <= 32);

    /* an empty pong frame is 6 bytes (2 header + 4 empty mask) */
    union {
        frameHeader *fh;
        void *buf;
    } fh = {.buf = buf};

    /* header plus empty mask */
    memset(fh.fh, 0, sizeof(uint16_t) + 4);

    fh.fh->fin = 1;
    fh.fh->opcode = F_PONG;
    fh.fh->masked = 1;
    fh.fh->payloadLengthSwitcher = dataLen;

    if (data) {
        /* write after header + empty mask */
        memcpy(buf + sizeof(uint16_t) + 4, data, dataLen);
    }

    /* total size is: 2 byte header + 4 byte (empty) mask + return data */
    return sizeof(uint16_t) + 4 + dataLen;

#if 0
    printf("Generated pong: 0x%X, 0x%X, 0x%X\n", buf[0], buf[1], buf[2]);
#endif
}

size_t genText(void *ibuf, const void *restrict data, const size_t dataLen,
               uint8_t **dataStart) {
    uint8_t *buf = (uint8_t *)ibuf;
    union {
        frameHeader *fh;
        void *buf;
    } fh = {.buf = buf};

    /* zero out header... */
    memset(fh.fh, 0, sizeof(uint16_t));

    fh.fh->fin = 1;
    fh.fh->opcode = F_TEXT;

    /* websocket spec says clients MUST send masked data, but clients
     * also get to specify the mask, so we just use a mask of 0, so take
     * that outdated standard you can't make us xor things!
     * our public connections are over TLS anyway so the mask isn't
     * useful for hiding from any middleboxes. */
    fh.fh->masked = 1;
    /* but, we still need to need to add 4 bytes of empty mask AFTER the length.
     * dataStart will initially be the start of the mask, then add empty mask,
     * then we set the actual dataStart 4 bytes after the first dataStart. */

    uint8_t *maskStart;
    if (dataLen <= 125) {
        /* Lengths less than 125 are included directly */
        maskStart = buf + 2;
        fh.fh->payloadLengthSwitcher = dataLen;
    } else if (dataLen <= UINT16_MAX) {
        /* Lengths up to 16 bits are a 2 byte trailer */
        maskStart = buf + 2 + 2;
        fh.fh->payloadLengthSwitcher = 126;
        const uint16_t writeLen = __builtin_bswap16(dataLen);
        memcpy(buf + 2, &writeLen, 2);
    } else {
        /* Larger lengths have an 8 byte trailer */
        maskStart = buf + 2 + 8;
        fh.fh->payloadLengthSwitcher = 127;
        const uint64_t writeLen = __builtin_bswap64(dataLen);
        memcpy(buf + 2, &writeLen, 8);
    }

    /* zero out user-supplied mask (since we aren't masking anything) */
    memset(maskStart, 0, 4);
    *dataStart = maskStart + 4;

    /* buf[0] needs to be 1000001 */
    assert(buf[0] == ((1 << 7) | F_TEXT));

    /* add the actual data to the frame */
    memcpy(*dataStart, data, dataLen);

    /* return value is total size of frame from 'buf' to end of data */
    return (*dataStart + dataLen) - buf;
}

/* 'dataSize()' returns the size of the data inside the frame (or a negative
 * number if we need to read more bytes to decode the header), along with
 * setting multiple inout metadata parameters */
int dataSize(void *const ibuf, const int bufLen, uint8_t **dataStart,
             enum frameType *type, bool *final, size_t *totalFrameSize) {
    uint8_t *buf = ibuf;
    union {
        const frameHeader *fh;
        const void *buf;
    } fh = {.buf = buf};

    /* We need a minimum of 2 bytes to properly start parsing a frame header. */
    if (unlikely(bufLen < 2)) {
        return 2 - bufLen;
    }

    const uint64_t requestedLen = fh.fh->payloadLengthSwitcher;
    size_t frameDataLen;
    *type = fh.fh->opcode;
    *final = fh.fh->fin;

#if 0
    printf("length switcher is: %lu\n", requestedLen);
    printf("fin is: %d\n", fh.fh->fin);
    printf("rsv is: %d, %d, %d\n", fh.fh->rsv1, fh.fh->rsv2, fh.fh->rsv3);
    printf("opcode is: 0x%X\n", fh.fh->opcode);
#endif

    if (requestedLen <= 125) {
        *dataStart = buf + 2; /* + 2 for 2 byte header */
        frameDataLen = requestedLen;
    } else if (requestedLen == 126) {
        if (bufLen < 4) {
            /* tell caller we need to read up to 2 more bytes */
            /* (we return negative numbers to tell the caller we need N more
             * bytes) */
            return bufLen - 4;
        }

        /* Note: these can be unaligned loads, but x64 eats them up fine */
        *dataStart = buf + 2 + 2; /* + 4 for 2 byte header + 2 byte length */
        frameDataLen = __builtin_bswap16(*(uint16_t *)(buf + 2));
    } else if (requestedLen == 127) {
        if (bufLen < 10) {
            /* tell caller we need to read up to 8 more bytes */
            /* (we return negative numbers to tell the caller we need N more
             * bytes
             */
            return bufLen - 10;
        }

        *dataStart = buf + 2 + 8; /* + 10 for 2 byte header + 8 byte length */
        frameDataLen = __builtin_bswap64(*(uint64_t *)(buf + 2));
    }

    *totalFrameSize = (*dataStart + frameDataLen) - buf;
    return frameDataLen;
}

#define GOODBYE_BYTES __attribute__((cleanup(ffree)))
static void ffree(uint8_t *const *thing) {
    free(*thing);
}

void dispatchWebsocketFrames(int sock, int writePipes[],
                             const uint32_t writePipesLen, uint64_t *totalTotal,
                             uint64_t *totalBytes) {
    const uint64_t modM = computeM_u32(writePipesLen);

    /* don't make bufSize too big (1 GB+) or the kernel tls will give
     * a memory error when trying to write into the buffer */
    const size_t bufSize = 1ULL << 28;
    uint8_t GOODBYE_BYTES *const buf = malloc(bufSize);

    const size_t continueBufferSize = 1ULL << 25;
    uint8_t GOODBYE_BYTES *const continueBuffer = malloc(continueBufferSize);
    size_t continueBufferOffset = 0;

    /* memset with non-zero so we activate all our pages right now */
    /* 0xAA is nice because it's 10101010 */
    memset(buf, 0xAA, bufSize);
    memset(continueBuffer, 0xAA, continueBufferSize);

    /* one static pong response we reuse for each empty ping */
    uint8_t pongEmptyResponse[2 + 4];
    genPong(pongEmptyResponse, NULL, 0);

    /* We trust the upstream server to not give us malformed WebSocket frames or
     * else we'll be jumping outside our valid table entries here. */
    void *events[] = {/* 0 */ &&continueFrame,
                      /* 1 */ &&text,
                      /* 2 */ &&binary,
                      /* 3 */ NULL,
                      /* 4 */ NULL,
                      /* 5 */ NULL,
                      /* 6 */ NULL,
                      /* 7 */ NULL,
                      /* 8 */ &&close,
                      /* 9 */ &&ping,
                      /* 10 */ &&pong};

    /* Right now we are ignoring TLS control/alert messages, but if we want to
     * receive them in the future, template is at:
     * https://www.kernel.org/doc/html/latest/networking/tls.html#receiving-tls-control-messages
     * (currently if alert comes in, recv returns I/O error and we reconnect) */
    uint64_t total = 0;
    int got = 0;
    int processed = 0;

    /* reset errno to a happy value in case this is a reconnect so we aren't
     * mistakenly reporting errors from a prior connection. */
    errno = 0;

#if READ_TLS_CONTROL_MESSAGES
    char cmsg[CMSG_SPACE(sizeof(unsigned char))];
    struct msghdr msg = {0};
    msg.msg_control = cmsg;
    msg.msg_controllen = sizeof(cmsg);

    struct iovec msg_iov;

    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;
#endif

    double startTime = timeUS() / 1000000.0;
    double highestRate = DBL_MIN;
    double lowestRate = DBL_MAX;
    double highestTime = startTime;
    double lowestTime = startTime;
    uint64_t totalReads = 0;
    uint64_t totalReadsSinceLastRate = 0;
    uint64_t totalFrames = 0;
    uint64_t totalFramesSinceLastRate = 0;
    uint64_t totalBytesSinceLastRate = 0;
    enum frameType continuedType = F_CONT;
    while (true) {
        if (processed == got) {
            /* we consumed all our data, so reset buffer back to the start */
            got = 0;
            processed = 0;
        } else {
            /* 'readAgain' is here because if we are reading AGAIN, it means we
             * already have buffer bytes, but need more buffer bytes to complete
             * a frame. So, since we already have buffer bytes, 'processed'
             * will be less than 'got', so it can not match the above p==g
             * condition, but it *could* potentially need to be reallocated
             * smaller if we had the bad luck of getting an infinite situation
             * where everytime we read, we end up with a partial frame at the
             * end of the buffer, so we need to read again, without ever being
             * able to clear the existing full buffer (as the previous
             * if p==g wants to do). */
        readAgain:
            if (processed > (bufSize / 2)) {
                /* else, only move read buffer down if it's over half full */
                // printf("Processed is: %d\n", processed);
                printf("moving remainder (%d bytes)...\n", got - processed);
                /* If we're entering the loop again with a partial frame
                 * already at the end of the buffer, move the partial frames
                 * to the start of our buffer again... */
                memmove(buf, buf + processed, got - processed);
                got = got - processed;
                processed = 0;
            }
        }

        /* things are very bad if we managed to fill up the entire receive
         * buffer without processing it (we'd be stuck in an infinite
         * zero-size read loop forever). */
        assert(bufSize - got > 0);

        /* Optionally consume TLS control messages, but TLS messages will be
         * alerts just telling us the connection is closing, so it's a lot of
         * work just to figure out the connection is going away, which we
         * already get notified about without doing all of this extra work. */
#if READ_TLS_CONTROL_MESSAGES
        msg_iov.iov_base = buf + got;
        msg_iov.iov_len = bufSize - got;

        const int topGot = recvmsg(sock, &msg, 0);

        struct cmsghdr *cmsgfirsthdr = CMSG_FIRSTHDR(&msg);
        if (cmsgfirsthdr->cmsg_level == SOL_TLS &&
            cmsgfirsthdr->cmsg_type == TLS_GET_RECORD_TYPE) {
            const int record_type = *((unsigned char *)CMSG_DATA(cmsgfirsthdr));
            // Do something with record_type, and control message data in
            // buffer.
            //
            // Note that record_type may be == to application data (23).
            //
            //
            /* Record types:
             *  - https://tools.ietf.org/html/rfc5246#appendix-A.1
             *
             * Alert types:
             *  - https://tools.ietf.org/html/rfc5246#appendix-A.3
             */
            if (unlikely(record_type != 23)) {
                const uint8_t *sbuf = buf + got;
                switch (record_type) {
                case 20:
                    printf(
                        "Got control message 20 to CHANGE CIPHER SPEC (?!)\n");
                    break;
                case 21:
                    printf("Got control message 21 to ALERT\n");
                    break;
                case 22:
                    printf("Got control message 22 to HANDSHAKE (?!)\n");
                    break;
                default:
                    printf("Got unexpected control message %d?!\n",
                           record_type);
                }

                if (record_type == 21) {
                    /* Alert types:
                     *  - https://tools.ietf.org/html/rfc5246#appendix-A.3
                     */
                    assert(topGot == 2);
                    const int level = sbuf[0];
                    const int alert = sbuf[1];
                    if (level == 1 && alert == 0) {
                        printf("[%.5f] Got close message from server. "
                               "Reconnecting.\n",
                               timeUS() / 1000000.0);
                        shutdown(sock, SHUT_RDWR);
                        close(sock);
                        return;
                    }

                    printf(
                        "Got unexpected alert message? Level %d with msg %d\n",
                        level, alert);
                }

                printf("Got record type: %d with got length: %d\n", record_type,
                       topGot);
                if (topGot > 0) {
                    printf("Data is: %.*s\n", topGot, buf + got);
                    printf("hex16 Data is: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X "
                           "0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X "
                           "0x%02X 0x%02X 0x%02X 0x%02X\n",
                           sbuf[0], sbuf[1], sbuf[2], sbuf[3], sbuf[4], sbuf[5],
                           sbuf[6], sbuf[7], sbuf[8], sbuf[9], sbuf[10],
                           sbuf[11], sbuf[12], sbuf[13], sbuf[14], sbuf[15]);
                }

                /* It's just a non-data alert, so what else can we do?
                 * Likely the connection is gone now, so the next read
                 * will return an I/O error and we'll fall back to just
                 * a reconnect. */
                continue;
            }
        }
#else
        /* read as much as the kernel wants to give us. we manually process
         * multiple frames per buffer below. */
        const int topGot = read(sock, buf + got, bufSize - got);
#endif

#if 0
        printf("read got: %d (total: %d) [%s]\n", topGot, got,
               strerror(errno));
#endif

#if 0
#if DBG_READ_TIME
        const uint64_t readStart = timeUS();
#endif
        got += read(sock, buf + got, bufSize - got);
#if DBG_READ_TIME
        const uint64_t readEnd = timeUS();
        printf("Read took: %lu us\n", readEnd - readStart);
#endif
#endif

        if (topGot <= 0) {
            printf("[%.5f] Disconnected (%d)! %s\n", timeUS() / 1000000.0,
                   topGot, strerror(errno));
            return;
        }

        got += topGot;
        totalReads++;

        (*totalBytes) += topGot;

        /* the frame processing loop must always accept the first iteration
         * because we just read data above, but haven't logged it as 'processed'
         * yet, so 'processed' MUST be less than 'got' on entry here. */
        assert(processed < got);
        while (processed < got) {
            // printf("banger! %d < %d\n", processed, got);
            uint8_t *dataStart;
            size_t totalFrameSize = SIZE_MAX;
            const size_t unprocessedByteCount = got - processed;
            enum frameType type;
            bool final = true;
            uint8_t *startCurrentFrame = buf + processed;

            const int frameDataLen =
                dataSize(startCurrentFrame, unprocessedByteCount, &dataStart,
                         &type, &final, &totalFrameSize);

            /* note: if frameDataLen is negative, then 'totalFrameSize' is not
             * valid here, but it'll all be cleaned up by reading more bytes. */
            if (frameDataLen < 0 || (unprocessedByteCount < totalFrameSize)) {
#if 0
                printf("banger2 ! %d < %d; %d < 0; (%d - %d) [%d] < %d \n",
                       processed, got, frameDataLen, got, processed,
                       got - processed, totalFrameSize);
#endif
                /* We need to read either more length bytes or more data bytes
                 * to parse the entire frame. */
                goto readAgain;
            }

            /* If there's more than one frame in the buffer, we'll save it for
             * next time. */
            assert(got >= totalFrameSize);
            processed += totalFrameSize;

            /* This is a good print to re-enable for more verbosity. */
#if 0
            printf("[0x%02X] [%lu] Received frame: 0x%02X, 0x%02X, 0x%02X; "
                   "Total Length: %lu; Data Length: %d\n",
                   type, total, buf[0], buf[1], buf[2], totalFrameSize,
                   frameDataLen);
#endif
            uint8_t *currentBuffer = dataStart;
            int currentLen = frameDataLen;

            /* add to our count of frames processed */
            totalFrames++;

            goto *events[type];

        text:
            /* we treat text frames and binary frames the same.
             * we don't care about validating utf-8 text frames, it's
             * just all bytes to us. */
        binary : {
            /* Process all the trades in this frame */
            // printf("data: %.*s\n\n", (int)currentLen, dataStart);
            /* Consume arrays of trade json until array is done:
             * [{"ev":"T","sym":"MSFT","p":114.18,"...},{....},...] */

            /* Initial continue frames have a type (which is how we got here),
             * but are marked NOT FINAL, so we may need to start growing a
             * continuation buffer... */
            if (unlikely(!final)) {
                /* also, continued frames don't remember their original type
                 * because future types will be F_CONT, so we need to remember
                 * the type from the first time we get a continue frame
                 * request. good job, 2011 websocket spec. */
                continuedType = type;
                goto continueFrame;
            }

            // processDataFrame(currentBuffer, currentLen);

            /* Now begin parsing the trade JSON inside the complete websocket
             * frame */
            /* Trade JSON is provided in an array of objects: [{blah},{blah2}]
             */

            /* First we skip the opening bracket */
            size_t position = 1;

            assert(currentBuffer[0] == '[');

            /* This is a more verbose assert to check for closing bracket
             * so we can report debug output if we get hit with weird
             * data problems (or if we didn't save a continued frame
             * correctly, etc). */
            if (unlikely(currentBuffer[currentLen - 1] != ']')) {
                printf("End of frame isn't ] for length: %d?\n", currentLen);
                printf("%.*s\n", currentLen, currentBuffer);
                printf("Buf header was: 0x%X 0x%X 0x%X 0x%X\n",
                       startCurrentFrame[0], startCurrentFrame[1],
                       startCurrentFrame[2], startCurrentFrame[3]);

                /* stream is corrupt, so we need to disconnect and reconnect */
                shutdown(sock, SHUT_RDWR);
                close(sock);
                return;
            }

            while (position < currentLen) {
#if 0
                printf("banger3 ! %d < %d\n", processed, got);
                printf("banger3 ! %d < %d fdl \n", position, currentLen);
#endif
                /* Next we skip _"ev":"T":"sym":" == 17 bytes */
                const size_t startTrade = position;
                uint8_t *bufferAtTrade = currentBuffer + startTrade;
                position += 17;

                /* hash symbol name until we reach the closing quote */
#if 1
                const uint32_t hash =
                    hash_fnv1a_until(currentBuffer + position, '"');
#else
                const uint32_t hash = hash_djb2(currentBuffer + position, '"');
#endif

                /* Now search for the next closing bracket */
                const uint8_t *end =
                    (const uint8_t *)strchr(
                        (const char *)currentBuffer + position, '}') +
                    1;
                const uint32_t tradeSize = end - bufferAtTrade;

                /* this is just a fancy micro-optimized: hash % writePipesLen */
                const uint32_t worker = fastmod_u32(hash, modM, writePipesLen);
#if 1
                /* This if/else is an optimization to avoid a full copy. If we
                 * are parsing a trade array, if we aren't at the first
                 * entry we can overwrite the last 4 bytes of the previous
                 * entry to be the length to send, then we just send from 4
                 * bytes back in the current buffer. */

                /* TODO: we could actually modify this to a 1 or 2 byte leading
                 * protocol since we are only sending single trades and we know
                 * the maximum size of a single trade is ~125 bytes. Needs
                 * cooperation from pipe receivers, but writing/reading 4 bytes
                 * is likely more efficient anyway. */
                if (bufferAtTrade - buf >= 4) {
                    /* protocol is little endian 4-byte length, then body */
                    memcpy(bufferAtTrade - 4, &tradeSize, sizeof(tradeSize));

                    int sendOffset = 0;

                    /* optimized single-write path for length + trade since we
                     * overwrote the end of the previous trade with the binary
                     * length prefix */
                    do {
                        sendOffset += write(writePipes[worker],
                                            bufferAtTrade - 4 + sendOffset,
                                            tradeSize + 4 - sendOffset);
                    } while (sendOffset < tradeSize + 4);
                } else {
                    /* Linux guarantees writing up to 4096 bytes is atomic and
                     * will not fragement as defined in/by <linux/limits.h>:
                     * #define PIPE_BUF 4096    // # atomic pipe write bytes
                     *
                     * larger writes may return less than written, but
                     * depends on usage. */

                    /* "regular" path where we write the length then write the
                     * data */
                    /* protocol is little endian 4-byte length, then body */
                    const int wrote = write(writePipes[worker], &tradeSize,
                                            sizeof(tradeSize));
                    assert(wrote == sizeof(tradeSize));

                    if (unlikely(tradeSize > 150)) {
                        printf("Why is trade size huge here? Trade size: %d\n",
                               tradeSize);
                        printf("Trade is: %.*s\n", tradeSize, bufferAtTrade);
                    }

                    int sendOffset = 0;
                    do {
                        sendOffset += write(writePipes[worker],
                                            bufferAtTrade + sendOffset,
                                            tradeSize - sendOffset);
                        // printf("Sent: %.*s\n", tradeSize, currentBuffer +
                        // startTrade); printf("wrote: %d\n", wrote);
                    } while (sendOffset < tradeSize);
                }
#else
                /* this is bad and slow */
                struct aiocb acb = {.aio_fildes = writePipes[worker],
                                    .aio_buf = currentBuffer + startTrade,
                                    .aio_nbytes = tradeSize};
                const int wrote = aio_write(&acb);
                // printf("wrote: %d\n", wrote);
                assert(wrote == 0);
#endif

                /* Report if receiving pipe has a high backlog. */
#if 0
                int nbytes = 0;
                ioctl(writePipes[worker], FIONREAD, &nbytes);
                /* on average, a single trade JSON is 100 bytes */
                const int unreadTrades = nbytes / 100;
                if (unreadTrades > 1024) {
                    printf("[%.*s] Worker %d has %d unread bytes (%d trades)...\n", 4,
                           currentBuffer + position, worker, nbytes,
                           unreadTrades);
                }
#endif

#if 0
            printf("[%d] Single trade is: %.*s\n", total, (int)tradeSize,
                   currentBuffer + startTrade);
#endif

                /* Increment count of trades processed */
                total++;
                (*totalTotal)++;

                /* Stats! */
#define TRADES_PER_STATS_RUN 8192
                if (total % TRADES_PER_STATS_RUN == 0) {
                    const double endTime = timeUS() / 1000000.0;
                    const double currentRate =
                        ((double)TRADES_PER_STATS_RUN / (endTime - startTime));
                    if (currentRate > highestRate) {
                        highestRate = currentRate;
                        highestTime = endTime;

                        printf("\t{new high %10.2f t/s at %.5f}\n", highestRate,
                               highestTime);
                    }

                    if (currentRate < lowestRate) {
                        lowestRate = currentRate;
                        lowestTime = endTime;

                        printf("\t{new low %8.2f t/s at %.5f}\n", lowestRate,
                               lowestTime);
                    }

                    const uint64_t readsPerRate =
                        totalReads - totalReadsSinceLastRate;
                    const uint64_t framesPerRate =
                        totalFrames - totalFramesSinceLastRate;
                    const uint64_t bytesPerRate =
                        *totalBytes - totalBytesSinceLastRate;
                    printf(
                        "[%.5f] Rate {r %4lu} {f %4lu} {f/r %6.2f} {t/f %6.2f} "
                        "{tt %lu} {ttt %lu} {br %7lu} {bt %13lu}: %10.2f t/s\n",
                        endTime, readsPerRate, framesPerRate,
                        /* frames per read */
                        readsPerRate > 0 ? (float)framesPerRate / readsPerRate
                                         : 0,
                        /* trades per frame */
                        (float)TRADES_PER_STATS_RUN / framesPerRate,
                        /* total trades */
                        total, *totalTotal,
                        /* bytes per update */
                        bytesPerRate,
                        /* bytes total */
                        *totalBytes,
                        /* current speed broadcast to per-second throughput */
                        currentRate);
                    startTime = endTime;
                    totalReadsSinceLastRate = totalReads;
                    totalFramesSinceLastRate = totalFrames;
                    totalBytesSinceLastRate = *totalBytes;
                }

                /* Update used bytes... */
                position += tradeSize - 16;
            }

            assert((currentLen - position) == 0);

            continue;
        }
        close : {
            printf("Got close!\n");
            continue;
        }
        ping : {
            if (!frameDataLen) {
                printf("[%.5f] Sending empty pong...\n", timeUS() / 1000000.0);
                writeCheck(sock, &pongEmptyResponse, sizeof(pongEmptyResponse));
            } else {
                uint8_t pongWriteback[32];
                const size_t writeSize =
                    genPong(pongWriteback, dataStart, frameDataLen);
                printf("[%.5f] Sending data pong (%zu bytes)...\n",
                       timeUS() / 1000000.0, writeSize);
                writeCheck(sock, &pongWriteback, writeSize);
            }
            continue;
        }
        pong : {
            printf("Unary pong?\n");
            continue;
        }
        continueFrame : {
            /* https://tools.ietf.org/html/rfc6455#section-5.4 */
            /* Continuation frames start with (!final && type (F_TEXT or
             * F_BINARY))
             *  - handled by binary: or text: above, which jumps here.
             * Continuation frames continue with (!final && type == F_CONT)
             *  - handled here (write buffer, read more)
             * Continuation frames end with (final && type == F_CONT)
             *  - handled here (write buffer, jump back to data processing)
             */

            /* By reaching here, we know the contents of 'dataStart' up to
             * 'frameDataLen' belongs inside the continuation buffer. */
            memcpy(continueBuffer + continueBufferOffset, dataStart,
                   frameDataLen);
            continueBufferOffset += frameDataLen;

            if (!final) {
                // printf("READING NEXT CONTINUATION!\n");
                continue;
            }

            /* else, this is the FINAL frame of the continuation, so we can
             * resume normal processing.
             * assign the current buffer to the continue buffer so the data
             * processing reads from the proper memory blobs. */
            currentBuffer = continueBuffer;
            currentLen = continueBufferOffset;

            /* reset continue buffer offset because we are fully consuming it */
            continueBufferOffset = 0;

#if 0
            printf(
                "[0x%X :: 0x%X] Processing using continued buffer size %d!\n",
                type, continuedType, currentLen);
#endif

            /* jump back to original processing type (recorded by the first
             * frame of this continuation disaster) */
            goto *events[continuedType];
        }
        }
    }
}

bool genHello(void *const dst, const size_t len, const void *const host,
              const void *const path) {
    /* We are fine using static keys here because it's all TLS to us in
     * production and the key is only used to protect against broken proxy
     * middle boxes returning cached replies. */
    const char *upgradeFmt = "GET /%s HTTP/1.1\r\n"
                             "Host: %s\r\n"
                             "Upgrade: websocket\r\n"
                             "Connection: Upgrade\r\n"
                             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                             "Sec-WebSocket-Version: 13\r\n\r\n";

    /* Success if wrote entire content without growing larger than buffer */
    return snprintf(dst, len, upgradeFmt, path, host) < len;
}

void addressToParts(const char *addr, char *proto, char *host, uint32_t *port,
                    char *path) {
    int prePort = -1;

    /* Detect if provided URL has a port number or not.
     * If not, use default port for protocol. */

    /* Try with port first, the fall back to without port */
    if (sscanf(addr, "%3[^:]://%99[^:]:%5d/%99[^\n]", proto, host, &prePort,
               path) != 4) {
        sscanf(addr, "%3[^:]://%99[^/]/%99[^\n]", proto, host, path);
    }

    printf("%s %s %d %s\n", proto, host, prePort, path);

    if (strcmp(proto, "wss") == 0 && prePort == -1) {
        /* if wss and no specific port, use default secure port */
        prePort = 443;
    } else if (strcmp(proto, "ws") == 0 && prePort == -1) {
        /* if ws ano no specific port, use default public port */
        prePort = 80;
    }

    *port = prePort;
}

int flexConnect(const char *hostname, const char *port, const bool connectTLS) {
    struct addrinfo hints = {0};
    struct addrinfo *res0 = NULL;

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    const int error = getaddrinfo(hostname, port, &hints, &res0);

    if (error) {
        /* failed to look up name? */
        return -1;
        // errx(1, "%s", gai_strerror(error));
        /*NOTREACHED*/
    }

    int s = -1;
    for (struct addrinfo *res = res0; res; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) {
            continue;
        }

        int connected;
        if (connectTLS) {
            connected = tls_connect(s, res->ai_addr, res->ai_addrlen);
        } else {
            connected = connect(s, res->ai_addr, res->ai_addrlen);
        }

        if (connected == -1) {
            close(s);
            s = -1;
            continue;
        }

        break; /* okay we got one */
    }

    freeaddrinfo(res0);

    /* we return -1 if the connection isn't valid */
    return s;
}

bool sendStr(int sock, const char *str) {
    const size_t strCount = strlen(str);
    const size_t bufSize = strCount < 512 ? 4096 : (strCount + 10);
    uint8_t GOODBYE_BYTES *const buf = malloc(bufSize);
    uint8_t *dataStart;

    const size_t frameLen = genText(buf, str, strlen(str), &dataStart);

    /* start of data is + header (2 bytes) + mask value (4 bytes)
     * (assuming our entire data size is <= 125, which it is for now) */
    if (strCount < 125) {
        assert(dataStart == buf + 2 + 4);
    } else {
        assert(dataStart == buf + 2 + 2 + 4);
    }
    printf("Sending (0x%X, 0x%X) [%lu]: %.*s\n", buf[0], buf[1], frameLen,
           (int)frameLen - 2 - 4, dataStart);

    writeCheck(sock, buf, frameLen);
    return true;

#if 0
    while (true) {
        /* wait for acknowledgement.
         * (we can also receive pings during this time) */
        int got = read(sock, buf, 2);
        assert(got == 2 || got <= 0);

        if (got <= 0) {
            return false;
        }

        /* Just read one reply frame header */
        uint8_t *dataStart;
        enum frameType type;
        size_t totalFrameSize;
        bool final = true;
        const int len =
            dataSize(buf, 2, &dataStart, &type, &final, &totalFrameSize);

        assert(final == true);

        /* Now read the reply body we got from the header.
         * NOTE: this is ONLY using embedded length headers, so the
         * responses must be less than 125 bytes. */
        got = read(sock, buf, bufSize);
        if (type == F_PING) {
            assert(len <= 20);

            /* one static pong response we reuse for each ping */
            uint8_t pongResponse[32];
            const size_t pongLen = genPong(pongResponse, dataStart, len);

            printf("Sending pong while waiting for reply...\n");
            writeCheck(sock, &pongResponse, pongLen);
            continue;
        }

        if (strstr((const char *)buf, "success")) {
            printf("Success!\n");
            printf("Found success inside data %d: %.*s\n", got, got, buf);
            return true;
        }

        printf("No success? Buffer is [%d]: %.*s\n", type, len, dataStart);
        return false;
    }
#endif
}

bool login(const int sock, const char *authkey) {
    char authstring[256] = {0};
    const char *authstringFmt = "{\"action\": \"auth\", \"params\": \"%s\"}";
    snprintf(authstring, sizeof(authstring), authstringFmt, authkey);

    printf("Logging in...\n");
    return sendStr(sock, authstring);
}

bool subscribe(int sock) {
    // const char *substring = "{\"action\": \"subscribe\", \"params\":
    // \"T.*\"}";
    const char *substring =
        "{\"action\": \"subscribe\", \"params\": "
        //        "\"T.AAL,T.AAPL,T.AMD,T.AMZN,T.BA,T.BABA,T.BAC,T.BIGC,T.BYND,T.CRM,T.CVAC,T.CVNA,T.CWH,T.DIA,T.DOCU,T.ETSY,T.FB,T.FDX,T.FSLY,T.GME,T.GOOG,T.IWM,T.LULU,T.LYFT,T.MIK,T.MSFT,T.NVAX,T.NVDA,T.OSTK,T.PINS,T.PRPL,T.PTON,T.QQQ,T.RKT,T.ROKU,T.SNOW,T.SPCE,T.SPOT,T.SPY,T.SQ,T.TSLA,T.TWLO,T.UBER,T.VALE,T.VXX,T.UVXY,T.DDOG,T.W,T.WFC,T.ZM,T.NIO,T.TLRY,T.IPOB,T.PSTH,T.TAN,T.SNAP,T.CGC,T.NVAX,T.MJ\"}";
        //        "\"T.SPY\"}";
        "\"T.*\"}";
    printf("Subscribing...\n");
    return sendStr(sock, substring);
}

pid_t untoTheWorldSummonTheDestroyer(const int *const readPipes,
                                     const int howManyPipes, char **launchArgs,
                                     const int howManyLaunchArgs,
                                     const char *workingdir) {
#define MAXPIPES 16384

    /* array of characters of things */
    char pipeArgs[MAXPIPES][8];
    char *sendArgs[MAXPIPES] = {0};
    int startArg = 0;

    /* executable then leading arguments.
     * The pipe numbers get appended after these arguments. */
    for (int i = 0; i < howManyLaunchArgs; i++) {
        sendArgs[startArg++] = launchArgs[i];
    }

    assert(howManyPipes < MAXPIPES - startArg);

    /* Turn each of our read pipes into strings so we can pass them as command
     * line arguments to the python process. */
    for (int i = 0; i < howManyPipes; i++) {
        snprintf(pipeArgs[i], 8, "%d", readPipes[i]);
        sendArgs[startArg++] = pipeArgs[i];
    }

    printf("Launching forked worker inside directory %s as:\n", workingdir);
    for (int i = 0; i < startArg; i++) {
        printf("%s ", sendArgs[i]);
    }
    printf("\n");

    pid_t pid = fork();
    if (pid == -1) {
        perror("Failed to fork?");
        exit(6);
    }

    if (pid == 0) {
        /* child execs and never returns */
        /* exit process when parent exits */
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        /* move into directory where we are going to exec the primary worker
         * process */
        const int changedDir = chdir(workingdir);
        assert(changedDir == 0);

        execve(sendArgs[0], sendArgs, environ);
        perror("Failed to launch THE DESTROYER?!");
        exit(7);
    }

    return pid;
}

void becomePipes(int *readPipes, int *writePipes, int howMany) {
    /* Create 'howMany' pipe pairs, then for the write end of eaach pipe
     * attempt to increase the maximum pipe buffer size. */
    for (int i = 0; i < howMany; i++) {
        int p[2];
        if (pipe(p) == -1) {
            perror("Pipe creation error!");
            exit(4);
        }

        readPipes[i] = p[0];
        writePipes[i] = p[1];

        /* also make write pipe bigger... */
        int trySize = 1L << 30; /* start with 1 GB! */
        while (true) {
            /* return value of this fcntl operation is the actual size of the
             * pipe after attempting to set it. If the size is too big to set,
             * the value will be less than what we requested. */
            if (fcntl(writePipes[i], F_SETPIPE_SZ, trySize) >= trySize) {
                printf("[%d] Set write pipe %d to %d bytes!\n", i,
                       writePipes[i], trySize);
                break;
            }

            /* else, try smaller... */
            trySize /= 2;
        }
    }
}

/* Welcome! */
int main(int argc, char *argv[]) {
    if (argc < 6) {
        printf("%s authkey websocket-address pipes-count "
               "worker-process-working-directory worker-process-path "
               "worker-args...\n",
               argv[0]);
        exit(1);
    }

    const char *authkey = argv[1];
    const char *addr = argv[2];
    const int PIPES_COUNT = atoi(argv[3]);
    const char *workingdir = argv[4];

    const int workerProcessArgsLength = (argc - 5);
    char **workerProcessStart = &argv[5];

    /* no SIGPIPE on bad writes */
    signal(SIGPIPE, SIG_IGN);

    char proto[8] = {0};
    char host[100] = {0};
    uint32_t port;
    char path[100] = {0};

    addressToParts(addr, proto, host, &port, path);
    printf("Connecting to %s on %d via %s\n", host, port, path);

    const bool addrIsTLS = port == 443;
    char portStr[8] = {0};
    snprintf(portStr, sizeof(portStr), "%d", port);

    int lapipesRead[PIPES_COUNT];
    int lapipesWrite[PIPES_COUNT];
    becomePipes(lapipesRead, lapipesWrite, PIPES_COUNT);

    const pid_t analysis = untoTheWorldSummonTheDestroyer(
        lapipesRead, PIPES_COUNT, workerProcessStart, workerProcessArgsLength,
        workingdir);

    /* total trades even across reconnects */
    uint64_t totalTotal = 0;
    uint64_t totalBytes = 0;
    /* If we get disconnected, login again! */
connectAgain:
    while (true) {
        const int sock = flexConnect(host, portStr, addrIsTLS);

#define MS_AS_US *1000
        if (sock == -1) {
            printf("Connection refused...\n");
            usleep(250 MS_AS_US);
            continue;
        }

        /* child processes don't get our socket */
        fcntl(sock, F_SETFD, FD_CLOEXEC);

        uint8_t upgrade[2048];
        genHello(upgrade, sizeof(upgrade), host, path);

#if 0
    printf("Hello is: %s\n", upgrade);
#endif

        const size_t upgradeLen = strlen((const char *)upgrade);
        int wrote = 0;
        do {
            const int didWrite =
                write(sock, upgrade + wrote, upgradeLen - wrote);
            if (didWrite == -1) {
                printf("Failed to upgrade? %s\n", strerror(errno));
                goto connectAgain;
            }

            wrote += didWrite;
        } while (wrote < upgradeLen);

        /* And we get back:
           HTTP/1.1 101 Switching Protocols
           Server: nginx/1.17.8
           Date: Sat, 25 Jul 2020 22:18:47 GMT
           Connection: upgrade
           Upgrade: websocket
           Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
           Strict-Transport-Security: max-age=15724800; includeSubDomains
         */

        uint8_t buf[128] = {0};
        char prevChar = 0;

        /* single char iterate over header searching for the end: \r\n\r\n */
        while (!(buf[0] == '\r' && prevChar == '\n')) {
            prevChar = buf[0];
            int got = read(sock, buf, 1);
            if (got <= 0) {
                continue;
            }
#if 0
            printf("got: %c\n", buf[0]);
#endif
        }

        /* throw away next character (final \n) */
        int got = read(sock, buf, 1);
        if (got <= 0) {
            continue;
        }

        /* read hello / connection message and throw it away... */
        got = read(sock, buf, sizeof(buf));
        if (got <= 0) {
            continue;
        }

#if 1
        printf("Read %d: %.*s\n", got, got, buf);
#endif

        if (!login(sock, authkey)) {
            exit(3);
        }

        if (!subscribe(sock)) {
            exit(4);
        }

        dispatchWebsocketFrames(sock, lapipesWrite, PIPES_COUNT, &totalTotal,
                                &totalBytes);

        /* Now we can start sending and receiving prefixed protocol data. */

        /* perform read write operations ... */
#if 0
    const char *msg = "GET / HTTP/1.0\r\n\r\n";
    int wrote = write(sock, msg, strlen(msg));
    printf("Wrote: %d\n", wrote);

    uint8_t buf[1 << 20];
    int got = read(sock, buf, bufSize);
    printf("Read: %d\n", got);

    printf("Got: %.*s\n", (int)bufSize, buf);

    printf("Boo!: %.*s\n", 32, buf);
#endif
        shutdown(sock, SHUT_RDWR);
        close(sock);
    }

    int status = 0;
    waitpid(analysis, &status, 0);

    return EXIT_SUCCESS;
}
